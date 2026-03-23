package squic

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

// isQUICInitial checks if a packet is a QUIC Initial packet.
// QUIC Initial packets have a long header (bit 7 = 1, bit 6 = 1)
// and packet type 0x00 in bits 5-4 of the first byte.
// The first byte format: 1 1 TT RRRR where TT=00 for Initial.
// So first byte & 0xF0 == 0xC0 for Initial packets.
func isQUICInitial(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	return data[0]&0xF0 == 0xC0
}

// clientConn wraps a *net.UDPConn for the client side.
// It appends the client's X25519 public key and a DH-based MAC1 to outgoing Initial packets.
// Implements OOBCapablePacketConn so quic-go uses the fast path (recvmmsg, sendmmsg, GSO, ECN).
type clientConn struct {
	conn         *net.UDPConn
	sharedSecret []byte // X25519(clientPriv, serverPub)
	clientPubKey []byte // 32-byte X25519 public key
	initialSent  atomic.Bool
}

func newClientConn(conn *net.UDPConn, sharedSecret, clientX25519Pub []byte) *clientConn {
	return &clientConn{
		conn:         conn,
		sharedSecret: sharedSecret,
		clientPubKey: clientX25519Pub,
	}
}

// --- net.PacketConn methods (delegate to underlying UDPConn) ---

func (c *clientConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.conn.ReadFrom(b)
}

func (c *clientConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if !c.initialSent.Load() && isQUICInitial(p) {
		return c.writeInitial(p, addr.(*net.UDPAddr))
	}
	return c.conn.WriteTo(p, addr)
}

func (c *clientConn) Close() error                       { return c.conn.Close() }
func (c *clientConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *clientConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *clientConn) SetReadDeadline(t time.Time) error   { return c.conn.SetReadDeadline(t) }
func (c *clientConn) SetWriteDeadline(t time.Time) error  { return c.conn.SetWriteDeadline(t) }

// net.Conn methods required by x/net/ipv4.NewPacketConn
func (c *clientConn) Read(b []byte) (int, error)          { return c.conn.Read(b) }
func (c *clientConn) Write(b []byte) (int, error)         { return c.conn.Write(b) }
func (c *clientConn) RemoteAddr() net.Addr                { return c.conn.RemoteAddr() }

// --- OOBCapablePacketConn methods (delegate to underlying UDPConn) ---

func (c *clientConn) SyscallConn() (syscall.RawConn, error) { return c.conn.SyscallConn() }
func (c *clientConn) SetReadBuffer(bytes int) error          { return c.conn.SetReadBuffer(bytes) }
func (c *clientConn) SetWriteBuffer(bytes int) error         { return c.conn.SetWriteBuffer(bytes) }

func (c *clientConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	return c.conn.ReadMsgUDP(b, oob)
}

func (c *clientConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if !c.initialSent.Load() && isQUICInitial(b) {
		return c.writeInitialMsg(b, oob, addr)
	}
	return c.conn.WriteMsgUDP(b, oob, addr)
}

// writeInitial appends client pubkey + timestamp + MAC1 to an Initial packet (WriteTo path).
func (c *clientConn) writeInitial(p []byte, addr *net.UDPAddr) (int, error) {
	ts := NowTimestamp()
	mac := ComputeMAC1(c.sharedSecret, p, ts)
	buf := make([]byte, len(p)+MACOverhead)
	copy(buf, p)
	copy(buf[len(p):], c.clientPubKey)
	binary.BigEndian.PutUint32(buf[len(p)+ClientKeySize:], ts)
	copy(buf[len(p)+ClientKeySize+TimestampSize:], mac)
	n, err := c.conn.WriteToUDP(buf, addr)
	if err == nil {
		n = len(p)
	}
	return n, err
}

// writeInitialMsg appends client pubkey + timestamp + MAC1 to an Initial packet (WriteMsgUDP path).
func (c *clientConn) writeInitialMsg(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	ts := NowTimestamp()
	mac := ComputeMAC1(c.sharedSecret, b, ts)
	buf := make([]byte, len(b)+MACOverhead)
	copy(buf, b)
	copy(buf[len(b):], c.clientPubKey)
	binary.BigEndian.PutUint32(buf[len(b)+ClientKeySize:], ts)
	copy(buf[len(b)+ClientKeySize+TimestampSize:], mac)
	n, oobn, err := c.conn.WriteMsgUDP(buf, oob, addr)
	if err == nil {
		n = len(b)
	}
	return n, oobn, err
}

// serverConn wraps a *net.UDPConn for the server side.
// It validates DH-based MAC1 on incoming Initial packets and silently drops invalid ones.
// Optionally checks client public keys against a whitelist.
// Implements OOBCapablePacketConn so quic-go uses the fast path.
type serverConn struct {
	conn             *net.UDPConn
	serverX25519Priv []byte            // server's X25519 private key
	keysMu           sync.RWMutex      // protects allowedKeys
	allowedKeys      map[[32]byte]bool  // optional whitelist of client X25519 public keys
	batchReader      *ipv4.PacketConn   // lazy-initialized for ReadBatch
}

func newServerConn(conn *net.UDPConn, serverX25519Priv []byte, allowedKeys [][]byte) *serverConn {
	sc := &serverConn{
		conn:             conn,
		serverX25519Priv: serverX25519Priv,
	}

	if len(allowedKeys) > 0 {
		sc.allowedKeys = make(map[[32]byte]bool, len(allowedKeys))
		for _, k := range allowedKeys {
			if len(k) == 32 {
				var key [32]byte
				copy(key[:], k)
				sc.allowedKeys[key] = true
			}
		}
	}

	return sc
}

// --- net.PacketConn methods ---

func (c *serverConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.conn.ReadFrom(p)
		if err != nil {
			return
		}
		if ok, stripped := c.validateAndStrip(p, n); ok {
			return stripped, addr, nil
		}
		// invalid — silently drop, read next
	}
}

func (c *serverConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.conn.WriteTo(p, addr)
}

func (c *serverConn) Close() error                       { return c.conn.Close() }
func (c *serverConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *serverConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *serverConn) SetReadDeadline(t time.Time) error   { return c.conn.SetReadDeadline(t) }
func (c *serverConn) SetWriteDeadline(t time.Time) error  { return c.conn.SetWriteDeadline(t) }

// net.Conn methods required by x/net/ipv4.NewPacketConn
func (c *serverConn) Read(b []byte) (int, error)          { return c.conn.Read(b) }
func (c *serverConn) Write(b []byte) (int, error)         { return c.conn.Write(b) }
func (c *serverConn) RemoteAddr() net.Addr                { return c.conn.RemoteAddr() }

// --- OOBCapablePacketConn methods ---

func (c *serverConn) SyscallConn() (syscall.RawConn, error) { return c.conn.SyscallConn() }
func (c *serverConn) SetReadBuffer(bytes int) error          { return c.conn.SetReadBuffer(bytes) }
func (c *serverConn) SetWriteBuffer(bytes int) error         { return c.conn.SetWriteBuffer(bytes) }

func (c *serverConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	for {
		n, oobn, flags, addr, err = c.conn.ReadMsgUDP(b, oob)
		if err != nil {
			return
		}
		if ok, stripped := c.validateAndStrip(b, n); ok {
			return stripped, oobn, flags, addr, nil
		}
		// invalid — silently drop, read next
	}
}

func (c *serverConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	return c.conn.WriteMsgUDP(b, oob, addr)
}

// ReadBatch reads a batch of packets, validating MAC1 on Initial packets.
// This implements the batchConn interface that quic-go checks for (sys_conn_oob.go:132).
// Without this, quic-go would unwrap our SyscallConn() and read the raw FD directly,
// completely bypassing our MAC1 validation.
func (c *serverConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	// Use the underlying ipv4.PacketConn for actual batch reads (recvmmsg on Linux)
	if c.batchReader == nil {
		c.batchReader = ipv4.NewPacketConn(c.conn)
	}

	n, err := c.batchReader.ReadBatch(ms, flags)
	if err != nil {
		return 0, err
	}

	// Filter: validate MAC1 on each message, compact valid ones to the front
	valid := 0
	for i := 0; i < n; i++ {
		data := ms[i].Buffers[0][:ms[i].N]
		if ok, stripped := c.validateAndStrip(data, ms[i].N); ok {
			if valid != i {
				ms[valid] = ms[i]
			}
			ms[valid].N = stripped
			valid++
		}
	}

	if valid == 0 {
		// All packets in this batch were invalid — try again
		return c.ReadBatch(ms, flags)
	}

	return valid, nil
}

// validateAndStrip checks if the packet is valid and strips MAC overhead from Initial packets.
// Returns (true, newLength) if valid, (false, 0) if should be dropped.
func (c *serverConn) validateAndStrip(p []byte, n int) (bool, int) {
	// Non-Initial packets pass through unmodified
	if !isQUICInitial(p[:n]) {
		return true, n
	}

	// Initial packet: must have client pubkey + MAC1 appended
	if n <= MACOverhead {
		return false, 0
	}

	quicLen := n - MACOverhead
	clientPub := p[quicLen : quicLen+ClientKeySize]
	tsBytes := p[quicLen+ClientKeySize : quicLen+ClientKeySize+TimestampSize]
	mac1 := p[quicLen+ClientKeySize+TimestampSize : n]
	timestamp := binary.BigEndian.Uint32(tsBytes)

	// Step 1: Replay protection — reject timestamps outside window
	if !TimestampInWindow(timestamp, NowTimestamp()) {
		return false, 0
	}

	// Step 2: Whitelist check (fast map lookup, before expensive DH)
	c.keysMu.RLock()
	keys := c.allowedKeys
	c.keysMu.RUnlock()
	if keys != nil {
		var key [32]byte
		copy(key[:], clientPub)
		if !keys[key] {
			return false, 0
		}
	}

	// Step 3: DH + MAC1 verification (includes timestamp in MAC input)
	shared, dhErr := X25519(c.serverX25519Priv, clientPub)
	if dhErr != nil {
		return false, 0
	}

	if !VerifyMAC1(shared, p[:quicLen], timestamp, mac1) {
		return false, 0
	}

	return true, quicLen
}

// addKey adds a client public key to the whitelist.
// Initializes the map if it was nil (implicitly enables whitelisting).
func (c *serverConn) addKey(key [32]byte) {
	c.keysMu.Lock()
	defer c.keysMu.Unlock()
	if c.allowedKeys == nil {
		c.allowedKeys = make(map[[32]byte]bool)
	}
	c.allowedKeys[key] = true
}

// removeKey removes a client public key from the whitelist.
func (c *serverConn) removeKey(key [32]byte) {
	c.keysMu.Lock()
	defer c.keysMu.Unlock()
	if c.allowedKeys != nil {
		delete(c.allowedKeys, key)
	}
}

// hasKey checks if a client public key is in the whitelist.
func (c *serverConn) hasKey(key [32]byte) bool {
	c.keysMu.RLock()
	defer c.keysMu.RUnlock()
	if c.allowedKeys == nil {
		return false
	}
	return c.allowedKeys[key]
}

// allKeys returns a copy of all whitelisted keys.
func (c *serverConn) allKeys() [][32]byte {
	c.keysMu.RLock()
	defer c.keysMu.RUnlock()
	if c.allowedKeys == nil {
		return nil
	}
	keys := make([][32]byte, 0, len(c.allowedKeys))
	for k := range c.allowedKeys {
		keys = append(keys, k)
	}
	return keys
}

// enableWhitelist initializes the whitelist with optional pre-populated keys.
// If the whitelist is already active, the provided keys are added to it.
func (c *serverConn) enableWhitelist(keys [][32]byte) {
	c.keysMu.Lock()
	defer c.keysMu.Unlock()
	if c.allowedKeys == nil {
		c.allowedKeys = make(map[[32]byte]bool, len(keys))
	}
	for _, k := range keys {
		c.allowedKeys[k] = true
	}
}

// disableWhitelist removes the whitelist entirely.
// All clients with a valid MAC1 will be allowed.
func (c *serverConn) disableWhitelist() {
	c.keysMu.Lock()
	defer c.keysMu.Unlock()
	c.allowedKeys = nil
}
