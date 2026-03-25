package squic

import (
	"crypto/rand"
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
	cookie       atomic.Value // stores []byte cookie from server (for MAC2)
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
	for {
		n, addr, err := c.conn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		// Check if this is a cookie reply
		if n > 0 && b[0] == CookieReplyType {
			c.cookie.Store(append([]byte(nil), b[1:n]...))
			continue // read next packet
		}
		return n, addr, nil
	}
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
	for {
		n, oobn, flags, addr, err = c.conn.ReadMsgUDP(b, oob)
		if err != nil {
			return
		}
		if n > 0 && b[0] == CookieReplyType {
			c.cookie.Store(append([]byte(nil), b[1:n]...))
			continue
		}
		return
	}
}

func (c *clientConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if !c.initialSent.Load() && isQUICInitial(b) {
		return c.writeInitialMsg(b, oob, addr)
	}
	return c.conn.WriteMsgUDP(b, oob, addr)
}

// buildInitial constructs the Initial packet with MAC1 + MAC2 appended.
func (c *clientConn) buildInitial(p []byte) []byte {
	ts := NowTimestamp()
	nonce, _ := GenerateNonce()
	mac1 := ComputeMAC1(c.sharedSecret, p, ts, nonce)

	buf := make([]byte, len(p)+MACOverhead)
	copy(buf, p)
	off := len(p)
	copy(buf[off:], c.clientPubKey)
	off += ClientKeySize
	binary.BigEndian.PutUint32(buf[off:], ts)
	off += TimestampSize
	copy(buf[off:], nonce)
	off += NonceSize
	copy(buf[off:], mac1)
	off += MACSize

	// MAC2: zeros if no cookie, computed if cookie available
	if cookie, ok := c.cookie.Load().([]byte); ok && len(cookie) > 0 {
		mac2 := ComputeMAC2(cookie, buf[:off], mac1)
		copy(buf[off:], mac2)
	}
	// else: MAC2 field is already zeros from make()

	return buf
}

// writeInitial appends client pubkey + timestamp + MAC1 + MAC2 to an Initial packet (WriteTo path).
func (c *clientConn) writeInitial(p []byte, addr *net.UDPAddr) (int, error) {
	buf := c.buildInitial(p)
	n, err := c.conn.WriteToUDP(buf, addr)
	if err == nil {
		n = len(p)
	}
	return n, err
}

// writeInitialMsg appends client pubkey + timestamp + MAC1 + MAC2 to an Initial packet (WriteMsgUDP path).
func (c *clientConn) writeInitialMsg(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	buf := c.buildInitial(b)
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

	// MAC2 + cookie DDoS protection
	cookieSecret     [32]byte          // current cookie encryption secret
	prevCookieSecret [32]byte          // previous secret (for rotation grace period)
	underLoad        atomic.Bool       // true when DH rate exceeds threshold
	dhCount          atomic.Int64      // DH operations in current second
	loadThreshold    int64             // DH/sec before entering under-load mode
}

func newServerConn(conn *net.UDPConn, serverX25519Priv []byte, allowedKeys [][]byte, loadThreshold int64) *serverConn {
	sc := &serverConn{
		conn:             conn,
		serverX25519Priv: serverX25519Priv,
		loadThreshold:    loadThreshold,
	}

	if sc.loadThreshold <= 0 {
		sc.loadThreshold = 1000 // default: 1000 DH ops/sec
	}

	// Initialize cookie secrets
	rand.Read(sc.cookieSecret[:])
	rand.Read(sc.prevCookieSecret[:])

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

	// Start background goroutines
	go sc.rotateCookieSecrets()
	go sc.monitorLoad()

	return sc
}

// rotateCookieSecrets rotates the cookie encryption secret every 120 seconds.
func (c *serverConn) rotateCookieSecrets() {
	ticker := time.NewTicker(120 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c.prevCookieSecret = c.cookieSecret
		rand.Read(c.cookieSecret[:])
	}
}

// monitorLoad tracks DH operations per second and toggles underLoad.
func (c *serverConn) monitorLoad() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		count := c.dhCount.Swap(0)
		if count > c.loadThreshold {
			c.underLoad.Store(true)
		} else {
			c.underLoad.Store(false)
		}
	}
}

// sendCookieReply sends an encrypted cookie to the client.
// The cookie is deterministic for (secret, IP), encrypted for transport.
func (c *serverConn) sendCookieReply(addr *net.UDPAddr) {
	cookie := CookieValue(c.cookieSecret, addr.IP)
	encrypted, err := EncryptCookie(c.cookieSecret, cookie)
	if err != nil {
		return
	}
	reply := make([]byte, 1+len(encrypted))
	reply[0] = CookieReplyType
	copy(reply[1:], encrypted)
	c.conn.WriteToUDP(reply, addr)
}

// --- net.PacketConn methods ---

func (c *serverConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.conn.ReadFrom(p)
		if err != nil {
			return
		}
		udpAddr, _ := addr.(*net.UDPAddr)
		if ok, stripped := c.validateAndStrip(p, n, udpAddr); ok {
			return stripped, addr, nil
		}
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
		if ok, stripped := c.validateAndStrip(b, n, addr); ok {
			return stripped, oobn, flags, addr, nil
		}
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
		var addr *net.UDPAddr
		if ms[i].Addr != nil {
			addr, _ = ms[i].Addr.(*net.UDPAddr)
		}
		if ok, stripped := c.validateAndStrip(data, ms[i].N, addr); ok {
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
// addr is used to send cookie replies when under load (can be nil to skip).
func (c *serverConn) validateAndStrip(p []byte, n int, addr *net.UDPAddr) (bool, int) {
	// Non-Initial packets pass through unmodified
	if !isQUICInitial(p[:n]) {
		return true, n
	}

	// Initial packet: must have client pubkey + MAC1 + MAC2 appended
	if n <= MACOverhead {
		return false, 0
	}

	quicLen := n - MACOverhead
	off := quicLen
	clientPub := p[off : off+ClientKeySize]
	off += ClientKeySize
	tsBytes := p[off : off+TimestampSize]
	off += TimestampSize
	nonce := p[off : off+NonceSize]
	off += NonceSize
	mac1Start := off
	mac1 := p[off : off+MACSize]
	off += MACSize
	mac2 := p[off : n]
	timestamp := binary.BigEndian.Uint32(tsBytes)

	// Step 1: Replay protection — reject timestamps outside window (cheap)
	if !TimestampInWindow(timestamp, NowTimestamp()) {
		return false, 0
	}

	// Step 2: MAC2 check — if under load, require valid MAC2
	if c.underLoad.Load() {
		isZero := true
		for _, b := range mac2 {
			if b != 0 {
				isZero = false
				break
			}
		}

		mac2Valid := false
		if !isZero && addr != nil {
			// Recompute deterministic cookie for this IP, verify MAC2
			// Try current secret, then previous (for rotation grace)
			dataBeforeMAC2 := p[:mac1Start]
			cookie := CookieValue(c.cookieSecret, addr.IP)
			if VerifyMAC2(cookie, dataBeforeMAC2, mac1, mac2) {
				mac2Valid = true
			} else {
				cookie = CookieValue(c.prevCookieSecret, addr.IP)
				if VerifyMAC2(cookie, dataBeforeMAC2, mac1, mac2) {
					mac2Valid = true
				}
			}
		}

		if !mac2Valid {
			// Under load with no valid MAC2 — send cookie reply and drop
			if addr != nil {
				c.sendCookieReply(addr)
			}
			return false, 0
		}
	}

	// Step 3: Whitelist check (fast map lookup, before expensive DH)
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

	// Step 4: DH + MAC1 verification (expensive)
	c.dhCount.Add(1)
	shared, dhErr := X25519(c.serverX25519Priv, clientPub)
	if dhErr != nil {
		return false, 0
	}

	if !VerifyMAC1(shared, p[:quicLen], timestamp, nonce, mac1) {
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
