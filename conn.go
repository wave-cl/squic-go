package squic

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
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

// isQUICZeroRTT reports whether a packet is a QUIC 0-RTT packet: long header,
// packet type 0x01, so first byte & 0xF0 == 0xD0.
//
// sQUIC does not carry 0-RTT. The envelope proves possession of the server's
// key and of a Diffie-Hellman shared secret, and it is attached to the Initial;
// a standalone 0-RTT datagram arrives with none of that, so a stack that
// accepts one is taking application data from a caller this transport has not
// authenticated — past the gate, past MAC1, and past the whitelist SIP-8
// enforces on the X25519 field the datagram does not carry.
func isQUICZeroRTT(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	return data[0]&0xF0 == 0xD0
}

// isShortHeader reports whether a packet has a QUIC short header: header-form
// bit clear, fixed bit set. Everything after the handshake looks like this and
// nothing before it does.
func isShortHeader(data []byte) bool {
	return len(data) > 0 && data[0]&0xC0 == 0x40
}

// isLongHeader reports whether a packet has a QUIC long header: the header-form
// bit is set. Initial, 0-RTT, Handshake and Retry all look like this.
func isLongHeader(data []byte) bool {
	return len(data) > 0 && data[0]&0x80 != 0
}

// supportedVersions is the set quic-go parses, and the set this server will
// accept a long header for. Kept as the exported constants rather than a
// literal so it cannot drift from the stack it is protecting.
var supportedVersions = []quic.Version{quic.Version1, quic.Version2}

// versionAccepted reports whether the QUIC stack behind us would parse this
// long header's version.
//
// The envelope gates Initials, but *every* long header reaches the QUIC stack,
// and a stack that does not recognise the version answers with a Version
// Negotiation packet before it has looked at the connection at all. That reply
// costs the caller no key and no captured traffic, so without this gate one
// datagram proves the server exists and SIP-6's silence is over.
//
// Only the unknown-version case is dropped. A long header the stack does
// recognise has to pass: the client's Handshake packets are long-headed too,
// and dropping every non-Initial long header would break every connection at
// the second flight. Those are already silent — quic-go ignores a non-Initial
// long header for a connection it does not know.
func versionAccepted(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	v := quic.Version(binary.BigEndian.Uint32(data[1:5]))
	for _, s := range supportedVersions {
		if v == s {
			return true
		}
	}
	return false
}

// peerKeyTTL bounds how long a validated peer key is retained before the
// connection is accepted. An Initial that passes MAC1 but whose handshake
// never completes would otherwise leave its key indefinitely; a peer that can
// pass MAC1 could fill the table. The window need only span first-Initial to
// accept, which is sub-second in practice.
const peerKeyTTL = 30 * time.Second

// peerTableMax is the most insertion records the table will hold, and so the
// most live entries — every live entry owns exactly one record.
//
// The table is filled by anything that passes MAC1, which without a whitelist
// is anyone holding the server's public key: a value that is *published*,
// being the tail of the connection string. The previous arrangement pruned only
// *expired* entries and then inserted regardless, so it freed nothing whenever
// arrivals outran the TTL — which is exactly what an attacker arranges — and
// the table grew without limit while every insert paid for a full scan that
// reclaimed nothing.
//
// At roughly 250 bytes an entry this bounds the table to about 4 MB. The
// healthy steady state is near-empty: an entry lives from the first Initial to
// accept, which is sub-second.
const peerTableMax = 16384

type peerEntry struct {
	key [32]byte
	// identity is the MAC1-bound Ed25519 key (SIP-3) that forward-derived to
	// key, valid only when hasIdentity is set. Absent for anonymous callers.
	identity    [32]byte
	hasIdentity bool
	inserted    time.Time
	// poisoned is set when two Initials shared a DCID with different keys. The
	// connection can no longer be attributed to one identity, so the entry
	// answers for neither.
	poisoned bool
}

// peerTable maps a QUIC Destination Connection ID to the peer X25519 key that
// MAC1 verified on the Initial carrying it, so the accepting application can
// learn who it is talking to. See SIP-2. The DCID bytes are the map key.
type peerTable struct {
	mu      sync.Mutex
	entries map[string]peerEntry
	// order holds one record per entry, in insertion order, so expiry and
	// eviction are both amortised O(1) and neither scans the map.
	//
	// A record is appended once, when the entry is first recorded, and its
	// timestamp never changes — which is what makes the front always the
	// oldest. A record whose timestamp no longer matches the map (the entry was
	// taken at accept, or evicted and re-recorded since) is stale, and is
	// discarded without touching whatever is there now.
	order []orderRecord
}

// orderRecord names an entry and when it was first recorded.
type orderRecord struct {
	inserted time.Time
	dcid     string
}

func newPeerTable() *peerTable {
	return &peerTable{entries: make(map[string]peerEntry)}
}

// dropFront drops the oldest record, and the entry it names if that entry is
// still the one the record refers to. Reports whether a live entry went too.
func (t *peerTable) dropFront() bool {
	if len(t.order) == 0 {
		return false
	}
	r := t.order[0]
	t.order = t.order[1:]
	if e, ok := t.entries[r.dcid]; ok && e.inserted.Equal(r.inserted) {
		delete(t.entries, r.dcid)
		return true
	}
	return false // stale record; the entry it named is already gone
}

// expire drops everything past its TTL. Timestamps never change and records are
// appended in order, so the front is always the oldest and this stops at the
// first live one — no scan, and no dependence on how full the table is.
func (t *peerTable) expire(now time.Time) {
	for len(t.order) > 0 && now.Sub(t.order[0].inserted) >= peerKeyTTL {
		t.dropFront()
	}
}

// record stores dcid -> key for an Initial that just passed MAC1. A repeat of
// the same DCID with the same key is a retransmission and refreshes the entry;
// a repeat with a different key is a collision that cannot be resolved safely
// (an on-path attacker could otherwise overwrite a victim's entry), so the
// entry is poisoned and will answer for neither key.
func (t *peerTable) record(dcid []byte, key [32]byte, identity [32]byte, hasIdentity bool, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// An entry that is already here is settled in place, ahead of any expiry or
	// eviction, so a live connection is never turned away by pressure a flood
	// created a moment ago.
	//
	// A retransmission no longer extends the entry: it lives its TTL from when
	// it was first seen. That is what lets the order queue be exact — a
	// timestamp that never moves means the front is always the oldest — and it
	// stops a peer holding an entry open indefinitely by retransmitting. The
	// TTL is 30s against a 10s handshake timeout, so the first sighting already
	// covers the whole handshake.
	k := string(dcid)
	if e, ok := t.entries[k]; ok {
		switch {
		case e.poisoned:
			// stays poisoned
		case e.key == key && e.identity == identity && e.hasIdentity == hasIdentity:
			// a retransmission; the entry keeps its original expiry
		default:
			e.poisoned = true
			t.entries[k] = e
		}
		return
	}

	t.expire(now)

	// Every live entry owns exactly one record, so bounding the queue bounds
	// the map. Dropping from the front evicts the oldest, which is the right
	// end: a legitimate caller's entry is read within milliseconds of being
	// written, so it is the newest thing here and the last to go.
	//
	// Under a flood heavy enough to fill this, some legitimate peer keys will
	// be evicted before their connection is accepted, and those connections are
	// then anonymous. That is a refusal at every consumer that fails closed,
	// which is the correct way to lose: the alternative this replaces was
	// unbounded growth and an O(n) prune per insert under the lock on the
	// receive path, which loses everything.
	for len(t.order) >= peerTableMax {
		t.dropFront()
	}

	t.entries[k] = peerEntry{key: key, identity: identity, hasIdentity: hasIdentity, inserted: now}
	t.order = append(t.order, orderRecord{inserted: now, dcid: k})
}

// take removes and returns the (key, identity) for dcid, if one is recorded,
// not poisoned, and not expired. It returns both so the one read the bridge
// performs surfaces the SIP-2 key and the SIP-3 identity together. The bool
// results are: hasIdentity (an Ed25519 identity was bound) and ok (an entry
// resolved at all).
func (t *peerTable) take(dcid []byte, now time.Time) (key [32]byte, identity [32]byte, hasIdentity bool, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := string(dcid)
	e, present := t.entries[k]
	if !present {
		return [32]byte{}, [32]byte{}, false, false
	}
	delete(t.entries, k)
	if e.poisoned || now.Sub(e.inserted) >= peerKeyTTL {
		return [32]byte{}, [32]byte{}, false, false
	}
	return e.key, e.identity, e.hasIdentity, true
}

// initialDCID returns the Destination Connection ID of a QUIC long-header
// (Initial) packet. Layout: byte 0 flags, bytes 1..5 version, byte 5 DCID
// length (0..=20), bytes 6..6+len DCID. isQUICInitial has already checked the
// flags.
func initialDCID(pkt []byte) ([]byte, bool) {
	if len(pkt) < 6 {
		return nil, false
	}
	n := int(pkt[5])
	if n > 20 || len(pkt) < 6+n {
		return nil, false
	}
	return pkt[6 : 6+n], true
}

// clientConn wraps a *net.UDPConn for the client side.
// It appends the client's X25519 public key and a DH-based MAC1 to outgoing Initial packets.
// Implements OOBCapablePacketConn so quic-go uses the fast path (recvmmsg, sendmmsg, GSO, ECN).
type clientConn struct {
	conn             *net.UDPConn
	batchReader      *ipv4.PacketConn // lazy-initialised for ReadBatch
	sharedSecret     []byte           // X25519(clientPriv, serverPub)
	clientPubKey     []byte           // 32-byte X25519 public key
	advertiseEd25519 []byte           // SIP-3: 32-byte Ed25519 identity to assert, or 32 zero bytes
	envelopeVersion  uint8            // SIP-29: the envelope version this client emits
	serverAddr       *net.UDPAddr     // the address dialled; a cookie reply from anywhere else is not ours
	gateKey          [32]byte         // keys MAC0 (envelope v3); derived from the server's public key
	cookieKey        [32]byte         // decrypts cookie replies; derived from the server's public key
	handshakeDone    atomic.Bool      // true after first non-cookie packet; skips the cookie scan
	cookie           atomic.Value     // decrypted 16-byte cookie from the server, keys MAC2
	// The most recent Initial datagram and where it went, so a cookie
	// challenge can be answered immediately rather than at the next PTO.
	lastInitial atomic.Value // holds sentInitial
	// answered reports whether the current Initial has already had a challenge
	// answered for it. One answer per Initial sent, which is what bounds the
	// work an injected cookie reply can buy.
	answered atomic.Bool
}

// sentInitial is the last Initial datagram written, kept so a cookie challenge
// can be answered without waiting for a retransmission timer.
type sentInitial struct {
	datagram []byte
	addr     *net.UDPAddr
}

func newClientConn(conn *net.UDPConn, sharedSecret, clientX25519Pub, advertiseEd25519 []byte, serverAddr *net.UDPAddr, gateKey, cookieKey [32]byte, envelopeVersion uint8) *clientConn {
	// Always a 32-byte field so the client's MAC1 input and the bytes on the
	// wire match what the server reads and hashes (all zeros = no identity).
	if len(advertiseEd25519) != Ed25519Size {
		advertiseEd25519 = make([]byte, Ed25519Size)
	}
	return &clientConn{
		conn:             conn,
		sharedSecret:     sharedSecret,
		clientPubKey:     clientX25519Pub,
		advertiseEd25519: advertiseEd25519,
		envelopeVersion:  envelopeVersion,
		serverAddr:       serverAddr,
		gateKey:          gateKey,
		cookieKey:        cookieKey,
	}
}

// storeCookie opens a cookie reply and keeps the cookie for the next Initial.
//
// The reply arrives encrypted; MAC2 is keyed on the plaintext, so it has to be
// opened here. A reply we cannot open did not come from a server holding the
// key we expect, so it is dropped and any cookie we already had is kept.
func (c *clientConn) storeCookie(payload []byte) bool {
	plain, ok := DecryptCookie(c.cookieKey, payload)
	if !ok || len(plain) != CookieSize {
		return false
	}

	// A reply carrying a cookie we already hold tells us nothing new, so it
	// earns no retransmission. Without this, one captured cookie reply replayed
	// at us is an unbounded supply of Initials aimed at the server — the reply
	// is 57 bytes and the Initial it provokes is 1309.
	if held, ok := c.cookie.Load().([]byte); ok && bytes.Equal(held, plain) {
		return true
	}
	c.cookie.Store(plain)
	c.answerChallenge()
	return true
}

// fromServer reports whether a datagram came from the address this client
// dialled.
//
// A cookie reply is sealed under a key derived from the server's *public* key,
// which is published — so anyone at all can mint one that opens, and the source
// address is the only thing separating the server from a stranger who would
// like this client to send a 1309-byte Initial for every 57 bytes they spend.
func (c *clientConn) fromServer(a net.Addr) bool {
	if c.serverAddr == nil {
		return false
	}
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return false
	}
	// IP.Equal sees through the IPv4-mapped form, which a dual-stack socket may
	// report for the same host.
	return ua.Port == c.serverAddr.Port && ua.IP.Equal(c.serverAddr.IP)
}

// answerChallenge re-sends the last Initial straight away, now carrying MAC2.
//
// quic-go never sees a cookie reply — the read paths strip them out — so left
// to itself it would not retransmit until its next PTO. The challenge is
// answerable at once and waiting costs the caller a whole round of backoff, so
// answer it here. WireGuard does the same, and squic-rust matches.
//
// Replaying the datagram is sound: the server dropped the original at the MAC2
// gate before quic-go saw it, so this is the first time that packet number
// reaches the peer; where it did get through, the duplicate is discarded. Only
// the sQUIC envelope is rebuilt, never the QUIC packet inside it.
func (c *clientConn) answerChallenge() {
	// One answer per Initial sent. A challenge is a response to something we
	// sent, so answering more than once for the same Initial is work an
	// attacker chose for us rather than work the handshake needs. Swap is the
	// whole check: whoever gets false answers, everyone else returns.
	if c.answered.Swap(true) {
		return
	}
	last, ok := c.lastInitial.Load().(sentInitial)
	if !ok || last.addr == nil {
		return // nothing sent yet; the next Initial will carry the cookie
	}
	c.conn.WriteToUDP(c.buildInitial(last.datagram), last.addr)
}

// rememberInitial keeps a copy of the datagram just sent, for answerChallenge.
func (c *clientConn) rememberInitial(p []byte, addr *net.UDPAddr) {
	c.lastInitial.Store(sentInitial{datagram: append([]byte(nil), p...), addr: addr})
	// A fresh Initial earns one answered challenge.
	c.answered.Store(false)
}

// --- net.PacketConn methods (delegate to underlying UDPConn) ---

func (c *clientConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.conn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		// Fast path: after handshake, no cookie replies possible
		if c.handshakeDone.Load() {
			return n, addr, nil
		}
		if n > 0 && b[0] == CookieReplyType && c.fromServer(addr) {
			c.storeCookie(b[1:n])
			continue
		}
		return n, addr, nil
	}
}

// WriteTo stamps the MAC envelope onto every Initial, not merely the first.
//
// The server silently drops any Initial that fails MAC1, so an unauthenticated
// retransmission is indistinguishable from an attack and gets dropped. A client
// that stopped stamping after the first packet could never recover from losing
// it — the handshake would stall until it timed out.
func (c *clientConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if isQUICInitial(p) {
		return c.writeInitial(p, addr.(*net.UDPAddr))
	}
	c.armFastPath(p)
	return c.conn.WriteTo(p, addr)
}

// armFastPath stops the read paths looking for cookie replies, once there can
// no longer be one to find.
//
// A short header means 1-RTT keys, which means the handshake finished — and
// only an Initial is ever challenged, so no cookie can follow. Arming this on
// the read side instead, at the first packet that was not a cookie, was wrong:
// the server's very first packet back clears it, and a server that then enters
// under-load mode mid-handshake challenges an Initial whose reply the client
// has stopped reading. The connection stalls until it times out, and only a
// fresh attempt recovers.
func (c *clientConn) armFastPath(p []byte) {
	if isShortHeader(p) {
		c.handshakeDone.Store(true)
	}
}

func (c *clientConn) Close() error                       { return c.conn.Close() }
func (c *clientConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *clientConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *clientConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *clientConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// net.Conn methods required by x/net/ipv4.NewPacketConn
func (c *clientConn) Read(b []byte) (int, error)  { return c.conn.Read(b) }
func (c *clientConn) Write(b []byte) (int, error) { return c.conn.Write(b) }
func (c *clientConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }

// --- OOBCapablePacketConn methods (delegate to underlying UDPConn) ---

func (c *clientConn) SyscallConn() (syscall.RawConn, error) { return c.conn.SyscallConn() }
func (c *clientConn) SetReadBuffer(bytes int) error         { return c.conn.SetReadBuffer(bytes) }
func (c *clientConn) SetWriteBuffer(bytes int) error        { return c.conn.SetWriteBuffer(bytes) }

func (c *clientConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	for {
		n, oobn, flags, addr, err = c.conn.ReadMsgUDP(b, oob)
		if err != nil {
			return
		}
		// Fast path: after handshake, no cookie replies possible
		if c.handshakeDone.Load() {
			return
		}
		if n > 0 && b[0] == CookieReplyType && c.fromServer(addr) {
			c.storeCookie(b[1:n])
			continue
		}
		return
	}
}

// WriteMsgUDP stamps every Initial, for the same reason as WriteTo.
func (c *clientConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if isQUICInitial(b) {
		return c.writeInitialMsg(b, oob, addr)
	}
	c.armFastPath(b)
	return c.conn.WriteMsgUDP(b, oob, addr)
}

// ReadBatch reads a batch of packets, intercepting cookie replies.
//
// This implements the batchConn interface quic-go checks for. Without it,
// quic-go unwraps our SyscallConn() and reads the raw FD directly, so cookie
// replies never reach storeCookie and land in quic-go as unparseable packets
// instead — leaving the client unable to answer a challenge it did receive.
// serverConn needs the same override for MAC1 validation.
// moveMessage moves packet src's contents into slot dst, leaving each slot's
// own Buffers where it is. Returns false if dst's buffer cannot hold n bytes,
// in which case nothing is written and the caller must drop the packet rather
// than forward a truncated one.
//
// The obvious way to compact — `ms[dst] = ms[src]` — is wrong here, and wrong
// in a way that corrupts packet data rather than merely leaking. quic-go keeps
// a parallel array and pairs the two **by index** (sys_conn_oob.go, ReadPacket):
//
//	msg := c.messages[c.readPos]
//	buffer := c.buffers[c.readPos]
//	p := receivedPacket{data: msg.Buffers[0][:msg.N], buffer: buffer}
//
// and it re-establishes that pairing itself, refreshing only the slots below
// readPos. Assigning the whole ipv4.Message carries Buffers across with it, so
// quic-go then hands the application packet src's bytes paired with slot dst's
// buffer handle. Releasing that packet returns the wrong buffer to the pool,
// while the memory actually holding the live data is never refreshed and is
// written into by the next recvmmsg.
//
// So squic copies the payload rather than the descriptor, which is what
// squic-rust has always done — it copies bytes between buffers and was never
// exposed to this. The contract being honoured: ReadBatch may fill messages,
// but it must not reorder their buffers.
func moveMessage(ms []ipv4.Message, dst, src, n int) bool {
	if len(ms[dst].Buffers) == 0 || len(ms[dst].Buffers[0]) < n {
		return false
	}
	copy(ms[dst].Buffers[0], ms[src].Buffers[0][:n])
	ms[dst].N = n
	if nn := ms[src].NN; nn > 0 && len(ms[dst].OOB) >= nn {
		copy(ms[dst].OOB, ms[src].OOB[:nn])
		ms[dst].NN = nn
	} else {
		ms[dst].NN = 0
	}
	ms[dst].Addr = ms[src].Addr
	ms[dst].Flags = ms[src].Flags
	return true
}

func (c *clientConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	if c.batchReader == nil {
		c.batchReader = ipv4.NewPacketConn(c.conn)
	}

	// A loop rather than recursion, for the reason given on serverConn.ReadBatch:
	// a peer that can send cookie replies can send nothing else, and recursing
	// per batch would grow the stack until the process aborts.
	for {
		n, err := c.batchReader.ReadBatch(ms, flags)
		if err != nil {
			return 0, err
		}

		// Fast path: after the handshake there are no cookie replies to look for.
		if c.handshakeDone.Load() {
			return n, nil
		}

		valid := 0
		sawCookie := false
		for i := 0; i < n; i++ {
			data := ms[i].Buffers[0][:ms[i].N]
			if len(data) > 0 && data[0] == CookieReplyType && c.fromServer(ms[i].Addr) {
				c.storeCookie(data[1:])
				sawCookie = true
				continue
			}
			if valid != i && !moveMessage(ms, valid, i, ms[i].N) {
				continue
			}
			valid++
		}

		if !sawCookie {
			return n, nil
		}
		if valid == 0 {
			// The whole batch was cookie replies — read the next one.
			continue
		}
		return valid, nil
	}
}

// buildInitial constructs the Initial packet with MAC1 + MAC2 appended.
func (c *clientConn) buildInitial(p []byte) []byte {
	// An identity is carried only when there is one to carry. The header byte
	// says which, so the server knows the trailer's width before it parses
	// anything.
	hasIdentity := false
	for _, b := range c.advertiseEd25519 {
		if b != 0 {
			hasIdentity = true
			break
		}
	}
	hdr := Hdr(c.envelopeVersion, hasIdentity)
	trailer, ok := TrailerLen(hdr)
	if !ok {
		// Dial refuses an unknown version before a clientConn is built, so this
		// is unreachable. Emit the version this build implements rather than a
		// buffer sized for one layout and written for another, which was a
		// panic rather than a bad packet.
		hdr = Hdr(EnvelopeV4, hasIdentity)
		trailer, _ = TrailerLen(hdr)
	}
	ts := NowTimestamp()

	buf := make([]byte, len(p)+trailer)
	copy(buf, p)
	off := len(p)
	copy(buf[off:], c.clientPubKey)
	off += ClientKeySize
	if hasIdentity {
		copy(buf[off:], c.advertiseEd25519)
		off += Ed25519Size
	}
	binary.BigEndian.PutUint32(buf[off:], ts)
	off += TimestampSize

	// Both tags cover exactly the bytes written so far, which is the contiguous
	// range the server hashes. The gate's key is the whole difference between
	// the two modes: the cookie when we hold one, the server's public key
	// otherwise.
	gateKey := c.gateKey[:]
	if held, ok := c.cookie.Load().([]byte); ok && held != nil {
		gateKey = held
	}
	copy(buf[off:], ComputeGate(hdr, gateKey, buf[:off]))
	gateEnd := off + GateSize
	copy(buf[gateEnd:], ComputeMAC1(hdr, c.sharedSecret, buf[:off]))

	// SIP-29: the header goes last, because that is the only offset a receiver
	// can find without already knowing the trailer's width.
	buf[len(buf)-1] = hdr
	return buf
}

// writeInitial appends client pubkey + timestamp + MAC1 + MAC2 to an Initial packet (WriteTo path).
func (c *clientConn) writeInitial(p []byte, addr *net.UDPAddr) (int, error) {
	c.rememberInitial(p, addr)
	buf := c.buildInitial(p)
	n, err := c.conn.WriteToUDP(buf, addr)
	if err == nil {
		n = len(p)
	}
	return n, err
}

// writeInitialMsg appends client pubkey + timestamp + MAC1 + MAC2 to an Initial packet (WriteMsgUDP path).
func (c *clientConn) writeInitialMsg(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	c.rememberInitial(b, addr)
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
	allowedKeys      map[[32]byte]bool // optional whitelist of client X25519 public keys
	batchReader      *ipv4.PacketConn  // lazy-initialized for ReadBatch

	gateKey [32]byte // keys MAC0 (envelope v3); derived from our public key
	// MAC2 + cookie DDoS protection
	cookieKey        [32]byte     // encrypts cookie replies; derived from our public key
	secretsMu        sync.RWMutex // protects the two rotating secrets below
	cookieSecret     [32]byte     // current cookie secret, mints per-IP cookies
	prevCookieSecret [32]byte     // previous secret, for the rotation grace period
	underLoad        atomic.Bool  // true when DH rate exceeds threshold
	dhCount          atomic.Int64 // DH operations in current second
	cookieReplies    atomic.Int64 // challenges issued since start
	mac2Verified     atomic.Int64 // Initials admitted on a valid MAC2
	// accepted counts Initials admitted per envelope version, indexed as
	// EnvelopeVersions.
	//
	// The number a deployment needs before retiring a version: without it the
	// choice is made on nerve, and getting it wrong locks out every client that
	// had not moved — silently, because a refused envelope is dropped without a
	// word.
	accepted         []atomic.Int64
	loadThreshold    int64   // DH/sec before entering under-load mode
	acceptedVersions []uint8 // SIP-29: envelope versions this server parses

	// peers maps DCID -> MAC1-verified peer key, drained by the application at
	// accept via the ConnContext/Tracer bridge in Listen. See SIP-2.
	peers *peerTable
}

// cookieSecrets returns the current and previous secrets under the read lock.
func (c *serverConn) cookieSecrets() (current, previous [32]byte) {
	c.secretsMu.RLock()
	defer c.secretsMu.RUnlock()
	return c.cookieSecret, c.prevCookieSecret
}

func newServerConn(conn *net.UDPConn, serverX25519Priv []byte, allowedKeys [][]byte, loadThreshold int64, acceptedVersions []uint8) *serverConn {
	sc := &serverConn{
		conn:             conn,
		serverX25519Priv: serverX25519Priv,
		loadThreshold:    loadThreshold,
		acceptedVersions: acceptedVersions,
		peers:            newPeerTable(),
		accepted:         make([]atomic.Int64, len(EnvelopeVersions)),
	}

	serverPub := x25519Public(serverX25519Priv)
	sc.cookieKey = CookieKey(serverPub)
	sc.gateKey = GateKey(serverPub)

	// The previous secret starts out equal to the current one rather than
	// random: until the first rotation there is no earlier secret, and seeding
	// it randomly makes the grace branch check a secret never in use.
	rand.Read(sc.cookieSecret[:])
	sc.prevCookieSecret = sc.cookieSecret

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

	// loadThreshold 0 means the caller turned the cookie defence off: no load
	// to track, and no cookies to rotate secrets for.
	if sc.loadThreshold > 0 {
		go sc.rotateCookieSecrets()
		go sc.monitorLoad()
	}

	return sc
}

// rotateCookieSecrets rotates the cookie encryption secret every 120 seconds.
func (c *serverConn) rotateCookieSecrets() {
	ticker := time.NewTicker(120 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		var fresh [32]byte
		rand.Read(fresh[:])
		c.secretsMu.Lock()
		c.prevCookieSecret = c.cookieSecret
		c.cookieSecret = fresh
		c.secretsMu.Unlock()
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

// loadStats reports the state of the cookie defence.
func (c *serverConn) loadStats() LoadStats {
	accepted := make(map[uint8]int64, len(EnvelopeVersions))
	for i, v := range EnvelopeVersions {
		accepted[v] = c.accepted[i].Load()
	}
	return LoadStats{
		UnderLoad:         c.underLoad.Load(),
		CookieRepliesSent: c.cookieReplies.Load(),
		MAC2Verified:      c.mac2Verified.Load(),
		AcceptedByVersion: accepted,
	}
}

// sendCookieReply sends an encrypted cookie to the client.
// The cookie is deterministic for (secret, IP), encrypted for transport.
func (c *serverConn) sendCookieReply(addr *net.UDPAddr) {
	current, _ := c.cookieSecrets()
	cookie := CookieValue(current, addr.IP)
	// Encrypted under the key derived from our public key, which the client can
	// also derive — not under the secret, which is ours alone and which the
	// client could never decrypt with.
	encrypted, err := EncryptCookie(c.cookieKey, cookie)
	if err != nil {
		return
	}
	reply := make([]byte, 1+len(encrypted))
	reply[0] = CookieReplyType
	copy(reply[1:], encrypted)
	c.cookieReplies.Add(1)
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
func (c *serverConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *serverConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// net.Conn methods required by x/net/ipv4.NewPacketConn
func (c *serverConn) Read(b []byte) (int, error)  { return c.conn.Read(b) }
func (c *serverConn) Write(b []byte) (int, error) { return c.conn.Write(b) }
func (c *serverConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }

// --- OOBCapablePacketConn methods ---

func (c *serverConn) SyscallConn() (syscall.RawConn, error) { return c.conn.SyscallConn() }
func (c *serverConn) SetReadBuffer(bytes int) error         { return c.conn.SetReadBuffer(bytes) }
func (c *serverConn) SetWriteBuffer(bytes int) error        { return c.conn.SetWriteBuffer(bytes) }

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
	// No UDP_GRO here, and that is deliberate — see S9. squic-rust hit a real
	// bug by inheriting it from quinn-udp: with GRO on, the kernel returns one
	// descriptor covering several coalesced datagrams, and validating the
	// concatenation as a single Initial silently drops every one of them. This
	// path never enables GRO, so each datagram arrives on its own, and the
	// filter below is right by construction rather than by luck. Anyone adding
	// GRO for throughput has to solve stripping first: the trailer width varies
	// by envelope version, so stripped segments are not uniformly sized and
	// cannot be described by a single stride.
	//
	// Use the underlying ipv4.PacketConn for actual batch reads (recvmmsg on Linux)
	if c.batchReader == nil {
		c.batchReader = ipv4.NewPacketConn(c.conn)
	}

	// A loop, not recursion. Dropping a whole batch is the *expected* outcome
	// under the flood this server is built to discard cheaply, so recursing
	// once per batch never unwinds: the stack grows until Go aborts the process
	// with "goroutine stack exceeds", which recover() cannot catch. squic-rust
	// has always looped here.
	for {
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
					if !moveMessage(ms, valid, i, stripped) {
						continue
					}
				} else {
					ms[valid].N = stripped
				}
				valid++
			}
		}

		if valid == 0 {
			// All packets in this batch were invalid — read the next one.
			continue
		}

		return valid, nil
	}
}

// validateAndStrip checks if the packet is valid and strips MAC overhead from Initial packets.
// Returns (true, newLength) if valid, (false, 0) if should be dropped.
// addr is used to send cookie replies when under load (can be nil to skip).
// outcome is what one envelope-version attempt concluded (SIP-29).
//
// challengeNeeded is reported rather than acted on, so that trying two layouts
// for one datagram cannot send the caller two cookie replies.
type outcome int

const (
	outcomeDrop outcome = iota
	outcomeChallenge
	outcomeAccepted
)

// validateAndStrip dispatches an Initial on its envelope version (SIP-29) and
// validates it. Returns (true, newLength) if valid, (false, 0) to drop.
//
// The version marker is the last byte of the datagram, which is the only place
// a receiver can read without already knowing the trailer's width — and knowing
// the width is what the marker is for. Version 1 predates the marker and carries
// none, so it is the fallback: its last byte is the last byte of MAC2, uniformly
// random, and names version 2 about once in 256 packets. That costs one wasted
// parse before the fallback succeeds, and nothing for the other 255.
//
// addr is used to send cookie replies when under load (can be nil to skip).
func (c *serverConn) validateAndStrip(p []byte, n int, addr *net.UDPAddr) (bool, int) {
	// A long header the QUIC stack cannot version-parse draws a Version
	// Negotiation reply out of it, which is a response to a caller that proved
	// nothing. Drop those here, before the stack sees them. See versionAccepted
	// for why the gate is on the version and not the packet type.
	if isLongHeader(p[:n]) && !versionAccepted(p[:n]) {
		return false, 0
	}

	// 0-RTT carries no envelope and cannot be given one: it is sent before the
	// handshake this transport authenticates, so there is no Initial of its own
	// to wrap and no shared secret yet to key MAC1 with. A stack that accepts a
	// standalone 0-RTT datagram is taking application data from a caller who
	// passed no gate, no MAC1 and no whitelist. sQUIC does not support 0-RTT;
	// this is where that is enforced.
	//
	// Only a datagram that starts with 0-RTT. One coalescing an Initial in
	// front of it begins with 0xC0, so it is envelope-checked as a whole —
	// MAC1 covers every byte, the 0-RTT among them — and quic-go splits it
	// afterwards.
	if isQUICZeroRTT(p[:n]) {
		return false, 0
	}

	// Non-Initial packets pass through unmodified
	if !isQUICInitial(p[:n]) {
		return true, n
	}

	// One version, so one layout: read the header byte and validate. The
	// guessing this replaced — try the marked version, then try unmarked v1 —
	// is what let a single datagram be parsed twice, and with it buy two curve
	// operations from a server that had accepted the older versions.
	hdr := p[n-1]
	switch res, quicLen := c.validateEnvelope(hdr, p, n, addr); res {
	case outcomeAccepted:
		return true, quicLen
	case outcomeChallenge:
		if addr != nil {
			c.sendCookieReply(addr)
		}
	}
	return false, 0
}

// accepts reports whether this server parses the given envelope version.
func (c *serverConn) accepts(version uint8) bool {
	for _, v := range c.acceptedVersions {
		if v == version {
			return true
		}
	}
	return false
}

// validateEnvelope validates one Initial.
//
// Returns outcomeChallenge rather than sending the cookie reply itself, so the
// caller owns the one-reply-per-datagram rule.
func (c *serverConn) validateEnvelope(hdr uint8, p []byte, n int, addr *net.UDPAddr) (outcome, int) {
	if !c.accepts(HdrVersion(hdr)) {
		return outcomeDrop, 0
	}
	trailer, known := TrailerLen(hdr)
	if !known || n <= trailer {
		return outcomeDrop, 0
	}

	quicLen := n - trailer
	off := quicLen
	clientPub := p[off : off+ClientKeySize]
	off += ClientKeySize
	// SIP-3: carried only when the header says so. Version 3 sent 32 zero bytes
	// on every anonymous Initial to say the same thing.
	var edField []byte
	if HdrHasIdentity(hdr) {
		edField = p[off : off+Ed25519Size]
		off += Ed25519Size
	}
	tsBytes := p[off : off+TimestampSize]
	off += TimestampSize
	// Both tags cover exactly this range, contiguously from offset 0.
	covered := p[:off]
	gate := p[off : off+GateSize]
	off += GateSize
	mac1 := p[off : off+MACSize]
	timestamp := binary.BigEndian.Uint32(tsBytes)

	// Step 1: replay window (cheap)
	if !TimestampInWindow(timestamp, NowTimestamp()) {
		return outcomeDrop, 0
	}

	// Step 2: the gate — one HMAC, before any curve operation.
	//
	// MAC1 is a Diffie-Hellman, so without something cheap in front of it a
	// server cannot tell a caller who knows its public key from a stranger, and
	// must challenge both — which is how a server under load ends up answering
	// everybody. The gate settles that question first.
	if c.underLoad.Load() {
		// Three outcomes, and the middle one is the whole of SIP-37:
		//
		//   cookie-keyed   proves the key *and* the address. Accept.
		//   key-keyed      proves the key but not the address. Challenge — this
		//                  caller is worth a 57-byte reply, and the reply tells
		//                  them nothing they did not already know, since they
		//                  demonstrated the key to get here.
		//   neither        proves nothing. Silence.
		//
		// Challenging on a failed cookie check alone would answer strangers
		// too, which is the defect MAC0 was added to close: a server under load
		// that replies to anyone has stopped being silent exactly when it
		// matters most.
		switch {
		case addr != nil && c.gateMatchesCookie(hdr, covered, gate, addr.IP):
			c.mac2Verified.Add(1)
		case VerifyGate(hdr, c.gateKey[:], covered, gate):
			return outcomeChallenge, 0
		default:
			return outcomeDrop, 0
		}
	} else {
		// The public-key form, then the cookie: a client that answered a
		// challenge during an earlier burst still holds one, and should not be
		// made to re-handshake because the load subsided. Two HMACs at worst,
		// still far below one X25519.
		if !VerifyGate(hdr, c.gateKey[:], covered, gate) &&
			!(addr != nil && c.gateMatchesCookie(hdr, covered, gate, addr.IP)) {
			return outcomeDrop, 0
		}
	}

	// Step 4: Whitelist check (fast map lookup, before expensive DH)
	c.keysMu.RLock()
	keys := c.allowedKeys
	c.keysMu.RUnlock()
	if keys != nil {
		var key [32]byte
		copy(key[:], clientPub)
		if !keys[key] {
			return outcomeDrop, 0
		}
	}

	// Step 5: DH + MAC1 verification (expensive)
	c.dhCount.Add(1)
	shared, dhErr := X25519(c.serverX25519Priv, clientPub)
	if dhErr != nil {
		return outcomeDrop, 0
	}

	if !VerifyMAC1(hdr, shared, covered, mac1) {
		return outcomeDrop, 0
	}

	// MAC1 holds, and it covers the version marker, which SIP-29 prefixes to
	// its input — a peer that tampered with the marker produces a tag over a
	// different layout, which is why a flipped marker can only cost a drop and
	// never an accept.
	//
	// SIP-3: if the caller asserted an Ed25519 identity (nonzero field), it must
	// forward-derive to the X25519 key MAC1 just proved. The map runs this way
	// even though it does not run backwards; the caller states which key is its
	// own and the server checks the statement. A mismatch, a non-point key, or a
	// small-order point fails the handshake rather than downgrading to anonymous.
	//
	// All zeros means "no identity asserted". It is a *valid* point — the order-4
	// point, deriving to u = 1 — not an invalid encoding, so it is matched
	// explicitly rather than left to fail the derivation.
	var identity [32]byte
	hasIdentity := false
	edZero := true
	for _, b := range edField {
		if b != 0 {
			edZero = false
			break
		}
	}
	if !edZero {
		derived, edErr := Ed25519IdentityToX25519(edField)
		if edErr != nil || subtle.ConstantTimeCompare(derived, clientPub) != 1 {
			return outcomeDrop, 0
		}
		copy(identity[:], edField)
		hasIdentity = true
	}

	// Record both against the Initial's DCID so the application can recover the
	// peer at accept (SIP-2 key, SIP-3 id).
	if dcid, ok := initialDCID(p[:quicLen]); ok {
		var key [32]byte
		copy(key[:], clientPub)
		c.peers.record(dcid, key, identity, hasIdentity, time.Now())
	}

	if i, ok := VersionIndex(HdrVersion(hdr)); ok {
		c.accepted[i].Add(1)
	}
	return outcomeAccepted, quicLen
}

// gateMatchesCookie reports whether gate verifies under the cookie for ip,
// trying the current secret and then the previous one.
//
// Two secrets because they rotate on a timer: a caller that answered a
// challenge seconds before a rotation holds a cookie derived from the older
// one, and refusing it would turn a routine rotation into a failed handshake.
func (c *serverConn) gateMatchesCookie(hdr uint8, covered []byte, gate []byte, ip net.IP) bool {
	current, previous := c.cookieSecrets()
	if VerifyGate(hdr, CookieValue(current, ip), covered, gate) {
		return true
	}
	return VerifyGate(hdr, CookieValue(previous, ip), covered, gate)
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
