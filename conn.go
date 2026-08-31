package squic

import (
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
	mac0Key          [32]byte         // keys MAC0 (envelope v3); derived from the server's public key
	cookieKey        [32]byte         // decrypts cookie replies; derived from the server's public key
	handshakeDone    atomic.Bool      // true after first non-cookie packet; skips the cookie scan
	cookie           atomic.Value     // decrypted 16-byte cookie from the server, keys MAC2
	// The most recent Initial datagram and where it went, so a cookie
	// challenge can be answered immediately rather than at the next PTO.
	lastInitial atomic.Value // holds sentInitial
}

// sentInitial is the last Initial datagram written, kept so a cookie challenge
// can be answered without waiting for a retransmission timer.
type sentInitial struct {
	datagram []byte
	addr     *net.UDPAddr
}

func newClientConn(conn *net.UDPConn, sharedSecret, clientX25519Pub, advertiseEd25519 []byte, mac0Key, cookieKey [32]byte, envelopeVersion uint8) *clientConn {
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
		mac0Key:          mac0Key,
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
	if !ok || len(plain) != MAC2Size {
		return false
	}
	c.cookie.Store(plain)
	c.answerChallenge()
	return true
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
	last, ok := c.lastInitial.Load().(sentInitial)
	if !ok || last.addr == nil {
		return // nothing sent yet; the next Initial will carry the cookie
	}
	c.conn.WriteToUDP(c.buildInitial(last.datagram), last.addr)
}

// rememberInitial keeps a copy of the datagram just sent, for answerChallenge.
func (c *clientConn) rememberInitial(p []byte, addr *net.UDPAddr) {
	c.lastInitial.Store(sentInitial{datagram: append([]byte(nil), p...), addr: addr})
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
		if n > 0 && b[0] == CookieReplyType {
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
		if n > 0 && b[0] == CookieReplyType {
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
			if len(data) > 0 && data[0] == CookieReplyType {
				c.storeCookie(data[1:])
				sawCookie = true
				continue
			}
			if valid != i {
				ms[valid] = ms[i]
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
	ts := NowTimestamp()
	nonce, _ := GenerateNonce()
	mac1 := ComputeMAC1(c.envelopeVersion, c.sharedSecret, p, c.advertiseEd25519, ts, nonce)

	trailer, ok := TrailerLen(c.envelopeVersion)
	if !ok {
		trailer = MACOverhead
	}
	buf := make([]byte, len(p)+trailer)
	copy(buf, p)
	off := len(p)
	copy(buf[off:], c.clientPubKey)
	off += ClientKeySize
	copy(buf[off:], c.advertiseEd25519) // SIP-3: Ed25519 identity, or zeros
	off += Ed25519Size
	binary.BigEndian.PutUint32(buf[off:], ts)
	off += TimestampSize
	copy(buf[off:], nonce)
	off += NonceSize

	// MAC0 (v3): computed over exactly the bytes written so far, which is the
	// contiguous range the server hashes.
	if HasMAC0(c.envelopeVersion) {
		copy(buf[off:], ComputeMAC0(c.envelopeVersion, c.mac0Key, buf[:off]))
		off += MAC0Size
	}

	copy(buf[off:], mac1)
	off += MACSize

	// MAC2: zeros if no cookie, computed if the server has sent us one.
	//
	// The server verifies over everything up to but NOT including mac1,
	// passing mac1 separately, so the slice here has to stop short of the mac1
	// just written. Covering buf[:off] folds mac1 in twice and never verifies.
	if cookie, ok := c.cookie.Load().([]byte); ok && len(cookie) > 0 {
		mac2 := ComputeMAC2(cookie, buf[:off-MACSize], mac1)
		copy(buf[off:], mac2)
	}
	// else: MAC2 field is already zeros from make()
	off += MAC2Size

	// SIP-29: the marker goes last, after MAC2, because that is the only offset
	// a receiver can find without already knowing the trailer's width. Version 1
	// predates it and emits nothing, which is what keeps this client able to
	// talk to a server that has not moved yet.
	if c.envelopeVersion != EnvelopeV1 {
		buf[off] = c.envelopeVersion
	}

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

	mac0Key [32]byte // keys MAC0 (envelope v3); derived from our public key
	// MAC2 + cookie DDoS protection
	cookieKey        [32]byte     // encrypts cookie replies; derived from our public key
	secretsMu        sync.RWMutex // protects the two rotating secrets below
	cookieSecret     [32]byte     // current cookie secret, mints per-IP cookies
	prevCookieSecret [32]byte     // previous secret, for the rotation grace period
	underLoad        atomic.Bool  // true when DH rate exceeds threshold
	dhCount          atomic.Int64 // DH operations in current second
	cookieReplies    atomic.Int64 // challenges issued since start
	mac2Verified     atomic.Int64 // Initials admitted on a valid MAC2
	loadThreshold    int64        // DH/sec before entering under-load mode
	acceptedVersions []uint8      // SIP-29: envelope versions this server parses

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
	}

	serverPub := x25519Public(serverX25519Priv)
	sc.cookieKey = CookieKey(serverPub)
	sc.mac0Key = MAC0Key(serverPub)

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
	return LoadStats{
		UnderLoad:         c.underLoad.Load(),
		CookieRepliesSent: c.cookieReplies.Load(),
		MAC2Verified:      c.mac2Verified.Load(),
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
					ms[valid] = ms[i]
				}
				ms[valid].N = stripped
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

	// Non-Initial packets pass through unmodified
	if !isQUICInitial(p[:n]) {
		return true, n
	}

	marked := p[n-1]
	challenge := false

	// A marked version, if we accept it and it is not the unmarked one.
	if marked != EnvelopeV1 && c.accepts(marked) {
		switch res, quicLen := c.tryVersion(marked, p, n, addr); res {
		case outcomeAccepted:
			return true, quicLen
		case outcomeChallenge:
			challenge = true
		}
	}

	// Then the unmarked form, which is the only version that needs guessing.
	if c.accepts(EnvelopeV1) {
		switch res, quicLen := c.tryVersion(EnvelopeV1, p, n, addr); res {
		case outcomeAccepted:
			return true, quicLen
		case outcomeChallenge:
			challenge = true
		}
	}

	// At most one challenge per datagram, however many layouts were tried.
	if challenge && addr != nil {
		c.sendCookieReply(addr)
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

// tryVersion validates one Initial under one envelope version.
func (c *serverConn) tryVersion(version uint8, p []byte, n int, addr *net.UDPAddr) (outcome, int) {
	trailer, known := TrailerLen(version)
	if !known || n <= trailer {
		return outcomeDrop, 0
	}

	quicLen := n - trailer
	off := quicLen
	clientPub := p[off : off+ClientKeySize]
	off += ClientKeySize
	edField := p[off : off+Ed25519Size]
	off += Ed25519Size
	tsBytes := p[off : off+TimestampSize]
	off += TimestampSize
	nonce := p[off : off+NonceSize]
	off += NonceSize
	// MAC0 covers everything up to here, contiguously.
	mac0End := off
	var mac0 []byte
	if HasMAC0(version) {
		mac0 = p[off : off+MAC0Size]
		off += MAC0Size
	}
	mac1Start := off
	mac1 := p[off : off+MACSize]
	off += MACSize
	mac2 := p[off : off+MAC2Size]
	timestamp := binary.BigEndian.Uint32(tsBytes)

	// Step 1: Replay protection — reject timestamps outside window (cheap)
	if !TimestampInWindow(timestamp, NowTimestamp()) {
		return outcomeDrop, 0
	}

	// Step 2: MAC0 — the cheap gate (envelope v3).
	//
	// This is the step that makes the cookie defence below silent. MAC1 is a
	// Diffie-Hellman, so without something cheap in front of it a server cannot
	// tell a caller who knows its public key from a stranger, and must
	// therefore challenge both — which is how a server under load ends up
	// answering everybody. MAC0 costs one HMAC and settles that question before
	// the challenge is issued, and before the curve operation, so rubbish never
	// reaches either.
	//
	// Versions 1 and 2 carry no MAC0 and skip this. A caller on those versions
	// is still challenged without proving anything, so this closes the hole
	// only for v3 traffic — and closes it outright once a deployment retires
	// the older versions.
	if mac0 != nil && !VerifyMAC0(version, c.mac0Key, p[:mac0End], mac0) {
		return outcomeDrop, 0
	}

	// Step 3: MAC2 check — if under load, require valid MAC2
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
			current, previous := c.cookieSecrets()
			cookie := CookieValue(current, addr.IP)
			if VerifyMAC2(cookie, dataBeforeMAC2, mac1, mac2) {
				mac2Valid = true
			} else {
				cookie = CookieValue(previous, addr.IP)
				if VerifyMAC2(cookie, dataBeforeMAC2, mac1, mac2) {
					mac2Valid = true
				}
			}
		}

		if mac2Valid {
			c.mac2Verified.Add(1)
		} else {
			return outcomeChallenge, 0
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

	if !VerifyMAC1(version, shared, p[:quicLen], edField, timestamp, nonce, mac1) {
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

	return outcomeAccepted, quicLen
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
