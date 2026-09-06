// Package squic provides Shielded QUIC — a silent-server wrapper around quic-go.
//
// sQUIC adds two features on top of standard QUIC:
//   - Silent server: the server is invisible to port scanners. Only clients
//     that possess the server's public key can elicit a response.
//   - No CA/PKI: identity is a pinned public key, not a certificate chain.
//   - Optional client key whitelisting with full silence for non-whitelisted clients.
//
// Usage:
//
//	// Server
//	ln, _ := squic.Listen("udp", ":4433", serverCert, serverPubKey, nil)
//	conn, _ := ln.Accept(ctx)
//
//	// Client
//	conn, _ := squic.Dial(ctx, "server:4433", serverPubKey, nil)
package squic

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
	"golang.org/x/crypto/curve25519"
)

// Config holds optional sQUIC configuration.
//
// # Parity with squic-rust
//
// The two implementations share a wire format, not a config surface, and the
// gaps below are not oversights — they are places where quic-go and quinn
// disagree about what is tunable. Recorded here because a caller who reads one
// API and assumes the other is wrong without being told.
//
// No Go equivalent, and none can be added: squic-rust has send_window,
// initial_rtt, congestion_controller and disable_active_migration. quic-go's
// Config has no field for any of them, so a mirrored field here could only be
// accepted and discarded — which is worse than its absence, because a setting
// that is read and never applied looks like it works.
//
// No Rust equivalent: QuicConfig, below, replaces everything else wholesale.
// quinn's TransportConfig is built inside squic-rust rather than accepted from
// the caller, so it has no such hatch.
//
// Same concept, same meaning, different defaults: StreamReceiveWindow and
// ReceiveWindow pair with squic-rust's stream_receive_window and
// receive_window. They did not always — these were MaxStreamReceiveWindow and
// MaxConnectionReceiveWindow and set only quic-go's auto-tuning ceiling, so one
// name meant a fixed window there and a cap here. Setting either now pins the
// window in both. What still differs is the value you get by leaving them
// unset: quinn does not auto-tune, so squic-rust is fixed at 1 MB and 10 MB,
// while quic-go starts there and tunes up to 6 MB and 15 MB.
type Config struct {
	// MaxIdleTimeout is the maximum time a connection can be idle.
	// Default: 30 seconds.
	MaxIdleTimeout time.Duration

	// MaxIncomingStreams is the maximum number of concurrent incoming streams.
	// Default: 100.
	MaxIncomingStreams int64

	// NextProtos overrides the TLS ALPN protocol list.
	// Default: ["squic"]. Set to ["h3"] for HTTP/3.
	NextProtos []string

	// AllowedKeys is an optional whitelist of client X25519 public keys (32 bytes each).
	// When set on the server, only clients whose X25519 public keys appear in this
	// list can connect. Non-whitelisted clients are silently dropped (no response).
	// When nil, any client that knows the server's public key can connect.
	AllowedKeys [][]byte

	// KeepAlive sends periodic keep-alive packets to prevent idle timeout.
	// Default: disabled (zero value).
	KeepAlive time.Duration

	// HandshakeTimeout is the maximum time for the TLS handshake to complete.
	// Default: 10 seconds.
	HandshakeTimeout time.Duration

	// StreamReceiveWindow is the per-stream flow control window, in bytes.
	// Zero means unset. Default when unset: 1 MB initially, auto-tuned by
	// quic-go up to 6 MB.
	//
	// Named and behaved to match squic-rust's stream_receive_window, which was
	// not true before: this was MaxStreamReceiveWindow and set only quic-go's
	// ceiling, so the same name meant a fixed window in one library and a cap
	// on auto-tuning in the other. Setting it now pins the window — quic-go's
	// initial and maximum are both set to this value — which is what quinn
	// does, because quinn does not auto-tune at all.
	//
	// To cap auto-tuning rather than pin the window, which quic-go can do and
	// quinn cannot, use QuicConfig. That asymmetry is the reason the escape
	// hatch exists.
	StreamReceiveWindow uint64

	// ReceiveWindow is the connection-level flow control window, in bytes.
	// Zero means unset. Default when unset: 10 MB initially, auto-tuned by
	// quic-go up to 15 MB.
	//
	// Matches squic-rust's receive_window, and pins the window for the reason
	// given on StreamReceiveWindow.
	ReceiveWindow uint64

	// InitialMTU sets the initial UDP payload size. Range: 1200-65000.
	// Default: 1200.
	InitialMTU uint16

	// DisableMTUDiscovery disables RFC 8899 path MTU discovery.
	// Default: false (discovery enabled).
	DisableMTUDiscovery bool

	// EnableDatagrams enables RFC 9221 QUIC datagram support.
	// Default: false.
	EnableDatagrams bool

	// ClientKey is an optional hex-encoded Ed25519 private key seed (64 hex chars).
	// When set, Dial() uses this persistent identity instead of generating an ephemeral one.
	// The client's X25519 public key is derived from this for MAC1 and whitelist matching.
	ClientKey string

	// AdvertiseIdentity, when set with ClientKey, carries this client's Ed25519
	// identity in the Initial envelope so the server can report it at accept via
	// PeerIdentity without pre-registering the caller (SIP-3). Ignored without
	// ClientKey. Default false — the caller stays anonymous on the wire, since
	// the identity is server-visible plaintext.
	AdvertiseIdentity bool

	// LoadThreshold is the DH operations per second before the server enters
	// under-load mode and starts requiring a cookie (MAC2) from callers it has
	// not challenged yet.
	//
	// Zero means unset and selects the default of 1000, because Go cannot tell
	// a field left out of a struct literal from one explicitly set to zero. To
	// turn the cookie defence off, pass a negative value. (squic-rust spells
	// the same two states Option::None and Some(0), which it can distinguish.)
	LoadThreshold int64

	// MaxConnections caps the number of concurrently-established connections.
	//
	// Each accepted connection can hold up to its receive window (see
	// ReceiveWindow, ~10 MB by default) of unread data, and the transport has
	// no other ceiling on how many may be open at once — so a caller that
	// completes handshakes and holds connections open can drive server memory
	// to N × the window. This bounds N: once that many connections are live,
	// further ones are refused before they establish.
	//
	// Zero (the default) means unlimited — the historical behaviour. A public,
	// whitelist-off deployment should set a finite value sized to its memory
	// budget (MaxConnections × ReceiveWindow). Ignored on dialed connections.
	// (squic-rust spells this Config.max_connections, Option<u64>.)
	MaxConnections int64

	// EnvelopeVersion is the envelope version this client emits (SIP-29).
	//
	// Zero means unset and selects EnvelopeV4, the only version implemented.
	// Zero is safe as a sentinel because SIP-29 reserves version 0 and forbids
	// emitting it, so it can never be a version somebody meant.
	//
	// Versions 1 to 3 were removed rather than deprecated. A version that has
	// to be narrowed *to* in order to be safe will be left wide somewhere, and
	// versions 1 and 2 carried no cheap gate at all, so a default admitting
	// them handed every stranger a curve operation. Dial refuses a version this
	// build cannot emit rather than letting it become a handshake timeout.
	//
	// Kept as a setting because the next transition will need it, not because
	// there is anything to choose today.
	EnvelopeVersion uint8

	// AcceptedEnvelopeVersions is the set of envelope versions this server
	// parses (SIP-29). Nil or empty selects EnvelopeV4, the only version
	// implemented.
	//
	// Listen refuses to bind on a set naming any version this build cannot
	// parse. That is not pedantry: such a server binds, reports itself healthy,
	// and then drops every Initial in silence, because SIP-6 requires silence
	// toward anything that fails validation. The operator sees a live process
	// and a dead port. ex ran [3] right up to the v4 cut.
	//
	// The mechanism survives for the next transition; what does not survive is
	// a default that admits a weaker version than the one the client sends.
	AcceptedEnvelopeVersions []uint8

	// LocalBind is the local address Dial binds, instead of an ephemeral port.
	//
	// Pairs with squic-rust's local_bind, which is a SocketAddr where this is a
	// string: each side takes what its own Dial and Listen already take, so a
	// caller passes what it would have passed anyway.
	//
	// **This exists for hole punching and for nothing else** (SIP-25). A NAT
	// maps an internal ip:port to an external one, and a peer can only be
	// reached through the mapping the exchange observed — which means dialling
	// *from* the port that made it. Dial otherwise binds :0 and gets a fresh
	// port, and therefore a fresh mapping the peer has never seen.
	//
	// Empty — the default, and what every ordinary caller wants — binds an
	// ephemeral port. Pinning one costs the ability to have two dials in flight
	// at once, and gains nothing unless something else is holding the mapping
	// open.
	//
	// Ignored by Listen, which already takes the address it binds.
	LocalBind string

	// Punch names addresses to send a punch datagram to, right after binding.
	//
	// A NAT will not deliver an inbound packet until something has gone out to
	// that peer, so both sides send first and each one's outbound opens its own
	// mapping. The datagram is one byte and is meant to be **dropped**: a
	// short-header packet for a connection nobody has, which every squic
	// endpoint discards in silence and never answers — a stateless reset here
	// would be a reply to a caller that has proved nothing.
	//
	// **This is a send primitive with a caller-supplied destination**, which is
	// the shape a reflection abuse takes, so it is bounded: at most
	// MaxPunchTargets addresses, PunchDatagrams one-byte datagrams each. It
	// amplifies nothing — one byte out per byte asked for — and the caller is
	// the local application, which could send these itself.
	//
	// SIP-25 requires that an address reach a peer only after *both* sides
	// asked an exchange to be introduced. Nothing here can enforce that; the
	// transport takes an address and sends to it.
	Punch []string

	// QuicConfig allows passing additional quic-go configuration.
	// If nil, sensible defaults are used. Overrides all other fields.
	QuicConfig *quic.Config
}

func (c *Config) quicConfig() *quic.Config {
	if c != nil && c.QuicConfig != nil {
		return c.QuicConfig.Clone()
	}

	timeout := 30 * time.Second
	maxStreams := int64(100)
	if c != nil {
		if c.MaxIdleTimeout > 0 {
			timeout = c.MaxIdleTimeout
		}
		if c.MaxIncomingStreams > 0 {
			maxStreams = c.MaxIncomingStreams
		}
	}

	qc := &quic.Config{
		MaxIdleTimeout:                 timeout,
		MaxIncomingStreams:             maxStreams,
		MaxIncomingUniStreams:          maxStreams,
		InitialStreamReceiveWindow:     1 << 20,  // 1MB
		InitialConnectionReceiveWindow: 10 << 20, // 10MB
	}

	if c != nil {
		if c.KeepAlive > 0 {
			qc.KeepAlivePeriod = c.KeepAlive
		}
		if c.HandshakeTimeout > 0 {
			qc.HandshakeIdleTimeout = c.HandshakeTimeout
		}
		// Initial and maximum together, so the window is pinned rather than
		// merely capped. quinn has no auto-tuning, so a caller who sets this
		// field in squic-rust gets a fixed window; setting only the ceiling
		// here would have given them a different thing under the same name.
		if c.StreamReceiveWindow > 0 {
			qc.InitialStreamReceiveWindow = c.StreamReceiveWindow
			qc.MaxStreamReceiveWindow = c.StreamReceiveWindow
		}
		if c.ReceiveWindow > 0 {
			qc.InitialConnectionReceiveWindow = c.ReceiveWindow
			qc.MaxConnectionReceiveWindow = c.ReceiveWindow
		}
		if c.InitialMTU > 0 {
			qc.InitialPacketSize = c.InitialMTU
		}
		if c.DisableMTUDiscovery {
			qc.DisablePathMTUDiscovery = true
		}
		if c.EnableDatagrams {
			qc.EnableDatagrams = true
		}
	}

	return qc
}

func (c *Config) allowedKeys() [][]byte {
	if c == nil {
		return nil
	}
	return c.AllowedKeys
}

func (c *Config) loadThreshold() int64 {
	if c == nil || c.LoadThreshold == 0 {
		return 1000 // unset
	}
	if c.LoadThreshold < 0 {
		return 0 // caller is disabling the cookie defence
	}
	return c.LoadThreshold
}

// maxConnections resolves the concurrent-connection cap; 0 means unlimited.
func (c *Config) maxConnections() int64 {
	if c == nil || c.MaxConnections < 0 {
		return 0
	}
	return c.MaxConnections
}

// errAtCapacity is returned from ConnContext to refuse a connection once the
// server is at its MaxConnections cap.
var errAtCapacity = errors.New("squic: server at connection capacity")

func (c *Config) envelopeVersion() uint8 {
	if c == nil || c.EnvelopeVersion == 0 {
		return EnvelopeV4 // unset; the only version implemented
	}
	return c.EnvelopeVersion
}

func (c *Config) acceptedEnvelopeVersions() []uint8 {
	if c == nil || len(c.AcceptedEnvelopeVersions) == 0 {
		return []uint8{EnvelopeV4}
	}
	return c.AcceptedEnvelopeVersions
}

func (c *Config) nextProtos() []string {
	if c != nil && len(c.NextProtos) > 0 {
		return c.NextProtos
	}
	return nil
}

// peerKeyCtxKey keys the per-connection peer-key holder carried in the
// connection's context. Unexported so no other package can collide with it.
type peerKeyCtxKey struct{}

// peerKeyHolder carries the MAC1-verified peer key from the point where the
// connection is created (where quic-go hands us its original destination CID
// via the Tracer hook) to the point where the application asks for it. It is
// installed by ConnContext and filled by the Tracer; both run before Accept
// returns the connection.
type peerKeyHolder struct {
	key [32]byte
	set bool
	// identity is the MAC1-bound Ed25519 identity (SIP-3), valid when
	// hasIdentity is set. Filled by the same one take() the Tracer performs.
	identity    [32]byte
	hasIdentity bool
}

// ServerListener wraps a quic.Listener with silent-server support.
type ServerListener struct {
	*quic.Listener
	conn      net.PacketConn
	sc        *serverConn
	publicKey []byte
}

// Listen creates a sQUIC listener on the given address.
// serverCert is the TLS certificate (from GenerateKeyPair or LoadKeyPair).
// serverPubKey is the raw Ed25519 public key bytes (distributed to clients out-of-band).
func Listen(network, addr string, serverCert tls.Certificate, serverPubKey []byte, config *Config) (*ServerListener, error) {
	// The mirror of the guard in Dial, and the one that costs more to be
	// without. A server told to accept a version this build cannot parse does
	// not fail: it binds, it reports itself healthy, and it drops every Initial
	// that arrives in silence, because SIP-6 requires exactly that of anything
	// it cannot validate. The operator sees a live process and a dead port with
	// nothing anywhere saying why.
	//
	// This is not hypothetical. ex ran accepted_envelope_versions = [3] right
	// up to the v4 cut, and installing the binary without editing that line in
	// the same breath would have taken the exchange down without one error.
	//
	// Every named version must be parsable, not merely one of them. A set like
	// [3, 4] on a v4-only build is the quieter half of the same fault: v4
	// callers connect, v3 callers are dropped without a word, and the operator
	// believes both are served.
	//
	// Nothing checks for an empty set here, unlike squic-rust:
	// acceptedEnvelopeVersions resolves nil or empty to the default, so an
	// empty set cannot reach the server. Rust's Config carries the list
	// directly and needs its own check.
	var unparsable []uint8
	for _, v := range config.acceptedEnvelopeVersions() {
		if _, ok := TrailerLen(Hdr(v, false)); !ok {
			unparsable = append(unparsable, v)
		}
	}
	if len(unparsable) > 0 {
		return nil, fmt.Errorf(
			"squic: AcceptedEnvelopeVersions names %v, which this build cannot parse "+
				"(it implements %d); a server accepting only versions it cannot parse "+
				"binds successfully and then drops every Initial in silence",
			unparsable, EnvelopeV4)
	}

	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("squic: resolve addr: %w", err)
	}

	rawConn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("squic: listen: %w", err)
	}
	// SIP-25: a listening peer punches too. Whichever side dials, both NATs
	// have to be opened, and only an outbound packet opens one.
	punch(rawConn, config)

	// Convert server Ed25519 private key to X25519 for DH-based MAC1
	edPriv, ok := serverCert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		rawConn.Close()
		return nil, fmt.Errorf("squic: server certificate must use Ed25519 key")
	}
	serverX25519Priv := Ed25519PrivateToX25519(edPriv)

	// Wrap with DH MAC1 validation — silent server
	wrappedConn := newServerConn(rawConn, serverX25519Priv, config.allowedKeys(), config.loadThreshold(), config.acceptedEnvelopeVersions())

	tlsConf := ServerTLSConfig(serverCert)
	if protos := config.nextProtos(); protos != nil {
		tlsConf.NextProtos = protos
	}
	quicConf := config.quicConfig()

	// Bridge the MAC1-verified peer key from the UDP receive path to the
	// accepted connection (SIP-2). quic-go does not expose the original
	// destination CID on an accepted connection, but it does hand it to the
	// qlog Tracer, whose context is the one ConnContext returned and the one
	// Conn.Context() later reports. So ConnContext installs an empty holder,
	// the Tracer looks the CID up in the peer table and fills it, and PeerKey
	// reads it back. No wire change; this only surfaces information already
	// verified.
	// Cap NEW unvalidated connection creations per second. quic-go allocates and
	// holds a connection for the handshake timeout on the first Initial of a fresh
	// DCID; every Initial that clears the envelope MAC1 reaches quic-go, and any
	// holder of the PUBLISHED server key can forge a valid MAC1 for its own key
	// with a fresh DCID, so a flood would grow RSS without bound (measured ~2.8 GB,
	// non-recovering) whenever the whitelist is off. Beyond the budget, quic-go
	// issues a stateless Retry and allocates nothing until the caller returns the
	// token: a flood never answers, so it creates no state, while honest clients
	// sit under the budget and never see a Retry. Gating on the load flag does not
	// work — the 1s monitor oscillates and lets bursts through its "not under load"
	// windows. This is quic-go's documented use of VerifySourceAddress.
	const newConnBudgetPerSec = 100
	var vsaMu sync.Mutex
	var vsaWindow int64
	var vsaCount int
	// Cap on concurrently-established connections (0 = unlimited). Counted in
	// ConnContext, which quic-go calls once per accepted connection and whose
	// context it cancels on close — so the Done watcher is the decrement, and
	// returning an error refuses the connection before it allocates.
	maxConns := config.maxConnections()
	var liveConns atomic.Int64
	tr := &quic.Transport{
		Conn: wrappedConn,
		// Belt and braces with the version gate in validateAndStrip. A Version
		// Negotiation packet is a reply to a caller that has proved nothing,
		// which is exactly what a silent server must not send; the gate stops
		// those packets reaching quic-go, and this stops quic-go answering if
		// one ever does.
		DisableVersionNegotiationPackets: true,
		VerifySourceAddress: func(net.Addr) bool {
			now := time.Now().Unix()
			vsaMu.Lock()
			if now != vsaWindow {
				vsaWindow = now
				vsaCount = 0
			}
			vsaCount++
			over := vsaCount > newConnBudgetPerSec
			vsaMu.Unlock()
			return over
		},
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			if maxConns > 0 {
				if liveConns.Add(1) > maxConns {
					liveConns.Add(-1)
					return ctx, errAtCapacity // refused before it establishes
				}
				// ctx is cancelled when this connection closes (or its
				// handshake fails), so this is the matching decrement.
				go func() {
					<-ctx.Done()
					liveConns.Add(-1)
				}()
			}
			return context.WithValue(ctx, peerKeyCtxKey{}, &peerKeyHolder{}), nil
		},
	}

	prevTracer := quicConf.Tracer
	quicConf.Tracer = func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
		if !isClient {
			if h, ok := ctx.Value(peerKeyCtxKey{}).(*peerKeyHolder); ok {
				if key, identity, hasIdentity, found := wrappedConn.peers.take(connID.Bytes(), time.Now()); found {
					h.key = key
					h.set = true
					h.identity = identity
					h.hasIdentity = hasIdentity
				}
			}
		}
		if prevTracer != nil {
			return prevTracer(ctx, isClient, connID)
		}
		return nil
	}

	// StatelessResetKey left nil — disables stateless reset for silent server
	ln, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("squic: quic listen: %w", err)
	}

	return &ServerListener{
		Listener:  ln,
		conn:      rawConn,
		sc:        wrappedConn,
		publicKey: append([]byte(nil), serverPubKey...),
	}, nil
}

// PublicKey returns this server's Ed25519 public key — the one clients pin when
// they dial, and the one passed to Listen.
//
// Without it a caller has to carry the key alongside the listener, which is the
// arrangement squic-rust added ServerListener::public_key to end; this is the
// Go half of that. The slice is a fresh copy, so a caller cannot reach back
// through it and change what the listener reports.
//
// Note this is the *server's own* key, not the caller's. sQUIC verifies the
// peer's X25519 key while validating the Initial (see PeerKey), and it could
// not be reported as Ed25519 in any case — the map from Ed25519 to X25519 does
// not run backwards.
func (l *ServerListener) PublicKey() []byte {
	return append([]byte(nil), l.publicKey...)
}

// PeerKey returns the peer's X25519 public key for an accepted connection, as
// verified by MAC1 on its Initial packet, and true — or a zero key and false
// if none was recorded (the connection did not pass MAC1, the DCID was
// contested by two different keys, or the entry expired before accept).
//
// Pass a connection returned by Accept. This is the transport key; it is not
// the caller's Ed25519 identity and cannot be converted to one — the
// Ed25519 -> X25519 map does not run backwards. A caller authorising by
// Ed25519 key holds the forward mapping and matches against it. See SIP-2.
func (sl *ServerListener) PeerKey(conn *quic.Conn) ([32]byte, bool) {
	h, ok := conn.Context().Value(peerKeyCtxKey{}).(*peerKeyHolder)
	if !ok || !h.set {
		return [32]byte{}, false
	}
	return h.key, true
}

// PeerIdentity returns the peer's MAC1-bound Ed25519 identity for an accepted
// connection (SIP-3), and true — or a zero key and false if the caller
// advertised none (the common, anonymous case), the DCID was contested, or the
// entry expired before accept.
//
// When present, the transport proved possession of the matching scalar and the
// server checked that this Ed25519 key forward-derives to the verified X25519
// key, so an open-set service may name and authorise the caller by it without
// having pre-registered it. Pass a connection returned by Accept.
func (sl *ServerListener) PeerIdentity(conn *quic.Conn) ([32]byte, bool) {
	h, ok := conn.Context().Value(peerKeyCtxKey{}).(*peerKeyHolder)
	if !ok || !h.set || !h.hasIdentity {
		return [32]byte{}, false
	}
	return h.identity, true
}

// AllowKey adds a client X25519 public key to the whitelist at runtime.
// If whitelisting is not enabled, this implicitly enables it.
// The key must be exactly 32 bytes.
func (sl *ServerListener) AllowKey(pubKey []byte) error {
	if len(pubKey) != 32 {
		return fmt.Errorf("squic: key must be 32 bytes, got %d", len(pubKey))
	}
	var key [32]byte
	copy(key[:], pubKey)
	sl.sc.addKey(key)
	return nil
}

// RemoveKey removes a client X25519 public key from the whitelist at runtime.
// The key must be exactly 32 bytes.
func (sl *ServerListener) RemoveKey(pubKey []byte) error {
	if len(pubKey) != 32 {
		return fmt.Errorf("squic: key must be 32 bytes, got %d", len(pubKey))
	}
	var key [32]byte
	copy(key[:], pubKey)
	sl.sc.removeKey(key)
	return nil
}

// HasKey checks if a client X25519 public key is in the whitelist.
func (sl *ServerListener) HasKey(pubKey []byte) bool {
	if len(pubKey) != 32 {
		return false
	}
	var key [32]byte
	copy(key[:], pubKey)
	return sl.sc.hasKey(key)
}

// AllowedKeys returns a copy of all whitelisted client X25519 public keys.
// Returns nil if whitelisting is not enabled.
func (sl *ServerListener) AllowedKeys() [][]byte {
	keys := sl.sc.allKeys()
	if keys == nil {
		return nil
	}
	result := make([][]byte, len(keys))
	for i, k := range keys {
		result[i] = k[:]
	}
	return result
}

// LoadStats is a snapshot of the server's cookie-based DDoS defence.
//
// Worth watching: UnderLoad means the server has stopped doing Diffie-Hellman
// for callers that have not echoed back a cookie, which costs every new client
// an extra round trip.
type LoadStats struct {
	// UnderLoad reports whether the server is currently demanding a valid MAC2.
	UnderLoad bool
	// CookieRepliesSent counts challenges issued since start.
	CookieRepliesSent int64
	// MAC2Verified counts Initial packets admitted on a valid MAC2.
	MAC2Verified int64
	// AcceptedByVersion counts Initials admitted, keyed by envelope version.
	//
	// The number to look at before retiring a version (SIP-29). A server that
	// drops an envelope does so in silence, so retiring one that clients are
	// still sending locks them out with no diagnostic on either side — this is
	// the evidence that turns that decision from nerve into arithmetic.
	//
	// Counts accepted Initials, not connections: a handshake retransmits, so
	// treat these as "is anything still arriving on this version", not as a
	// connection count.
	AcceptedByVersion map[uint8]int64
}

// LoadStats returns a snapshot of the cookie defence's state.
func (sl *ServerListener) LoadStats() LoadStats {
	return sl.sc.loadStats()
}

// SetUnderLoad forces the under-load state. Exposed for tests, which would
// otherwise have to win a race with the one-second load monitor.
func (sl *ServerListener) SetUnderLoad(value bool) {
	sl.sc.underLoad.Store(value)
}

// EnableWhitelist activates the client key whitelist, optionally pre-populated with keys.
// Once enabled, only clients whose X25519 public keys are in the whitelist can connect.
// If no keys are provided, the whitelist starts empty (blocks all new connections).
func (sl *ServerListener) EnableWhitelist(keys ...[]byte) {
	var fixed [][32]byte
	for _, k := range keys {
		if len(k) == 32 {
			var key [32]byte
			copy(key[:], k)
			fixed = append(fixed, key)
		}
	}
	sl.sc.enableWhitelist(fixed)
}

// DisableWhitelist removes the whitelist entirely.
// Any client with a valid MAC1 (knowing the server's public key) can connect.
func (sl *ServerListener) DisableWhitelist() {
	sl.sc.disableWhitelist()
}

// Close closes the listener and the underlying connection.
func (l *ServerListener) Close() error {
	err := l.Listener.Close()
	l.conn.Close()
	return err
}

// Dial connects to a sQUIC server at the given address.
// MaxPunchTargets is how many addresses one Config.Punch may name.
const MaxPunchTargets = 4

// PunchDatagrams is how many datagrams are sent to each punch target.
//
// More than one because the first may cross the peer's on the way and find its
// NAT still shut; few, because this is unsolicited traffic to an address a
// caller named.
const PunchDatagrams = 3

// punch opens the NAT mapping for each peer, so its packets are not dropped on
// the way in.
//
// One byte, 0x00: a short-header packet for a connection nobody has, which
// every squic endpoint discards in silence — and never answers, because a
// stateless reset would be a reply to a caller that has proved nothing.
//
// Errors are ignored on purpose. A punch that does not leave is a punch that
// did not work, and there is nothing to report to a caller who will find that
// out when the connection does not form.
func punch(conn *net.UDPConn, config *Config) {
	if config == nil || len(config.Punch) == 0 {
		return
	}
	targets := config.Punch
	if len(targets) > MaxPunchTargets {
		targets = targets[:MaxPunchTargets]
	}
	for _, target := range targets {
		addr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			continue
		}
		for i := 0; i < PunchDatagrams; i++ {
			_, _ = conn.WriteToUDP([]byte{0x00}, addr)
		}
	}
}

// serverPubKey is the server's raw Ed25519 public key (known out-of-band).
// The client generates an ephemeral X25519 key pair for DH-based MAC1.
func Dial(ctx context.Context, addr string, serverPubKey []byte, config *Config) (*quic.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("squic: resolve addr: %w", err)
	}

	// Bind what the caller asked for, or an ephemeral port. A caller pinning a
	// local address (SIP-25) is taken at its word; mismatching the peer's family
	// is then its own error and is reported as the dial's.
	bind := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	if config != nil && config.LocalBind != "" {
		bind, err = net.ResolveUDPAddr("udp", config.LocalBind)
		if err != nil {
			return nil, fmt.Errorf("squic: resolve LocalBind: %w", err)
		}
	}
	rawConn, err := net.ListenUDP("udp", bind)
	if err != nil {
		return nil, fmt.Errorf("squic: listen: %w", err)
	}
	// Before quic-go owns the socket: the mapping has to exist before the
	// handshake starts, and this is the only moment the raw socket is in hand.
	punch(rawConn, config)

	// Reject an envelope version nobody defines, here, where the caller can
	// see it. Left to run it produces an envelope every server drops, so the
	// symptom is a handshake timeout with no hint of the cause — and before
	// buildInitial was hardened it was an out-of-range panic on the first
	// Initial.
	if _, ok := TrailerLen(Hdr(config.envelopeVersion(), false)); !ok {
		rawConn.Close()
		return nil, fmt.Errorf("squic: unknown EnvelopeVersion %d (defined: %d)",
			config.envelopeVersion(), EnvelopeV4)
	}

	// Convert server Ed25519 pubkey to X25519 for DH
	serverX25519Pub, err := Ed25519PublicToX25519(serverPubKey)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("squic: convert server key: %w", err)
	}

	// Derive or generate X25519 key pair for this connection, and the Ed25519
	// identity (if any) it came from — the latter may be advertised (SIP-3).
	var clientPriv [32]byte
	var advertiseEd25519 []byte
	if config != nil && config.ClientKey != "" {
		// Persistent client identity: derive X25519 from Ed25519 seed
		ed25519Pub, err := hex.DecodeString(config.ClientKey)
		if err != nil || len(ed25519Pub) != ed25519.SeedSize {
			rawConn.Close()
			return nil, fmt.Errorf("squic: invalid ClientKey (expected %d hex chars)", ed25519.SeedSize*2)
		}
		priv := ed25519.NewKeyFromSeed(ed25519Pub)
		pub := priv.Public().(ed25519.PublicKey)
		x25519Priv := Ed25519PrivateToX25519(priv)
		copy(clientPriv[:], x25519Priv)
		if config.AdvertiseIdentity {
			advertiseEd25519 = pub // SIP-3: assert this identity in the envelope
		}
	} else {
		// Ephemeral: random X25519 key pair
		if _, err := rand.Read(clientPriv[:]); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("squic: generate client key: %w", err)
		}
	}
	clientPub, err := curve25519.X25519(clientPriv[:], curve25519.Basepoint)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("squic: derive client pubkey: %w", err)
	}

	// Compute DH shared secret
	shared, err := X25519(clientPriv[:], serverX25519Pub)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("squic: DH key exchange: %w", err)
	}

	// Wrap with DH MAC1 appending
	wrappedConn := newClientConn(rawConn, shared, clientPub, advertiseEd25519, udpAddr,
		GateKey(serverX25519Pub), CookieKey(serverX25519Pub), config.envelopeVersion())

	tlsConf := ClientTLSConfig(serverPubKey)
	if protos := config.nextProtos(); protos != nil {
		tlsConf.NextProtos = protos
	}
	quicConf := config.quicConfig()

	tr := &quic.Transport{Conn: wrappedConn}
	conn, err := tr.Dial(ctx, udpAddr, tlsConf, quicConf)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("squic: dial: %w", err)
	}

	return conn, nil
}
