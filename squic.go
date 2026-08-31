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
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
	"golang.org/x/crypto/curve25519"
)

// Config holds optional sQUIC configuration.
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

	// MaxStreamReceiveWindow is the maximum per-stream flow control window.
	// Default: 6 MB.
	MaxStreamReceiveWindow uint64

	// MaxConnectionReceiveWindow is the maximum connection-level flow control window.
	// Default: 15 MB.
	MaxConnectionReceiveWindow uint64

	// InitialMTU sets the initial UDP payload size. Range: 1200-65000.
	// Default: 1200.
	InitialMTU uint16

	// DisableMTUDiscovery disables RFC 8899 path MTU discovery.
	// Default: false (discovery enabled).
	DisableMTUDiscovery bool

	// EnableDatagrams enables RFC 9221 QUIC datagram support.
	// Default: false.
	EnableDatagrams bool

	// Enable0RTT allows 0-RTT resumption. Has replay attack implications.
	// Default: false.
	Enable0RTT bool

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

	// EnvelopeVersion is the envelope version this client emits (SIP-29).
	//
	// Zero means unset and selects EnvelopeV2 as of v0.63.0. It selected
	// EnvelopeV1 in v0.62.0, which is the discipline SIP-29 requires — a
	// release that introduces a version ships clients still sending the
	// previous one, so that upgrading a client before a server cannot break
	// anything, and a later release moves the default once servers have had
	// time to deploy. This is that later release.
	//
	// Set it to EnvelopeV1 if you still talk to a server older than squic-go
	// v0.62.0, which will drop a version 2 Initial in silence.
	//
	// Zero is safe as a sentinel here because SIP-29 reserves version 0 and
	// forbids emitting it, so it can never be a version somebody meant.
	EnvelopeVersion uint8

	// AcceptedEnvelopeVersions is the set of envelope versions this server
	// parses (SIP-29). Nil selects all of them, so a server can be upgraded
	// without waiting for its clients. Drop older versions to retire them —
	// which a deployment must be able to do, or the oldest envelope ever
	// defined becomes a permanent floor.
	//
	// Retiring v1 and v2 is what finishes the job v3 starts. Only v3 carries
	// MAC0, so only a v3 caller can be turned away before the cookie stage; a
	// server still accepting v1 or v2 will keep answering callers on those
	// versions with a cookie while it is under load, whatever they know. Set
	// this to []uint8{EnvelopeV3} once the clients have moved.
	AcceptedEnvelopeVersions []uint8

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
		if c.MaxStreamReceiveWindow > 0 {
			qc.MaxStreamReceiveWindow = c.MaxStreamReceiveWindow
		}
		if c.MaxConnectionReceiveWindow > 0 {
			qc.MaxConnectionReceiveWindow = c.MaxConnectionReceiveWindow
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
		if c.Enable0RTT {
			qc.Allow0RTT = true
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

func (c *Config) envelopeVersion() uint8 {
	if c == nil || c.EnvelopeVersion == 0 {
		return EnvelopeV2 // unset; see the field comment for the history
	}
	return c.EnvelopeVersion
}

func (c *Config) acceptedEnvelopeVersions() []uint8 {
	if c == nil || len(c.AcceptedEnvelopeVersions) == 0 {
		return []uint8{EnvelopeV1, EnvelopeV2, EnvelopeV3}
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
	conn net.PacketConn
	sc   *serverConn
}

// Listen creates a sQUIC listener on the given address.
// serverCert is the TLS certificate (from GenerateKeyPair or LoadKeyPair).
// serverPubKey is the raw Ed25519 public key bytes (distributed to clients out-of-band).
func Listen(network, addr string, serverCert tls.Certificate, serverPubKey []byte, config *Config) (*ServerListener, error) {
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("squic: resolve addr: %w", err)
	}

	rawConn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("squic: listen: %w", err)
	}

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
	tr := &quic.Transport{
		Conn: wrappedConn,
		// Belt and braces with the version gate in validateAndStrip. A Version
		// Negotiation packet is a reply to a caller that has proved nothing,
		// which is exactly what a silent server must not send; the gate stops
		// those packets reaching quic-go, and this stops quic-go answering if
		// one ever does.
		DisableVersionNegotiationPackets: true,
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
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

	return &ServerListener{Listener: ln, conn: rawConn, sc: wrappedConn}, nil
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
// serverPubKey is the server's raw Ed25519 public key (known out-of-band).
// The client generates an ephemeral X25519 key pair for DH-based MAC1.
func Dial(ctx context.Context, addr string, serverPubKey []byte, config *Config) (*quic.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("squic: resolve addr: %w", err)
	}

	rawConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("squic: listen: %w", err)
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
		MAC0Key(serverX25519Pub), CookieKey(serverX25519Pub), config.envelopeVersion())

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
