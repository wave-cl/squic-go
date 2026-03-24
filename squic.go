// Package squic provides Sovereign QUIC — a silent-server wrapper around quic-go.
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
		MaxIncomingStreams:              maxStreams,
		MaxIncomingUniStreams:           maxStreams,
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

func (c *Config) nextProtos() []string {
	if c != nil && len(c.NextProtos) > 0 {
		return c.NextProtos
	}
	return nil
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
	wrappedConn := newServerConn(rawConn, serverX25519Priv, config.allowedKeys())

	tlsConf := ServerTLSConfig(serverCert)
	if protos := config.nextProtos(); protos != nil {
		tlsConf.NextProtos = protos
	}
	quicConf := config.quicConfig()

	// StatelessResetKey left nil — disables stateless reset for silent server
	tr := &quic.Transport{Conn: wrappedConn}
	ln, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("squic: quic listen: %w", err)
	}

	return &ServerListener{Listener: ln, conn: rawConn, sc: wrappedConn}, nil
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

	// Derive or generate X25519 key pair for this connection
	var clientPriv [32]byte
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
		_ = pub // Ed25519 public key available if needed for TLS cert
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
	wrappedConn := newClientConn(rawConn, shared, clientPub)

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
