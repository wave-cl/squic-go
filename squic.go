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

	// AllowedKeys is an optional whitelist of client X25519 public keys (32 bytes each).
	// When set on the server, only clients whose X25519 public keys appear in this
	// list can connect. Non-whitelisted clients are silently dropped (no response).
	// When nil, any client that knows the server's public key can connect.
	AllowedKeys [][]byte

	// QuicConfig allows passing additional quic-go configuration.
	// If nil, sensible defaults are used.
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

	return &quic.Config{
		MaxIdleTimeout:                 timeout,
		MaxIncomingStreams:             maxStreams,
		MaxIncomingUniStreams:          maxStreams,
		InitialStreamReceiveWindow:    1 << 20,  // 1MB
		InitialConnectionReceiveWindow: 10 << 20, // 10MB
	}
}

func (c *Config) allowedKeys() [][]byte {
	if c == nil {
		return nil
	}
	return c.AllowedKeys
}

// ServerListener wraps a quic.Listener with silent-server support.
type ServerListener struct {
	*quic.Listener
	conn net.PacketConn
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
	quicConf := config.quicConfig()

	// StatelessResetKey left nil — disables stateless reset for silent server
	tr := &quic.Transport{Conn: wrappedConn}
	ln, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("squic: quic listen: %w", err)
	}

	return &ServerListener{Listener: ln, conn: rawConn}, nil
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

	// Generate ephemeral X25519 key pair for this connection
	var clientPriv [32]byte
	if _, err := rand.Read(clientPriv[:]); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("squic: generate client key: %w", err)
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
	quicConf := config.quicConfig()

	tr := &quic.Transport{Conn: wrappedConn}
	conn, err := tr.Dial(ctx, udpAddr, tlsConf, quicConf)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("squic: dial: %w", err)
	}

	return conn, nil
}
