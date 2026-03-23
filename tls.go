package squic

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// KeySize is the size of an Ed25519 public key in bytes (32 bytes = 64 hex chars).
const KeySize = ed25519.PublicKeySize

// GenerateKeyPair generates a new Ed25519 key pair for use with sQUIC.
// Returns the TLS certificate and the 32-byte raw public key (for distribution).
func GenerateKeyPair() (tls.Certificate, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generate key: %w", err)
	}

	cert, err := selfSignedCert(priv, pub)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("self-signed cert: %w", err)
	}

	// Return the raw 32-byte Ed25519 public key (not PKIX-wrapped)
	return cert, []byte(pub), nil
}

// LoadKeyPair reconstructs a TLS certificate and public key from a hex-encoded
// Ed25519 private key seed (64 hex characters = 32 bytes).
// Use this to persist server identity across restarts.
func LoadKeyPair(privateKeyHex string) (tls.Certificate, []byte, error) {
	seed, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("decode hex key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return tls.Certificate{}, nil, fmt.Errorf("key must be %d bytes (got %d)", ed25519.SeedSize, len(seed))
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	cert, err := selfSignedCert(priv, pub)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("self-signed cert: %w", err)
	}

	return cert, []byte(pub), nil
}

// selfSignedCert creates a self-signed TLS certificate from an Ed25519 key.
func selfSignedCert(priv ed25519.PrivateKey, pub ed25519.PublicKey) (tls.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "squic"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ServerTLSConfig creates a TLS config for the server using the given certificate.
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"squic"},
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLSConfig creates a TLS config for the client that pins the server's
// raw 32-byte Ed25519 public key.
func ClientTLSConfig(serverPubKey []byte) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("squic: server presented no certificate")
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("squic: parse server cert: %w", err)
			}

			edKey, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("squic: server key is not Ed25519")
			}

			if subtle.ConstantTimeCompare([]byte(edKey), serverPubKey) != 1 {
				return fmt.Errorf("squic: server public key mismatch")
			}

			return nil
		},
		NextProtos: []string{"squic"},
		MinVersion: tls.VersionTLS13,
	}
}
