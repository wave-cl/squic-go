package squic

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"filippo.io/edwards25519"
)

// Ed25519PublicToX25519 converts an Ed25519 public key to an X25519 public key.
// This performs the birational map from the Ed25519 Edwards curve to the
// X25519 Montgomery curve (RFC 7748).
func Ed25519PublicToX25519(edPub ed25519.PublicKey) ([]byte, error) {
	if len(edPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("squic: invalid Ed25519 public key size: %d", len(edPub))
	}

	// Decompress the Edwards point
	p, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return nil, fmt.Errorf("squic: invalid Ed25519 public key: %w", err)
	}

	// Convert to Montgomery u-coordinate
	return p.BytesMontgomery(), nil
}

// Ed25519PrivateToX25519 converts an Ed25519 private key to an X25519 private key.
// Uses the standard conversion: SHA-512 hash of the seed, clamped.
func Ed25519PrivateToX25519(edPriv ed25519.PrivateKey) []byte {
	h := sha512.Sum512(edPriv.Seed())

	// Clamp per RFC 7748
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	return h[:32]
}

// X25519 performs a Diffie-Hellman key exchange.
// Returns the 32-byte shared secret.
func X25519(scalar, point []byte) ([]byte, error) {
	return curve25519.X25519(scalar, point)
}
