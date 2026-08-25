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

// Ed25519IdentityToX25519 is the strict form of Ed25519PublicToX25519, for an
// Ed25519 key a *peer* asserts as its identity (SIP-3).
//
// It additionally rejects small-order points. Every 32-byte string that
// decompresses is some curve point — including all zeros, which is the order-4
// point and maps to the Montgomery key u = 1 — so the map alone cannot tell an
// identity from a degenerate value. A genuine public key aB lies in the
// prime-order subgroup and is never small-order, so refusing torsion here costs
// an honest caller nothing and keeps this check sound on its own, rather than
// relying on the DH's non-contributory check having run first.
func Ed25519IdentityToX25519(edPub ed25519.PublicKey) ([]byte, error) {
	if len(edPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("squic: invalid Ed25519 public key size: %d", len(edPub))
	}

	p, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return nil, fmt.Errorf("squic: invalid Ed25519 public key: %w", err)
	}

	// Small order iff [8]P is the identity.
	var cofactored edwards25519.Point
	cofactored.MultByCofactor(p)
	if cofactored.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, fmt.Errorf("squic: small-order Ed25519 identity")
	}

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

// x25519Public derives the X25519 public key for a private key.
func x25519Public(priv []byte) []byte {
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return make([]byte, 32)
	}
	return pub
}
