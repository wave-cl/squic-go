// Package squic provides a silent-server QUIC wrapper around quic-go.
package squic

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

const (
	// MACSize is the size of the MAC1 tag in bytes.
	MACSize = 16

	// ClientKeySize is the size of an X25519 public key appended to Initial packets.
	ClientKeySize = 32

	// MACOverhead is the total overhead appended to Initial packets:
	// 32-byte client X25519 public key + 16-byte MAC1.
	MACOverhead = ClientKeySize + MACSize
)

// ComputeMAC1 computes a MAC1 tag using a DH shared secret.
// MAC1 = HMAC-SHA256(sharedSecret, data)[:16]
func ComputeMAC1(sharedSecret []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(data)
	return mac.Sum(nil)[:MACSize]
}

// VerifyMAC1 checks a MAC1 tag against data using a DH shared secret.
func VerifyMAC1(sharedSecret []byte, data []byte, mac1 []byte) bool {
	expected := ComputeMAC1(sharedSecret, data)
	return subtle.ConstantTimeCompare(mac1, expected) == 1
}
