// Package squic provides a silent-server QUIC wrapper around quic-go.
package squic

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"time"
)

const (
	// MACSize is the size of the MAC1 tag in bytes.
	MACSize = 16

	// ClientKeySize is the size of an X25519 public key appended to Initial packets.
	ClientKeySize = 32

	// TimestampSize is the size of the replay-protection timestamp (uint32 epoch seconds).
	TimestampSize = 4

	// MACOverhead is the total overhead appended to Initial packets:
	// 32-byte client X25519 public key + 4-byte timestamp + 16-byte MAC1.
	MACOverhead = ClientKeySize + TimestampSize + MACSize

	// ReplayWindow is the maximum age of a timestamp before the server rejects it.
	// Also allows timestamps slightly in the future to account for clock skew.
	ReplayWindow = 120 * time.Second
)

// ComputeMAC1 computes a MAC1 tag with a timestamp for replay protection.
// MAC1 = HMAC-SHA256(sharedSecret, data || timestamp)[:16]
func ComputeMAC1(sharedSecret []byte, data []byte, timestamp uint32) []byte {
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(data)
	var ts [4]byte
	binary.BigEndian.PutUint32(ts[:], timestamp)
	mac.Write(ts[:])
	return mac.Sum(nil)[:MACSize]
}

// VerifyMAC1 checks a MAC1 tag against data, timestamp, and shared secret.
func VerifyMAC1(sharedSecret []byte, data []byte, timestamp uint32, mac1 []byte) bool {
	expected := ComputeMAC1(sharedSecret, data, timestamp)
	return subtle.ConstantTimeCompare(mac1, expected) == 1
}

// NowTimestamp returns the current time as a uint32 epoch seconds value.
func NowTimestamp() uint32 {
	return uint32(time.Now().Unix())
}

// TimestampInWindow checks if a timestamp is within the replay window of now.
func TimestampInWindow(timestamp uint32, now uint32) bool {
	diff := int64(now) - int64(timestamp)
	window := int64(ReplayWindow / time.Second)
	return diff >= -window && diff <= window
}
