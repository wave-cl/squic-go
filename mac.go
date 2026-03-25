// Package squic provides a silent-server QUIC wrapper around quic-go.
package squic

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// MACSize is the size of the MAC1 tag in bytes.
	MACSize = 16

	// ClientKeySize is the size of an X25519 public key appended to Initial packets.
	ClientKeySize = 32

	// TimestampSize is the size of the replay-protection timestamp (uint32 epoch seconds).
	TimestampSize = 4

	// MAC2Size is the size of the MAC2 tag in bytes.
	MAC2Size = 16

	// MACOverhead is the total overhead appended to Initial packets:
	// 32-byte client X25519 public key + 4-byte timestamp + 16-byte MAC1 + 16-byte MAC2.
	MACOverhead = ClientKeySize + TimestampSize + MACSize + MAC2Size

	// CookieReplyType is the first byte of a cookie reply packet.
	// Distinguishes from QUIC packets (Initial starts with 0xC0+).
	CookieReplyType = 0x01

	// CookieNonceSize is the nonce size for XChaCha20-Poly1305.
	CookieNonceSize = 24

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

// ComputeMAC2 computes a MAC2 tag from a cookie and the packet+MAC1 data.
// MAC2 = HMAC-SHA256(cookie, packet || mac1)[:16]
func ComputeMAC2(cookie []byte, packet []byte, mac1 []byte) []byte {
	mac := hmac.New(sha256.New, cookie)
	mac.Write(packet)
	mac.Write(mac1)
	return mac.Sum(nil)[:MAC2Size]
}

// VerifyMAC2 checks a MAC2 tag.
func VerifyMAC2(cookie []byte, packet []byte, mac1 []byte, mac2 []byte) bool {
	expected := ComputeMAC2(cookie, packet, mac1)
	return subtle.ConstantTimeCompare(mac2, expected) == 1
}

// CookieValue computes a deterministic cookie for a given (secret, IP) pair.
// cookie = HMAC-SHA256(secret, ip)[:16]
// This is deterministic so the server can recompute it to verify MAC2.
func CookieValue(secret [32]byte, clientIP net.IP) []byte {
	ip := clientIP.To16()
	if ip == nil {
		ip = clientIP.To4()
	}
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(ip)
	return mac.Sum(nil)[:16]
}

// EncryptCookie encrypts a cookie value for sending to the client.
// Returns [nonce(24)] [ciphertext(cookie + 16 byte tag)].
func EncryptCookie(secret [32]byte, cookie []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(secret[:])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, CookieNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	encrypted := aead.Seal(nil, nonce, cookie, nil)
	result := make([]byte, CookieNonceSize+len(encrypted))
	copy(result, nonce)
	copy(result[CookieNonceSize:], encrypted)
	return result, nil
}

// DecryptCookie decrypts a cookie reply to recover the cookie value.
func DecryptCookie(secret [32]byte, data []byte) ([]byte, bool) {
	if len(data) < CookieNonceSize+16+16 { // nonce + tag + cookie
		return nil, false
	}

	aead, err := chacha20poly1305.NewX(secret[:])
	if err != nil {
		return nil, false
	}

	nonce := data[:CookieNonceSize]
	ciphertext := data[CookieNonceSize:]
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, false
	}

	return plain, true
}

// TimestampInWindow checks if a timestamp is within the replay window of now.
func TimestampInWindow(timestamp uint32, now uint32) bool {
	diff := int64(now) - int64(timestamp)
	window := int64(ReplayWindow / time.Second)
	return diff >= -window && diff <= window
}
