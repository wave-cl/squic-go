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

	// Ed25519Size is the size of the carried Ed25519 identity field (SIP-3).
	// All-zero means "no identity asserted".
	Ed25519Size = 32

	// TimestampSize is the size of the replay-protection timestamp (uint32 epoch seconds).
	TimestampSize = 4

	// NonceSize is the size of the random nonce in bytes.
	NonceSize = 8

	// MAC2Size is the size of the MAC2 tag in bytes.
	MAC2Size = 16

	// MACOverhead is the total overhead appended to Initial packets by envelope
	// version 1 (SIP-6): 32-byte client X25519 public key + 32-byte Ed25519
	// identity + 4-byte timestamp + 8-byte nonce + 16-byte MAC1 + 16-byte MAC2.
	MACOverhead = ClientKeySize + Ed25519Size + TimestampSize + NonceSize + MACSize + MAC2Size

	// EnvelopeV1 is the envelope of SIP-6: no marker byte on the wire. It is
	// named so that a receiver supporting both has something to call the
	// unmarked form.
	EnvelopeV1 = 1

	// EnvelopeV2 is EnvelopeV1 plus a one-byte version marker, last (SIP-29).
	EnvelopeV2 = 2

	// EnvelopeV3 is EnvelopeV2 plus MAC0, a cheap outer MAC keyed on the
	// server's public key and verified before any curve operation.
	//
	// MAC1 is a Diffie-Hellman, so a server cannot tell a caller who knows its
	// public key from a stranger without paying for one — which is why the
	// cookie defence has to challenge before it knows who it is talking to, and
	// why a server under load answers everybody. WireGuard does not have this
	// problem: its MAC1 is keyed on a *hash* of the responder's static public
	// key and costs a hash to check, so it only ever cookies callers that have
	// already proved they know the key. MAC0 is that construction, added
	// alongside sQUIC's MAC1 rather than replacing it.
	EnvelopeV3 = 3

	// MAC0Size is the size of the MAC0 tag in bytes.
	MAC0Size = 16

	// VersionSize is the width of the version marker.
	VersionSize = 1

	// MACOverheadV2 is the trailer width for envelope version 2.
	MACOverheadV2 = MACOverhead + VersionSize

	// MACOverheadV3 is the trailer width for envelope version 3: version 2 plus
	// the MAC0 field.
	MACOverheadV3 = MACOverheadV2 + MAC0Size

	// CookieReplyType is the first byte of a cookie reply packet.
	// Distinguishes from QUIC packets (Initial starts with 0xC0+).
	CookieReplyType = 0x01

	// CookieNonceSize is the nonce size for XChaCha20-Poly1305.
	CookieNonceSize = 24

	// ReplayWindow is the maximum age of a timestamp before the server rejects it.
	// Also allows timestamps slightly in the future to account for clock skew.
	ReplayWindow = 120 * time.Second
)

// TrailerLen returns the trailer width for an envelope version, and false if
// the version is unknown.
//
// SIP-29: version 0 is reserved and never emitted, so a zero byte is known not
// to be a marker.
func TrailerLen(version uint8) (int, bool) {
	switch version {
	case EnvelopeV1:
		return MACOverhead, true
	case EnvelopeV2:
		return MACOverheadV2, true
	case EnvelopeV3:
		return MACOverheadV3, true
	default:
		return 0, false
	}
}

// EnvelopeVersions is every envelope version this build knows, lowest first.
//
// The one list to extend when a version is added — TrailerLen and the
// per-version accept counters are both keyed off it, and
// TestEveryKnownVersionHasATrailer fails if the two drift apart.
var EnvelopeVersions = []uint8{EnvelopeV1, EnvelopeV2, EnvelopeV3}

// VersionIndex returns the position of version in EnvelopeVersions, for
// indexing per-version state, and false for a version this build does not know.
func VersionIndex(version uint8) (int, bool) {
	for i, v := range EnvelopeVersions {
		if v == version {
			return i, true
		}
	}
	return 0, false
}

// HasMAC0 reports whether an envelope version carries a MAC0 field.
func HasMAC0(version uint8) bool {
	return version >= EnvelopeV3
}

// mac0KeyLabel is the domain separator for the MAC0 key.
var mac0KeyLabel = []byte("squic-mac0-v1")

// MAC0Key derives the MAC0 key from the server's X25519 public key.
//
// Keyed on a *public* value, deliberately. Every legitimate caller already
// holds the server's public key — that is the premise of a silent server — so
// both ends can compute this with one hash and no key agreement. It is
// therefore not authentication: anyone holding the key can forge a MAC0, and
// MAC1 remains the proof of possession. What it buys is that a caller who does
// not hold the key can be turned away for the price of one HMAC, before the
// cookie decision and before the Diffie-Hellman.
func MAC0Key(serverX25519Pub []byte) [32]byte {
	h := sha256.New()
	h.Write(mac0KeyLabel)
	h.Write(serverX25519Pub)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

// ComputeMAC0 computes MAC0 over the envelope up to but not including MAC0.
//
// covered is datagram || x25519 || ed25519 || ts || nonce — one contiguous
// slice, which is why this takes bytes rather than fields. The version is
// prefixed for the reason SIP-29 gives for MAC1: it authenticates the marker a
// receiver has to read before it can verify anything, and it makes tags
// computed under different versions unrelated.
//
// Unlike MAC1 this covers the client's X25519 key explicitly. MAC1 does not
// need to — that key is what its shared secret is derived from — but MAC0's key
// does not depend on it, so leaving it out would let it be swapped.
func ComputeMAC0(version uint8, key [32]byte, covered []byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte{version})
	mac.Write(covered)
	return mac.Sum(nil)[:MAC0Size]
}

// VerifyMAC0 checks a MAC0 tag in constant time.
func VerifyMAC0(version uint8, key [32]byte, covered []byte, mac0 []byte) bool {
	return subtle.ConstantTimeCompare(mac0, ComputeMAC0(version, key, covered)) == 1
}

// ComputeMAC1 computes a MAC1 tag with a timestamp and nonce for replay protection.
// MAC1 = HMAC-SHA256(sharedSecret, [version ||] data || ed25519 || timestamp || nonce)[:16]
//
// SIP-3: the carried Ed25519 identity field is part of the MAC1 input (it does
// not feed the shared secret, so leaving it unauthenticated would let an on-path
// attacker substitute the sign-conjugate key and flip the reported identity).
// ed25519 is the 32-byte field exactly as it appears on the wire (all zeros when
// no identity is asserted).
//
// SIP-29: every marked version prefixes its version byte; version 1 predates the
// marker and prefixes nothing. A prefix rather than a suffix, because it is doing
// two jobs. It authenticates the marker, which a receiver has to read before it
// can verify anything. And because it comes first, tags computed under different
// versions are unrelated even when the remaining input coincides — so a packet
// valid under one version can never verify under another, whatever an attacker
// picks for the rest of the envelope.
func ComputeMAC1(version uint8, sharedSecret []byte, data []byte, ed25519 []byte, timestamp uint32, nonce []byte) []byte {
	mac := hmac.New(sha256.New, sharedSecret)
	if version != EnvelopeV1 {
		mac.Write([]byte{version})
	}
	mac.Write(data)
	mac.Write(ed25519)
	var ts [4]byte
	binary.BigEndian.PutUint32(ts[:], timestamp)
	mac.Write(ts[:])
	mac.Write(nonce)
	return mac.Sum(nil)[:MACSize]
}

// VerifyMAC1 checks a MAC1 tag against data, the ed25519 field, timestamp,
// nonce, and shared secret.
func VerifyMAC1(version uint8, sharedSecret []byte, data []byte, ed25519 []byte, timestamp uint32, nonce []byte, mac1 []byte) bool {
	expected := ComputeMAC1(version, sharedSecret, data, ed25519, timestamp, nonce)
	return subtle.ConstantTimeCompare(mac1, expected) == 1
}

// GenerateNonce generates a cryptographically random 8-byte nonce.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
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

// cookieKeyLabel is the domain separator for the cookie-reply encryption key.
var cookieKeyLabel = []byte("squic-cookie-v1")

// CookieKey derives the key that encrypts cookie replies, from the server's
// X25519 public key.
//
// Both ends can compute this without a Diffie-Hellman: the server holds the
// matching private key, and any legitimate client already knows the server's
// public key — that is the premise of a silent server. Keying it off the DH
// shared secret instead would defeat the purpose, since the cookie exists
// precisely so the server does not have to do a DH for an unverified caller.
//
// An attacker who does not hold the server's public key cannot read the
// cookie, and one who does could already make the server do DH work, so
// nothing is given away.
func CookieKey(serverX25519Pub []byte) [32]byte {
	h := sha256.New()
	h.Write(cookieKeyLabel)
	h.Write(serverX25519Pub)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
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
