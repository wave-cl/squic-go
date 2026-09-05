// Package squic provides a silent-server QUIC wrapper around quic-go.
package squic

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// MACSize is the size of the MAC1 tag in bytes.
	MACSize = 16

	// GateSize is the size of the gate tag in bytes.
	GateSize = 16

	// CookieSize is the size of the cookie a challenge carries.
	CookieSize = 16

	// ClientKeySize is the size of an X25519 public key appended to Initial packets.
	ClientKeySize = 32

	// Ed25519Size is the size of the carried Ed25519 identity field (SIP-3),
	// when one is present.
	Ed25519Size = 32

	// TimestampSize is the size of the replay-protection timestamp (uint32 epoch seconds).
	TimestampSize = 4

	// HdrSize is the width of the trailing header byte: version in the high
	// nibble, flags in the low one.
	HdrSize = 1

	// EnvelopeV4 replaces the separate MAC0 and MAC2 of version 3 with one gate
	// tag.
	//
	// They were never both load-bearing: a cookie is delivered encrypted under
	// a key derived from the server's public key, so producing a valid MAC2
	// already demonstrated the key knowledge MAC0 existed to prove. Version 3
	// paid 32 bytes for two states of one proof.
	//
	// The identity field is now carried only when there is one, and the
	// version-1 nonce is gone — SIP-6 said it was never tracked, and the QUIC
	// datagram underneath already differs per attempt.
	EnvelopeV4 = 4

	// FlagIdentity marks that a 32-byte Ed25519 identity follows the X25519
	// key (SIP-3).
	FlagIdentity = 0x01

	// FlagReserved is the header's remaining flag bits, which no version
	// defines a meaning for.
	//
	// Refused rather than ignored, because ignoring them is a one-way door.
	// Both tags cover the header byte as it arrived, so a client that sets a
	// reserved bit and computes its tags over it would otherwise be admitted —
	// the tags verify, and nothing else looks at the bit. Deployed servers
	// would then be accepting these bits with no meaning attached, and a later
	// version could not give them one: it would have no way to tell a peer
	// asserting the new flag from an older peer that set the bit for no reason.
	//
	// Tampering in transit was never the risk — a flipped bit changes the tag
	// input and fails. The risk is to the protocol's own future, and closing it
	// costs nothing only while none of the bits are wanted.
	FlagReserved = 0x0E

	// TrailerAnon is the trailer width for an anonymous caller: X25519,
	// timestamp, gate, MAC1, header.
	TrailerAnon = ClientKeySize + TimestampSize + GateSize + MACSize + HdrSize

	// TrailerWithIdentity is the trailer width when an identity is carried.
	TrailerWithIdentity = TrailerAnon + Ed25519Size

	// CookieReplyType is the first byte of a cookie reply packet.
	// Distinguishes from QUIC packets (Initial starts with 0xC0+).
	CookieReplyType = 0x01

	// CookieNonceSize is the nonce size for XChaCha20-Poly1305.
	CookieNonceSize = 24

	// ReplayWindow is the maximum age of a timestamp before the server rejects it.
	// Also allows timestamps slightly in the future to account for clock skew.
	ReplayWindow = 120 * time.Second
)

// Hdr builds the trailing header byte.
func Hdr(version uint8, identity bool) uint8 {
	h := version << 4
	if identity {
		h |= FlagIdentity
	}
	return h
}

// HdrVersion returns the version half of a header byte.
func HdrVersion(hdr uint8) uint8 {
	return hdr >> 4
}

// HdrHasIdentity reports whether a header byte says an Ed25519 identity is
// carried.
func HdrHasIdentity(hdr uint8) bool {
	return hdr&FlagIdentity != 0
}

// TrailerLen returns the trailer width a header byte implies, and false if the
// version is unknown.
//
// Unlike version 3 this is not a constant per version: the identity field is
// present only when flagged, so the width has to be read off the header byte
// that a receiver finds at the end of the datagram.
func TrailerLen(hdr uint8) (int, bool) {
	if HdrVersion(hdr) != EnvelopeV4 {
		return 0, false
	}
	if hdr&FlagReserved != 0 {
		return 0, false
	}
	if HdrHasIdentity(hdr) {
		return TrailerWithIdentity, true
	}
	return TrailerAnon, true
}

// EnvelopeVersions is every envelope version this build knows.
//
// The one list to extend when a version is added — TrailerLen and the
// per-version accept counters are both keyed off it.
var EnvelopeVersions = []uint8{EnvelopeV4}

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

// gateKeyLabel is the domain separator for the gate key.
var gateKeyLabel = []byte("squic-gate-v1")

// GateKey derives the no-cookie gate key from the server's X25519 public key.
//
// Keyed on a *public* value, deliberately. Every legitimate caller already
// holds the server's public key — that is the premise of a silent server — so
// both ends compute this with one hash and no key agreement. It is therefore
// not authentication: anyone holding the key can forge this tag, and MAC1
// remains the proof of possession. What it buys is that a caller who does
// *not* hold the key is turned away for the price of one HMAC, before the
// Diffie-Hellman.
func GateKey(serverX25519Pub []byte) [32]byte {
	h := sha256.New()
	h.Write(gateKeyLabel)
	h.Write(serverX25519Pub)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

// ComputeGate computes the gate tag over the envelope up to but not including
// the tag.
//
// covered is datagram || x25519 || [ed25519] || ts — one contiguous slice,
// which is why this takes bytes rather than fields. The header byte is
// prefixed for the reason SIP-29 gives: it authenticates the byte a receiver
// has to read before it can verify anything, and because it comes first, tags
// computed under different versions or flags are unrelated even when the rest
// of the input coincides.
//
// The key is what makes this one field do two jobs:
//
//   - GateKey — the caller holds no cookie, and the tag proves only that it
//     knows the server's public key.
//   - the cookie itself — the caller answered a challenge, and the tag proves
//     that and that its source address receives packets, which no single
//     datagram can demonstrate on its own.
func ComputeGate(hdr uint8, key []byte, covered []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte{hdr})
	mac.Write(covered)
	return mac.Sum(nil)[:GateSize]
}

// VerifyGate checks a gate tag in constant time.
func VerifyGate(hdr uint8, key []byte, covered []byte, gate []byte) bool {
	return subtle.ConstantTimeCompare(gate, ComputeGate(hdr, key, covered)) == 1
}

// ComputeMAC1 computes MAC1 over the same range the gate tag covers, keyed on
// the Diffie-Hellman shared secret.
//
// One covered range for both tags — hdr || datagram || x25519 || [ed25519] ||
// ts — so there is a single rule to hold rather than two constructions with
// different opinions about what they authenticate.
//
// This is the proof of possession, and the reason it cannot merge with the
// gate: verifying it requires the curve operation the gate exists to avoid.
//
// SIP-3: the carried Ed25519 identity is inside the covered range. That is
// load-bearing — it does not feed the shared secret, so if it were left
// unauthenticated an on-path attacker could substitute the sign-conjugate key,
// which passes the server's derivation check, and flip the reported identity.
func ComputeMAC1(hdr uint8, sharedSecret []byte, covered []byte) []byte {
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write([]byte{hdr})
	mac.Write(covered)
	return mac.Sum(nil)[:MACSize]
}

// VerifyMAC1 checks a MAC1 tag in constant time.
func VerifyMAC1(hdr uint8, sharedSecret []byte, covered []byte, mac1 []byte) bool {
	return subtle.ConstantTimeCompare(mac1, ComputeMAC1(hdr, sharedSecret, covered)) == 1
}

// NowTimestamp returns the current time as a uint32 epoch seconds value.
func NowTimestamp() uint32 {
	return uint32(time.Now().Unix())
}

// CookieValue computes a deterministic cookie for a given (secret, IP) pair.
// cookie = HMAC-SHA256(secret, ip)[:16]
// This is deterministic so the server can recompute it to verify a cookie-keyed
// gate tag.
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
