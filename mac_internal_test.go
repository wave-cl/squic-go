package squic

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// These pin the constructions squic-rust has to agree with byte for byte. A
// disagreement on any of them is invisible in a single-implementation test and
// shows up on the wire as a handshake that quietly takes an extra round trip
// forever, or does not complete at all.

func TestMACOverheadIs108(t *testing.T) {
	if MACOverhead != 108 {
		t.Fatalf("envelope is %d bytes; SIP-6 fixes it at 108", MACOverhead)
	}
	if MACOverhead != ClientKeySize+Ed25519Size+TimestampSize+NonceSize+MACSize+MAC2Size {
		t.Fatal("MACOverhead does not equal the sum of its fields")
	}
}

// MAC2 covers the envelope up to but NOT including MAC1, with MAC1 fed in
// separately. Covering the buffer whole folds MAC1 in twice and never verifies
// — and because a failing MAC2 is indistinguishable from a client that has no
// cookie, the symptom is not an error but an extra round trip, forever.
func TestMAC2CoversTheEnvelopeUpToMAC1(t *testing.T) {
	cookie := bytes.Repeat([]byte{0x7a}, 16)
	shared := bytes.Repeat([]byte{0xab}, 32)
	datagram := []byte("a QUIC Initial, more or less")
	ed := make([]byte, Ed25519Size)
	ts := NowTimestamp()
	nonce, _ := GenerateNonce()
	mac1 := ComputeMAC1(shared, datagram, ed, ts, nonce)

	var buf []byte
	buf = append(buf, datagram...)
	buf = append(buf, bytes.Repeat([]byte{0x11}, ClientKeySize)...)
	buf = append(buf, ed...)
	buf = append(buf, byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts))
	buf = append(buf, nonce...)
	beforeMAC1 := len(buf)
	buf = append(buf, mac1...)

	right := ComputeMAC2(cookie, buf[:beforeMAC1], mac1)
	if !VerifyMAC2(cookie, buf[:beforeMAC1], mac1, right) {
		t.Fatal("MAC2 over the specified range does not verify")
	}

	wrong := ComputeMAC2(cookie, buf, mac1)
	if VerifyMAC2(cookie, buf[:beforeMAC1], mac1, wrong) {
		t.Fatal("MAC2 over the whole buffer verified against the specified range")
	}
}

// An IPv4 address and its IPv4-mapped IPv6 form are the same client and must
// mint the same cookie, or a client reaching a dual-stack socket is challenged
// with one cookie and verified against another.
func TestCookieIsTheSameForV4AndItsMappedForm(t *testing.T) {
	var secret [32]byte
	for i := range secret {
		secret[i] = 0x33
	}
	v4 := net.ParseIP("192.0.2.7")
	mapped := net.ParseIP("::ffff:192.0.2.7")

	if !bytes.Equal(CookieValue(secret, v4), CookieValue(secret, mapped)) {
		t.Fatal("an IPv4 address and its mapped form minted different cookies")
	}
	if bytes.Equal(CookieValue(secret, v4), CookieValue(secret, net.ParseIP("192.0.2.8"))) {
		t.Fatal("different addresses minted the same cookie")
	}
}

// The client derives the reply key from the server's public key alone, with no
// Diffie-Hellman — which is the whole point of the cookie.
func TestCookieReplyOpensUnderTheDerivedKey(t *testing.T) {
	serverPub := bytes.Repeat([]byte{0x5c}, 32)
	key := CookieKey(serverPub)
	cookie := bytes.Repeat([]byte{0x42}, 16)

	sealed, err := EncryptCookie(key, cookie)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(sealed) != CookieNonceSize+16+16 {
		t.Fatalf("sealed cookie is %d bytes, expected %d", len(sealed), CookieNonceSize+32)
	}
	got, ok := DecryptCookie(key, sealed)
	if !ok || !bytes.Equal(got, cookie) {
		t.Fatal("the cookie did not come back out under its own key")
	}
	if _, ok := DecryptCookie(CookieKey(bytes.Repeat([]byte{0x5d}, 32)), sealed); ok {
		t.Fatal("the cookie opened under a key derived from a different server")
	}
}

// The load monitor is what makes the cookie defence reachable at all: without
// it underLoad is never set and the whole MAC2 branch is dead code. squic-rust
// has covered this since the defence landed; Go had not.
func TestLoadMonitorRaisesAndClearsUnderLoad(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	seed := make([]byte, 32)
	rand.Read(seed)
	sc := newServerConn(conn, seed, nil, 5)

	if sc.underLoad.Load() {
		t.Fatal("a server starts under load")
	}

	// Push the counter past the threshold and let one monitor tick see it.
	sc.dhCount.Store(50)
	if !waitFor(func() bool { return sc.underLoad.Load() }) {
		t.Fatal("the monitor never raised under-load with the count above the threshold")
	}

	// The monitor resets the count each tick, so with no further work it falls
	// back on its own — an operator does not have to clear it.
	if !waitFor(func() bool { return !sc.underLoad.Load() }) {
		t.Fatal("under-load never cleared once the offered load stopped")
	}
}

// A cookie minted under the previous secret is still accepted for one rotation
// period. Without the grace, a client challenged just before a rotation answers
// with a cookie the server no longer knows, is challenged again, and in a
// pathological case never converges.
func TestCookieRotationKeepsOneGenerationOfGrace(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	seed := make([]byte, 32)
	rand.Read(seed)
	sc := newServerConn(conn, seed, nil, 0) // defence off: no background rotation

	ip := net.ParseIP("198.51.100.9")
	current, _ := sc.cookieSecrets()
	old := CookieValue(current, ip)

	rotate(sc)
	cur, prev := sc.cookieSecrets()
	if !bytes.Equal(CookieValue(prev, ip), old) {
		t.Fatal("the previous secret is not the one that was current")
	}
	if bytes.Equal(CookieValue(cur, ip), old) {
		t.Fatal("rotation did not change the current secret")
	}

	rotate(sc)
	_, prev = sc.cookieSecrets()
	if bytes.Equal(CookieValue(prev, ip), old) {
		t.Fatal("a cookie two rotations old is still within the grace period")
	}
}

func rotate(c *serverConn) {
	var fresh [32]byte
	rand.Read(fresh[:])
	c.secretsMu.Lock()
	c.prevCookieSecret = c.cookieSecret
	c.cookieSecret = fresh
	c.secretsMu.Unlock()
}

func waitFor(cond func() bool) bool {
	for i := 0; i < 60; i++ {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
