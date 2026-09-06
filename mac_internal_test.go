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

func TestTrailerWidthsAre69And101(t *testing.T) {
	if TrailerAnon != 69 {
		t.Fatalf("anonymous trailer is %d bytes, want 69", TrailerAnon)
	}
	if TrailerAnon != ClientKeySize+TimestampSize+GateSize+MACSize+HdrSize {
		t.Fatal("TrailerAnon does not equal the sum of its fields")
	}
	if TrailerWithIdentity != TrailerAnon+Ed25519Size {
		t.Fatalf("identity trailer is %d bytes, want %d", TrailerWithIdentity, TrailerAnon+Ed25519Size)
	}
}

// Both tags cover the same contiguous range and differ only in key. That is
// what lets one field carry two proofs, and it is the construction squic-rust
// has to agree with byte for byte.
func TestBothTagsCoverTheSameRange(t *testing.T) {
	hdr := Hdr(EnvelopeV4, false)
	covered := bytes.Repeat([]byte{0x5c}, 64)
	key := GateKey(bytes.Repeat([]byte{0x11}, 32))
	shared := bytes.Repeat([]byte{0x22}, 32)

	gate := ComputeGate(hdr, key[:], covered)
	mac1 := ComputeMAC1(hdr, shared, covered)

	if !VerifyGate(hdr, key[:], covered, gate) {
		t.Fatal("the gate did not verify over its own range")
	}
	if !VerifyMAC1(hdr, shared, covered, mac1) {
		t.Fatal("MAC1 did not verify over its own range")
	}
	// Same range, different keys, so the tags must differ.
	if bytes.Equal(gate, mac1) {
		t.Fatal("the gate and MAC1 produced the same tag")
	}
	// One byte of the range altered breaks both.
	altered := append([]byte(nil), covered...)
	altered[0] ^= 1
	if VerifyGate(hdr, key[:], altered, gate) || VerifyMAC1(hdr, shared, altered, mac1) {
		t.Fatal("a tag verified over a range it did not cover")
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
	sc := newServerConn(conn, seed, nil, 5, []uint8{EnvelopeV4})

	if sc.underLoad.Load() {
		t.Fatal("a server starts under load")
	}

	// Push the counter past the threshold and let one monitor tick see it.
	sc.loadCount.Store(50)
	if !waitFor(func() bool { return sc.underLoad.Load() }) {
		t.Fatal("the monitor never raised under-load with the count above the threshold")
	}

	// Hysteresis: a brief lull shorter than the release debounce must NOT clear
	// under-load. This is the anti-oscillation guarantee — a sustained flood
	// whose 1s windows dip below the threshold now and then must not flap the
	// server out of under-load, because Initials forwarded while it is clear
	// evade the cookie defence. The engaging tick zeroed the debounce, so three
	// quiet seconds are still short of the release window.
	sc.loadCount.Store(0)
	if waitForDur(func() bool { return !sc.underLoad.Load() }, 3*time.Second) {
		t.Fatal("under-load cleared during a brief lull; hysteresis must hold through short dips")
	}

	// A sustained lull does clear it on its own — an operator does not have to.
	// This takes the release debounce, so allow well beyond it.
	if !waitForDur(func() bool { return !sc.underLoad.Load() }, 8*time.Second) {
		t.Fatal("under-load never cleared after a sustained lull")
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
	sc := newServerConn(conn, seed, nil, 0, []uint8{EnvelopeV4}) // defence off: no background rotation

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

// waitForDur polls cond until it holds or the duration elapses. Used by the
// hysteresis test, whose windows are measured in seconds, not the fixed budget
// waitFor gives.
func waitForDur(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
