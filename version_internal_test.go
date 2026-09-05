package squic

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
)

// SIP-29. The header is the last byte of the datagram because that is the only
// offset a receiver can read without already knowing the trailer's width — and
// knowing the width is what the header is for. Under version 4 it carries the
// identity flag too, so the width is no longer a constant per version.

const testDatagram = 1200

// pair builds a matched client and server over loopback, choosing the version
// the client emits and the versions the server will parse.
func pair(t *testing.T, clientVersion uint8, serverVersions []uint8) (*serverConn, *clientConn) {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	serverPriv := Ed25519PrivateToX25519(ed25519.NewKeyFromSeed(seed))
	serverPub := x25519Public(serverPriv)

	cseed := make([]byte, ed25519.SeedSize)
	rand.Read(cseed)
	clientPriv := Ed25519PrivateToX25519(ed25519.NewKeyFromSeed(cseed))
	clientPub := x25519Public(clientPriv)

	shared, err := X25519(clientPriv, serverPub)
	if err != nil {
		t.Fatalf("X25519: %v", err)
	}

	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sconn.Close() })
	cconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cconn.Close() })

	sc := newServerConn(sconn, serverPriv, nil, 0, serverVersions)
	cc := newClientConn(cconn, shared, clientPub, nil, sconn.LocalAddr().(*net.UDPAddr), GateKey(serverPub), CookieKey(serverPub), clientVersion)
	return sc, cc
}

func initialDatagram() []byte {
	p := make([]byte, testDatagram)
	p[0] = 0xC0 // long header, fixed bit, Initial
	// QUIC v1, big-endian in bytes 1..5. The version field is load-bearing in a
	// fixture: the server drops a long header whose version quic-go would not
	// parse, and it does so ahead of the envelope, so a datagram left at
	// version 0 never reaches the code these tests are about.
	binary.BigEndian.PutUint32(p[1:5], uint32(quic.Version1))
	return p
}

// The whole envelope agreed end to end: the header's position, the trailer's
// width, and the header prefix in both tags.
func TestEnvelopeVersion4RoundTrips(t *testing.T) {
	sc, cc := pair(t, EnvelopeV4, []uint8{EnvelopeV4})
	buf := cc.buildInitial(initialDatagram())

	if len(buf) != testDatagram+TrailerAnon {
		t.Fatalf("envelope is %d bytes, want %d", len(buf), testDatagram+TrailerAnon)
	}
	if got := HdrVersion(buf[len(buf)-1]); got != EnvelopeV4 {
		t.Fatalf("header names version %d, want %d", got, EnvelopeV4)
	}
	if HdrHasIdentity(buf[len(buf)-1]) {
		t.Fatal("an anonymous client set the identity flag")
	}

	ok, quicLen := sc.validateAndStrip(buf, len(buf), nil)
	if !ok || quicLen != testDatagram {
		t.Fatalf("server rejected a version 4 envelope: ok=%v len=%d", ok, quicLen)
	}
}

// The 32 bytes version 3 spent on every anonymous Initial.
func TestAnonymousEnvelopeIsShorterThanOneWithAnIdentity(t *testing.T) {
	if TrailerWithIdentity-TrailerAnon != Ed25519Size {
		t.Fatalf("identity costs %d bytes, want %d", TrailerWithIdentity-TrailerAnon, Ed25519Size)
	}
	if TrailerAnon != 69 || TrailerWithIdentity != 101 {
		t.Fatalf("trailer widths are %d and %d, want 69 and 101", TrailerAnon, TrailerWithIdentity)
	}
}

// A server refuses a version it does not implement, and says nothing.
func TestUnimplementedVersionIsDropped(t *testing.T) {
	sc, cc := pair(t, EnvelopeV4, []uint8{EnvelopeV4})
	for _, v := range []uint8{1, 2, 3, 5} {
		buf := cc.buildInitial(initialDatagram())
		buf[len(buf)-1] = Hdr(v, false)
		if ok, _ := sc.validateAndStrip(buf, len(buf), nil); ok {
			t.Fatalf("server parsed envelope version %d", v)
		}
	}
}

// The header is read before it is authenticated. Tampering with it must cost a
// drop and never an accept: both tags cover it as a prefix.
func TestFlippedHeaderIsDropped(t *testing.T) {
	sc, cc := pair(t, EnvelopeV4, []uint8{EnvelopeV4})

	buf := cc.buildInitial(initialDatagram())
	buf[len(buf)-1] = Hdr(EnvelopeV4, true) // claim an identity that is not there
	if ok, _ := sc.validateAndStrip(buf, len(buf), nil); ok {
		t.Fatal("a flipped identity flag was accepted")
	}

	buf = cc.buildInitial(initialDatagram())
	buf[len(buf)-1] = Hdr(7, false)
	if ok, _ := sc.validateAndStrip(buf, len(buf), nil); ok {
		t.Fatal("an unknown version was accepted")
	}
}

// SIP-29's reason for prefixing the header: a tag computed under one header
// must be unrelated to the same input under another.
func TestBothTagsAreBoundToTheHeaderByte(t *testing.T) {
	covered := []byte("a QUIC datagram, a client key, a timestamp")
	anon := Hdr(EnvelopeV4, false)
	ident := Hdr(EnvelopeV4, true)
	shared := []byte("shared secret for tests..........")

	m := ComputeMAC1(anon, shared, covered)
	if VerifyMAC1(ident, shared, covered, m) {
		t.Fatal("MAC1 ignored the header")
	}

	key := GateKey([]byte("a server public key.............."))
	g := ComputeGate(anon, key[:], covered)
	if VerifyGate(ident, key[:], covered, g) {
		t.Fatal("the gate ignored the header")
	}
}

// The property the gate exists for.
func TestGateSeparatesACallerWhoKnowsTheKey(t *testing.T) {
	covered := []byte("envelope bytes")
	h := Hdr(EnvelopeV4, false)
	mine := GateKey([]byte("the real server public key......."))
	theirs := GateKey([]byte("some other server's public key.."))

	tag := ComputeGate(h, mine[:], covered)
	if !VerifyGate(h, mine[:], covered, tag) {
		t.Fatal("a caller holding the key was refused")
	}
	if VerifyGate(h, theirs[:], covered, tag) {
		t.Fatal("a stranger's tag verified")
	}
}

// The two modes must not verify each other, or the load rule could be
// side-stepped by sending the cheaper form.
func TestTheTwoGateModesDoNotVerifyEachOther(t *testing.T) {
	covered := []byte("envelope bytes")
	h := Hdr(EnvelopeV4, false)
	key := GateKey([]byte("a server public key.............."))
	cookie := []byte("0123456789abcdef")

	byKey := ComputeGate(h, key[:], covered)
	byCookie := ComputeGate(h, cookie, covered)

	if VerifyGate(h, cookie, covered, byKey) {
		t.Fatal("a public-key tag verified as a cookie tag")
	}
	if VerifyGate(h, key[:], covered, byCookie) {
		t.Fatal("a cookie tag verified as a public-key tag")
	}
}

// Both keys are derived from the same public value and separated only by their
// labels. Reusing one label would key two unrelated constructions identically.
func TestGateAndCookieKeysAreSeparated(t *testing.T) {
	pub := []byte("a server public key..............")
	if GateKey(pub) == CookieKey(pub) {
		t.Fatal("the gate key and the cookie key are the same")
	}
}

func TestTrailerLenKnowsOnlyDefinedVersions(t *testing.T) {
	if n, ok := TrailerLen(Hdr(EnvelopeV4, false)); !ok || n != TrailerAnon {
		t.Fatalf("anonymous width is %d (ok=%v), want %d", n, ok, TrailerAnon)
	}
	if n, ok := TrailerLen(Hdr(EnvelopeV4, true)); !ok || n != TrailerWithIdentity {
		t.Fatalf("identity width is %d (ok=%v), want %d", n, ok, TrailerWithIdentity)
	}
	for _, v := range []uint8{0, 1, 2, 3, 5, 15} {
		if _, ok := TrailerLen(Hdr(v, false)); ok {
			t.Fatalf("version %d was accepted", v)
		}
	}
}

func TestEveryKnownVersionHasATrailer(t *testing.T) {
	for _, v := range EnvelopeVersions {
		if _, ok := TrailerLen(Hdr(v, false)); !ok {
			t.Fatalf("version %d has no trailer width", v)
		}
		if _, ok := VersionIndex(v); !ok {
			t.Fatalf("version %d has no counter slot", v)
		}
	}
}
