package squic

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"github.com/quic-go/quic-go"
	"net"
	"testing"
)

// SIP-29. The marker is the last byte of the datagram because that is the only
// offset a receiver can read without already knowing the trailer's width — and
// knowing the width is what the marker is for.

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
	cc := newClientConn(cconn, shared, clientPub, nil, CookieKey(serverPub), clientVersion)
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

// A version 2 client and a server that accepts version 2 agree on the whole
// envelope: the marker's position, the trailer's width, and the version prefix
// in MAC1.
func TestEnvelopeVersion2RoundTrips(t *testing.T) {
	sc, cc := pair(t, EnvelopeV2, []uint8{EnvelopeV1, EnvelopeV2})
	buf := cc.buildInitial(initialDatagram())

	if len(buf) != testDatagram+MACOverheadV2 {
		t.Fatalf("envelope is %d bytes, want %d", len(buf), testDatagram+MACOverheadV2)
	}
	if buf[len(buf)-1] != EnvelopeV2 {
		t.Fatalf("marker is not the last byte: got %#02x", buf[len(buf)-1])
	}

	ok, quicLen := sc.validateAndStrip(buf, len(buf), nil)
	if !ok || quicLen != testDatagram {
		t.Fatalf("server rejected a version 2 envelope: ok=%v len=%d", ok, quicLen)
	}
}

// The transition case, and the reason this SIP is worth having: one server
// serving both versions at once.
func TestServerServesBothVersionsAtOnce(t *testing.T) {
	for _, version := range []uint8{EnvelopeV1, EnvelopeV2} {
		sc, cc := pair(t, version, []uint8{EnvelopeV1, EnvelopeV2})
		buf := cc.buildInitial(initialDatagram())
		ok, quicLen := sc.validateAndStrip(buf, len(buf), nil)
		if !ok || quicLen != testDatagram {
			t.Fatalf("server accepting both refused version %d", version)
		}
	}
}

// A version 1 packet's last byte is the last byte of MAC2. With no cookie that
// is deterministically zero — the reserved version, never a marker — so the
// collision only arises for a packet carrying a real MAC2, which means one
// issued under load. Forced here, because one in 256 is not a thing to leave to
// chance in a test.
func TestVersion1PacketNamingVersion2StillGetsThrough(t *testing.T) {
	sc, cc := pair(t, EnvelopeV1, []uint8{EnvelopeV1, EnvelopeV2})
	buf := cc.buildInitial(initialDatagram())
	if buf[len(buf)-1] != 0 {
		t.Fatalf("no cookie should mean a zero tail, got %#02x", buf[len(buf)-1])
	}

	// Now make it look like a version 2 marker. Not under load, so MAC2's
	// contents are never examined and only the dispatch changes.
	buf[len(buf)-1] = EnvelopeV2

	ok, quicLen := sc.validateAndStrip(buf, len(buf), nil)
	if !ok || quicLen != testDatagram {
		t.Fatal("the version 1 fallback did not rescue a packet that named version 2")
	}
}

// A deployment must be able to retire a version, or the oldest envelope ever
// defined is a permanent floor.
func TestServerCanRetireVersion1(t *testing.T) {
	sc, cc := pair(t, EnvelopeV1, []uint8{EnvelopeV2})
	buf := cc.buildInitial(initialDatagram())
	if ok, _ := sc.validateAndStrip(buf, len(buf), nil); ok {
		t.Fatal("a server that retired version 1 still accepted it")
	}
}

// And a server that has not learned version 2 refuses it, which is the direction
// that does not interoperate and the reason for servers-first deployment.
func TestVersion1ServerRefusesVersion2(t *testing.T) {
	sc, cc := pair(t, EnvelopeV2, []uint8{EnvelopeV1})
	buf := cc.buildInitial(initialDatagram())
	if ok, _ := sc.validateAndStrip(buf, len(buf), nil); ok {
		t.Fatal("a version 1 server accepted a version 2 envelope")
	}
}

// The marker is read before it is authenticated. Tampering with it must cost a
// drop and never an accept: MAC1 covers it as a prefix, so a flipped marker is a
// tag over a layout the sender never used.
func TestFlippedMarkerIsDropped(t *testing.T) {
	sc, cc := pair(t, EnvelopeV2, []uint8{EnvelopeV1, EnvelopeV2})
	buf := cc.buildInitial(initialDatagram())
	buf[len(buf)-1] = 7 // a version nobody defines
	if ok, _ := sc.validateAndStrip(buf, len(buf), nil); ok {
		t.Fatal("an unknown marker was accepted")
	}
}

// SIP-29 prefixes the version to the MAC1 input rather than appending it, so
// that tags computed under different versions are unrelated even when everything
// after the prefix is identical.
func TestMAC1IsBoundToTheEnvelopeVersion(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	data := []byte("one QUIC Initial")
	ed := make([]byte, Ed25519Size)
	ts := NowTimestamp()
	nonce, _ := GenerateNonce()

	v1 := ComputeMAC1(EnvelopeV1, secret, data, ed, ts, nonce)
	v2 := ComputeMAC1(EnvelopeV2, secret, data, ed, ts, nonce)
	if hmac.Equal(v1, v2) {
		t.Fatal("the version is not in the MAC1 input")
	}
	if VerifyMAC1(EnvelopeV2, secret, data, ed, ts, nonce, v1) {
		t.Fatal("a version 1 tag verified as version 2")
	}
	if VerifyMAC1(EnvelopeV1, secret, data, ed, ts, nonce, v2) {
		t.Fatal("a version 2 tag verified as version 1")
	}
	if !VerifyMAC1(EnvelopeV1, secret, data, ed, ts, nonce, v1) ||
		!VerifyMAC1(EnvelopeV2, secret, data, ed, ts, nonce, v2) {
		t.Fatal("a tag did not verify under its own version")
	}
}

// Version 1 predates the marker, so its MAC1 must be exactly what SIP-6
// specified — no prefix. A peer that started prefixing version 1 would break
// every deployment still on it.
func TestVersion1MAC1CarriesNoPrefix(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = 0x11
	}
	data := []byte("payload")
	ed := make([]byte, Ed25519Size)
	var ts uint32 = 1234
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = 7
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	mac.Write(ed)
	var tsb [4]byte
	binary.BigEndian.PutUint32(tsb[:], ts)
	mac.Write(tsb[:])
	mac.Write(nonce)
	want := mac.Sum(nil)[:MACSize]

	got := ComputeMAC1(EnvelopeV1, secret, data, ed, ts, nonce)
	if !hmac.Equal(got, want) {
		t.Fatal("version 1 MAC1 is no longer SIP-6's construction")
	}
}

func TestTrailerLenKnowsOnlyDefinedVersions(t *testing.T) {
	if n, ok := TrailerLen(EnvelopeV1); !ok || n != MACOverhead {
		t.Fatalf("version 1 trailer = %d, %v", n, ok)
	}
	if n, ok := TrailerLen(EnvelopeV2); !ok || n != MACOverhead+1 {
		t.Fatalf("version 2 trailer = %d, %v", n, ok)
	}
	// Version 0 is reserved and never emitted, so a zero byte is known not to
	// be a marker.
	for _, v := range []uint8{0, 3, 255} {
		if _, ok := TrailerLen(v); ok {
			t.Fatalf("version %d should be unknown", v)
		}
	}
}
