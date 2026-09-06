package squic

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"github.com/quic-go/quic-go"
	"net"
	"strings"
	"testing"
	"time"
)

// loadThreshold decides whether the cookie defence runs at all, so the mapping
// from the config field to the effective value is worth pinning down. Zero
// cannot mean "off" in Go — it is indistinguishable from a field left out of a
// struct literal — so off is spelled with a negative value.
func TestLoadThresholdMapping(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *Config
		want int64
	}{
		{"nil config takes the default", nil, 1000},
		{"unset field takes the default", &Config{}, 1000},
		{"explicit zero is indistinguishable from unset", &Config{LoadThreshold: 0}, 1000},
		{"positive is used as given", &Config{LoadThreshold: 25}, 25},
		{"negative disables the defence", &Config{LoadThreshold: -1}, 0},
		{"any negative disables it", &Config{LoadThreshold: -9999}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.loadThreshold(); got != tc.want {
				t.Errorf("loadThreshold() = %d, want %d", got, tc.want)
			}
		})
	}
}

// A zero effective threshold must actually stop the machinery, not merely sit
// there as a threshold nothing reaches.
func TestZeroThresholdStartsNoCookieMachinery(t *testing.T) {
	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv := make([]byte, 32)
	copy(priv, pub)

	sc := newServerConn(nil, priv, nil, 0, []uint8{EnvelopeV4})
	if sc.loadThreshold != 0 {
		t.Fatalf("loadThreshold = %d, want 0", sc.loadThreshold)
	}
	// With the monitor goroutine never started, under-load can never latch.
	if sc.underLoad.Load() {
		t.Fatal("underLoad set with the defence disabled")
	}
	sc.loadCount.Add(1_000_000)
	if sc.underLoad.Load() {
		t.Fatal("underLoad latched despite the monitor being disabled")
	}
}

// Storing a cookie must put an Initial back on the wire immediately, rather
// than leaving it to quic-go's retransmission timer. The end-to-end test
// cannot show this on its own — quic-go's PTO is short enough to pass a
// timing bound either way — so drive the mechanism directly.
func TestAnswerChallengeRetransmitsImmediately(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("peer socket: %v", err)
	}
	defer peer.Close()

	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("local socket: %v", err)
	}
	defer local.Close()

	var cookieKey [32]byte
	rand.Read(cookieKey[:])
	var gateKey [32]byte
	rand.Read(gateKey[:])
	c := newClientConn(local, make([]byte, 32), make([]byte, 32), nil, peer.LocalAddr().(*net.UDPAddr), gateKey, cookieKey, EnvelopeV4)

	// A cookie arriving before anything has been sent must not panic and must
	// not invent a packet.
	cookie := make([]byte, CookieSize)
	rand.Read(cookie)
	sealed, err := EncryptCookie(cookieKey, cookie)
	if err != nil {
		t.Fatalf("EncryptCookie: %v", err)
	}
	if !c.storeCookie(sealed) {
		t.Fatal("storeCookie rejected a cookie sealed with the matching key")
	}
	peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 2048)
	if n, _, err := peer.ReadFromUDP(buf); err == nil {
		t.Fatalf("sent %d bytes before any Initial had been written", n)
	}

	// With an Initial on record, the next cookie must trigger a resend of it.
	datagram := make([]byte, 1200)
	datagram[0] = 0xC0 // long header, Initial
	binary.BigEndian.PutUint32(datagram[1:5], uint32(quic.Version1))
	c.rememberInitial(datagram, peer.LocalAddr().(*net.UDPAddr))

	// A *fresh* cookie, because a repeat of one already held earns no
	// retransmission: buildInitial stamps the stored cookie onto every Initial,
	// so a second copy of it has nothing to add. That rule has its own test
	// below; this one is about a new challenge being answered at once.
	fresh := make([]byte, CookieSize)
	rand.Read(fresh)
	sealedFresh, err := EncryptCookie(cookieKey, fresh)
	if err != nil {
		t.Fatalf("EncryptCookie: %v", err)
	}
	if !c.storeCookie(sealedFresh) {
		t.Fatal("storeCookie rejected a freshly sealed cookie")
	}
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no Initial resent after the cookie was stored: %v", err)
	}
	if want := len(datagram) + TrailerAnon; n != want {
		t.Fatalf("resent %d bytes, want %d (datagram plus MAC envelope)", n, want)
	}
	if !isQUICInitial(buf[:n]) {
		t.Fatal("resent datagram is not an Initial")
	}
}

// One version, and the default accept-set is that same version.
//
// The second audit measured why this matters: with [1, 2, 3] as the shipped
// default, a junk datagram bought a curve operation, because versions 1 and 2
// carried no cheap gate for the server to check. A default that admits a weaker
// envelope than the client sends undoes the gate entirely.
func TestTheOnlyVersionIsFourAndItIsTheDefaultOnBothSides(t *testing.T) {
	for _, cfg := range []*Config{nil, {}} {
		if got := cfg.envelopeVersion(); got != EnvelopeV4 {
			t.Fatalf("client default = %d, want %d", got, EnvelopeV4)
		}
		accepted := cfg.acceptedEnvelopeVersions()
		if len(accepted) != 1 || accepted[0] != EnvelopeV4 {
			t.Fatalf("server default accepts %v, want [%d]", accepted, EnvelopeV4)
		}
	}
	if len(EnvelopeVersions) != 1 || EnvelopeVersions[0] != EnvelopeV4 {
		t.Fatalf("EnvelopeVersions = %v, want [%d]", EnvelopeVersions, EnvelopeV4)
	}
}

// Anyone can mint a cookie reply this client will open — it is sealed under a
// key derived from the server's *public* key, which is published. So the source
// address is the only thing separating the server from a stranger who would
// like the client to send a 1309-byte Initial for every 57 bytes they spend.
func TestCookieReplyFromAStrangerIsIgnored(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	stranger, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()

	var cookieKey, gateKey [32]byte
	rand.Read(cookieKey[:])
	rand.Read(gateKey[:])
	c := newClientConn(local, make([]byte, 32), make([]byte, 32), nil,
		peer.LocalAddr().(*net.UDPAddr), gateKey, cookieKey, EnvelopeV4)

	datagram := make([]byte, 1200)
	datagram[0] = 0xC0
	binary.BigEndian.PutUint32(datagram[1:5], uint32(quic.Version1))
	c.rememberInitial(datagram, peer.LocalAddr().(*net.UDPAddr))

	if c.fromServer(stranger.LocalAddr()) {
		t.Fatal("a stranger's address was accepted as the server's")
	}
	if !c.fromServer(peer.LocalAddr()) {
		t.Fatal("the server's own address was rejected")
	}

	// Drive the read path with a reply the stranger minted.
	cookie := make([]byte, CookieSize)
	rand.Read(cookie)
	sealed, err := EncryptCookie(cookieKey, cookie)
	if err != nil {
		t.Fatal(err)
	}
	reply := append([]byte{CookieReplyType}, sealed...)
	if _, err := stranger.WriteToUDP(reply, local.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	local.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := c.ReadFrom(buf); err != nil {
		t.Fatalf("the injected reply was swallowed instead of passed through: %v", err)
	}
	if _, ok := c.cookie.Load().([]byte); ok {
		t.Error("a stranger set our cookie")
	}
	peer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := peer.ReadFromUDP(buf); err == nil {
		t.Errorf("an injected cookie reply made the client send %d bytes at the server", n)
	}
}

// The amplifier this closes: one Initial earns one answered challenge, however
// many replies arrive. Each carries a different cookie, so it is the
// per-Initial allowance being measured and not the duplicate check.
func TestOneInitialEarnsOneAnsweredChallenge(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()

	var cookieKey, gateKey [32]byte
	rand.Read(cookieKey[:])
	rand.Read(gateKey[:])
	c := newClientConn(local, make([]byte, 32), make([]byte, 32), nil,
		peer.LocalAddr().(*net.UDPAddr), gateKey, cookieKey, EnvelopeV4)

	datagram := make([]byte, 1200)
	datagram[0] = 0xC0
	binary.BigEndian.PutUint32(datagram[1:5], uint32(quic.Version1))
	c.rememberInitial(datagram, peer.LocalAddr().(*net.UDPAddr))

	for i := 0; i < 10; i++ {
		cookie := make([]byte, CookieSize)
		rand.Read(cookie)
		sealed, err := EncryptCookie(cookieKey, cookie)
		if err != nil {
			t.Fatal(err)
		}
		c.storeCookie(sealed)
	}

	answers := 0
	buf := make([]byte, 2048)
	for {
		peer.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		if _, _, err := peer.ReadFromUDP(buf); err != nil {
			break
		}
		answers++
	}
	if answers != 1 {
		t.Fatalf("ten replies bought %d Initials; the allowance is one per Initial sent", answers)
	}
}

// And a cookie we already hold earns nothing, even after a fresh Initial has
// re-armed the allowance. A captured reply replayed at the client is then worth
// nothing at all.
func TestRepeatedCookieEarnsNoFurtherAnswer(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()

	var cookieKey, gateKey [32]byte
	rand.Read(cookieKey[:])
	rand.Read(gateKey[:])
	c := newClientConn(local, make([]byte, 32), make([]byte, 32), nil,
		peer.LocalAddr().(*net.UDPAddr), gateKey, cookieKey, EnvelopeV4)

	datagram := make([]byte, 1200)
	datagram[0] = 0xC0
	binary.BigEndian.PutUint32(datagram[1:5], uint32(quic.Version1))
	cookie := make([]byte, CookieSize)
	rand.Read(cookie)
	sealed, err := EncryptCookie(cookieKey, cookie)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)

	c.rememberInitial(datagram, peer.LocalAddr().(*net.UDPAddr))
	c.storeCookie(sealed)
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := peer.ReadFromUDP(buf); err != nil {
		t.Fatalf("the first challenge was not answered at all: %v", err)
	}

	// A second Initial re-arms the allowance, so only the duplicate check
	// stands between a replayed reply and another Initial.
	c.rememberInitial(datagram, peer.LocalAddr().(*net.UDPAddr))
	c.storeCookie(sealed)
	peer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := peer.ReadFromUDP(buf); err == nil {
		t.Errorf("a cookie we already held bought another %d-byte Initial", n)
	}
}

// An envelope version nobody defines used to write the marker one byte past a
// buffer sized without room for it — a panic on the client's first Initial,
// from a config typo. Dial refuses it now, and buildInitial cannot be reached
// with one; if it ever were, it falls back to version 1 whole rather than to
// version 1's width with a version 3 marker.
func TestUnknownEnvelopeVersionDoesNotPanic(t *testing.T) {
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()

	var cookieKey, gateKey [32]byte
	rand.Read(cookieKey[:])
	rand.Read(gateKey[:])

	for _, v := range []uint8{0, 4, 7, 255} {
		c := newClientConn(local, make([]byte, 32), make([]byte, 32), nil,
			local.LocalAddr().(*net.UDPAddr), gateKey, cookieKey, v)
		datagram := make([]byte, 1200)
		datagram[0] = 0xC0
		binary.BigEndian.PutUint32(datagram[1:5], uint32(quic.Version1))

		buf := c.buildInitial(datagram) // must not panic
		if want := len(datagram) + TrailerAnon; len(buf) != want {
			t.Errorf("version %d: built %d bytes, want %d (the version 1 envelope)", v, len(buf), want)
		}
	}
}

// And Dial says so plainly rather than letting it become a handshake timeout.
func TestDialRejectsAnUnknownEnvelopeVersion(t *testing.T) {
	_, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = Dial(ctx, "127.0.0.1:1", pubKey, &Config{EnvelopeVersion: 9})
	if err == nil {
		t.Fatal("Dial accepted an undefined envelope version")
	}
	if !strings.Contains(err.Error(), "unknown EnvelopeVersion") {
		t.Errorf("error does not name the cause: %v", err)
	}
}

// The mirror, and the one with the higher price for being absent. A server told
// to accept only versions it cannot parse binds, reports itself healthy, and
// then drops every Initial without a word — SIP-6 requires the silence, so
// nothing distinguishes it from a firewall.
//
// [3] is the case that matters rather than a synthetic one: it is what ex had
// in its config file up to the v4 cut, and installing a v4 binary without
// editing that line would have taken the exchange down in silence.
func TestListenRejectsAnAcceptSetItCannotParse(t *testing.T) {
	cert, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Wholly unparsable, including ex's real pre-cut config; then the quieter
	// half, a set mixing parsable and unparsable versions, which would serve v4
	// callers and silently drop v3 callers while the operator believed both
	// were served.
	for _, bad := range [][]uint8{{3}, {1}, {0}, {2, 3}, {5, 255}, {3, 4}} {
		ln, err := Listen("udp", "127.0.0.1:0", cert, pubKey,
			&Config{AcceptedEnvelopeVersions: bad})
		if err == nil {
			ln.Close()
			t.Errorf("Listen bound on an accept set it cannot parse: %v", bad)
			continue
		}
		if !strings.Contains(err.Error(), "AcceptedEnvelopeVersions") {
			t.Errorf("%v was refused for the wrong reason: %v", bad, err)
		}
	}

	// The control. The implemented set gets past the guard and binds, so the
	// loop above is failing on the version and not on something incidental to
	// every Listen in it.
	ln, err := Listen("udp", "127.0.0.1:0", cert, pubKey,
		&Config{AcceptedEnvelopeVersions: []uint8{EnvelopeV4}})
	if err != nil {
		t.Fatalf("the implemented version was refused by the guard: %v", err)
	}
	ln.Close()
}

// T3: the window fields mean the same thing in both implementations now, and
// "the same thing" is a pinned window rather than a ceiling.
//
// quinn does not auto-tune, so a caller who sets stream_receive_window in
// squic-rust gets a fixed window. Setting only quic-go's Max would have given
// them a floor of 1 MB rising to whatever they asked for — a different thing
// under the same name, which is what the audit found. Initial and Max are set
// together so the two libraries do what each other do.
func TestReceiveWindowsArePinnedNotCapped(t *testing.T) {
	const stream = 3 << 20
	const conn = 24 << 20

	qc := (&Config{StreamReceiveWindow: stream, ReceiveWindow: conn}).quicConfig()

	if qc.InitialStreamReceiveWindow != stream || qc.MaxStreamReceiveWindow != stream {
		t.Errorf("stream window not pinned: initial=%d max=%d, want both %d",
			qc.InitialStreamReceiveWindow, qc.MaxStreamReceiveWindow, stream)
	}
	if qc.InitialConnectionReceiveWindow != conn || qc.MaxConnectionReceiveWindow != conn {
		t.Errorf("connection window not pinned: initial=%d max=%d, want both %d",
			qc.InitialConnectionReceiveWindow, qc.MaxConnectionReceiveWindow, conn)
	}

	// Unset leaves quic-go's own auto-tuning in place, starting at the values
	// squic-rust uses as its fixed defaults. The documented divergence.
	def := (&Config{}).quicConfig()
	if def.InitialStreamReceiveWindow != 1<<20 {
		t.Errorf("default initial stream window = %d, want 1 MB", def.InitialStreamReceiveWindow)
	}
	if def.InitialConnectionReceiveWindow != 10<<20 {
		t.Errorf("default initial connection window = %d, want 10 MB", def.InitialConnectionReceiveWindow)
	}
	if def.MaxStreamReceiveWindow != 0 {
		t.Errorf("default pinned the stream ceiling at %d; auto-tuning should be quic-go's",
			def.MaxStreamReceiveWindow)
	}
}
