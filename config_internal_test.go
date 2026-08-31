package squic

import (
	"crypto/rand"
	"encoding/binary"
	"github.com/quic-go/quic-go"
	"net"
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

	sc := newServerConn(nil, priv, nil, 0, []uint8{EnvelopeV1, EnvelopeV2})
	if sc.loadThreshold != 0 {
		t.Fatalf("loadThreshold = %d, want 0", sc.loadThreshold)
	}
	// With the monitor goroutine never started, under-load can never latch.
	if sc.underLoad.Load() {
		t.Fatal("underLoad set with the defence disabled")
	}
	sc.dhCount.Add(1_000_000)
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
	c := newClientConn(local, make([]byte, 32), make([]byte, 32), nil, cookieKey, EnvelopeV1)

	// A cookie arriving before anything has been sent must not panic and must
	// not invent a packet.
	cookie := make([]byte, MAC2Size)
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

	if !c.storeCookie(sealed) {
		t.Fatal("storeCookie rejected the cookie on the second call")
	}
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no Initial resent after the cookie was stored: %v", err)
	}
	if want := len(datagram) + MACOverhead; n != want {
		t.Fatalf("resent %d bytes, want %d (datagram plus MAC envelope)", n, want)
	}
	if !isQUICInitial(buf[:n]) {
		t.Fatal("resent datagram is not an Initial")
	}
}

// SIP-29's Sending rule in two parts. A release that introduces a version ships
// clients still sending the previous one, so upgrading a client before a server
// cannot break anything; a later release moves the default once servers have
// deployed. This is that later release, so the default is version 2 — and a
// server still accepts version 1, because retiring it is a separate decision a
// deployment makes for itself.
func TestClientDefaultIsVersion2AndServersStillAcceptVersion1(t *testing.T) {
	for _, cfg := range []*Config{nil, {}} {
		if got := cfg.envelopeVersion(); got != EnvelopeV2 {
			t.Fatalf("client default = %d, want %d", got, EnvelopeV2)
		}
		accepted := cfg.acceptedEnvelopeVersions()
		var sawV1, sawV2 bool
		for _, v := range accepted {
			sawV1 = sawV1 || v == EnvelopeV1
			sawV2 = sawV2 || v == EnvelopeV2
		}
		if !sawV1 || !sawV2 {
			t.Fatalf("server default accepts %v, want both versions", accepted)
		}
	}
}
