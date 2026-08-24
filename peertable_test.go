package squic

import (
	"testing"
	"time"
)

func TestPeerTableSameKeyIdempotent(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	k := [32]byte{1}
	pt.record([]byte("cid1"), k, now)
	pt.record([]byte("cid1"), k, now) // retransmission
	got, ok := pt.take([]byte("cid1"), now)
	if !ok || got != k {
		t.Fatalf("take = %x, %v; want %x, true", got, ok, k)
	}
}

func TestPeerTableContestedIsPoisoned(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	pt.record([]byte("cid1"), [32]byte{1}, now)
	pt.record([]byte("cid1"), [32]byte{2}, now) // different key, same DCID
	if _, ok := pt.take([]byte("cid1"), now); ok {
		t.Fatal("poisoned entry must not resolve")
	}
}

func TestPeerTableTakeDrains(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	pt.record([]byte("cid1"), [32]byte{7}, now)
	if _, ok := pt.take([]byte("cid1"), now); !ok {
		t.Fatal("first take should succeed")
	}
	if _, ok := pt.take([]byte("cid1"), now); ok {
		t.Fatal("second take should find nothing")
	}
}

func TestPeerTableExpiry(t *testing.T) {
	pt := newPeerTable()
	start := time.Now()
	pt.record([]byte("cid1"), [32]byte{9}, start)
	later := start.Add(peerKeyTTL + time.Second)
	if _, ok := pt.take([]byte("cid1"), later); ok {
		t.Fatal("expired entry must not resolve")
	}
}

func TestInitialDCID(t *testing.T) {
	pkt := []byte{0xC0, 0, 0, 0, 1, 4, 0xAA, 0xBB, 0xCC, 0xDD, 0x99}
	dcid, ok := initialDCID(pkt)
	if !ok || string(dcid) != string([]byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Fatalf("dcid = %x, %v", dcid, ok)
	}
	if _, ok := initialDCID([]byte{0xC0, 0, 0, 0, 1, 21}); ok {
		t.Fatal("over-long DCID length must be rejected")
	}
}
