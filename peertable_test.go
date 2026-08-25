package squic

import (
	"testing"
	"time"
)

func TestPeerTableSameKeyIdempotent(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	k := [32]byte{1}
	id := [32]byte{9}
	pt.record([]byte("cid1"), k, id, true, now)
	pt.record([]byte("cid1"), k, id, true, now) // retransmission
	got, gotID, hasID, ok := pt.take([]byte("cid1"), now)
	if !ok || got != k || !hasID || gotID != id {
		t.Fatalf("take = %x id=%x has=%v ok=%v; want key %x id %x", got, gotID, hasID, ok, k, id)
	}
}

func TestPeerTableContestedIsPoisoned(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	pt.record([]byte("cid1"), [32]byte{1}, [32]byte{}, false, now)
	pt.record([]byte("cid1"), [32]byte{2}, [32]byte{}, false, now) // different key, same DCID
	if _, _, _, ok := pt.take([]byte("cid1"), now); ok {
		t.Fatal("poisoned entry must not resolve")
	}
}

func TestPeerTableContestedIdentityIsPoisoned(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	pt.record([]byte("cid1"), [32]byte{1}, [32]byte{9}, true, now)
	pt.record([]byte("cid1"), [32]byte{1}, [32]byte{8}, true, now) // same key, different identity
	if _, _, _, ok := pt.take([]byte("cid1"), now); ok {
		t.Fatal("contested identity must poison the entry")
	}
}

func TestPeerTableTakeDrains(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	pt.record([]byte("cid1"), [32]byte{7}, [32]byte{}, false, now)
	if _, _, _, ok := pt.take([]byte("cid1"), now); !ok {
		t.Fatal("first take should succeed")
	}
	if _, _, _, ok := pt.take([]byte("cid1"), now); ok {
		t.Fatal("second take should find nothing")
	}
}

func TestPeerTableAnonymousHasNoIdentity(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	pt.record([]byte("cid1"), [32]byte{7}, [32]byte{}, false, now)
	_, _, hasID, ok := pt.take([]byte("cid1"), now)
	if !ok || hasID {
		t.Fatalf("anonymous entry: ok=%v hasIdentity=%v; want ok=true hasIdentity=false", ok, hasID)
	}
}

func TestPeerTableExpiry(t *testing.T) {
	pt := newPeerTable()
	start := time.Now()
	pt.record([]byte("cid1"), [32]byte{9}, [32]byte{}, false, start)
	later := start.Add(peerKeyTTL + time.Second)
	if _, _, _, ok := pt.take([]byte("cid1"), later); ok {
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
