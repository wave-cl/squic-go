package squic

import "testing"

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

	sc := newServerConn(nil, priv, nil, 0)
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
