package tun

import "testing"

func TestSelectDefaultRouteCandidatePrefersPreviousInterfaceOnMetricTie(t *testing.T) {
	candidates := []defaultRouteCandidate{
		{index: 36, alias: "WLAN", metric: 50},
		{index: 37, alias: "WLAN 8", metric: 50},
	}

	selected, ok := selectDefaultRouteCandidate(candidates, 37)
	if !ok {
		t.Fatal("expected a selected candidate")
	}
	if selected.index != 37 {
		t.Fatalf("expected previous interface 37 to be kept on metric tie, got %d", selected.index)
	}
}

func TestSelectDefaultRouteCandidateSwitchesWhenMetricIsLower(t *testing.T) {
	candidates := []defaultRouteCandidate{
		{index: 36, alias: "WLAN", metric: 35},
		{index: 37, alias: "WLAN 8", metric: 40},
	}

	selected, ok := selectDefaultRouteCandidate(candidates, 37)
	if !ok {
		t.Fatal("expected a selected candidate")
	}
	if selected.index != 36 {
		t.Fatalf("expected lower-metric interface 36 to win, got %d", selected.index)
	}
}

func TestSelectDefaultRouteCandidateReturnsFalseWhenEmpty(t *testing.T) {
	if _, ok := selectDefaultRouteCandidate(nil, 0); ok {
		t.Fatal("expected empty candidate list to return false")
	}
}
