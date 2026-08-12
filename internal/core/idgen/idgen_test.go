package idgen

import (
	"strings"
	"testing"
)

func TestFindingIDStableAndPrefixed(t *testing.T) {
	a := FindingID("CVE-2021-44228", "host-1")
	b := FindingID("CVE-2021-44228", "host-1")
	if a != b {
		t.Fatalf("finding ID not stable: %q != %q", a, b)
	}
	if !strings.HasPrefix(a, "RISKX-") {
		t.Fatalf("expected RISKX- prefix, got %q", a)
	}
}

func TestAssetIDDistinctForDifferentContent(t *testing.T) {
	a := AssetID("domain", "example.com")
	b := AssetID("domain", "other.com")
	if a == b {
		t.Fatal("different content produced the same asset ID")
	}
}
