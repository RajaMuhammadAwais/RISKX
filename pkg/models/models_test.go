package models

import (
	"testing"
	"time"
)

func TestContentIDDeterminism(t *testing.T) {
	a := ContentID("finding", "CVE-2021-44228", "host-1", 8080)
	b := ContentID("finding", "CVE-2021-44228", "host-1", 8080)
	if a != b {
		t.Fatalf("content ID not deterministic: %q != %q", a, b)
	}
	c := ContentID("finding", "CVE-2021-44228", "host-1", 8081)
	if a == c {
		t.Fatalf("different content must yield different IDs")
	}
}

func TestContentIDPrefix(t *testing.T) {
	id := ContentID("asset", "example.com")
	if id[:6] != "asset-" {
		t.Fatalf("expected asset- prefix, got %q", id)
	}
}

func TestSuppressionActive(t *testing.T) {
	s := Suppression{
		Reason:    "planned patch",
		Owner:     "ops@example.com",
		CreatedAt: time.Now().Add(-24 * time.Hour),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	if !s.IsActive(time.Now()) {
		t.Fatal("active suppression reported inactive")
	}
	s2 := s
	s2.ExpiresAt = time.Now().Add(-1 * time.Hour)
	if s2.IsActive(time.Now()) {
		t.Fatal("expired suppression reported active")
	}
	s3 := s
	s3.Expired = true
	if s3.IsActive(time.Now().Add(-2 * time.Hour)) {
		t.Fatal("expired flag must force inactive even before expiry")
	}
}

func TestFindingHelpers(t *testing.T) {
	f := Finding{
		Evidence: []Evidence{
			{Type: "kev", Value: "CVE-2021-44228"},
			{Type: "admin_panel_exposed", Value: "port 8443"},
		},
		References: []string{"CVE-2021-44228"},
	}
	if !f.InKEV() {
		t.Fatal("InKEV false with kev evidence")
	}
	if !f.IsAdmin() {
		t.Fatal("IsAdmin false with admin_panel_exposed evidence")
	}
	if !f.ReferencesCVE("CVE-2021-44228") {
		t.Fatal("ReferencesCVE false with matching reference")
	}
	if f.ReferencesCVE("CVE-2099-00000") {
		t.Fatal("ReferencesCVE true for non-matching CVE")
	}
}

func TestFindingExposureLevel(t *testing.T) {
	f := Finding{Evidence: []Evidence{{Type: "internal", Value: "lan"}}}
	if got := f.ExposureLevel(); got != ExposureInternal {
		t.Fatalf("expected internal, got %s", got)
	}
	f.Evidence = append(f.Evidence, Evidence{Type: "internet", Value: "443"})
	if got := f.ExposureLevel(); got != ExposureInternet {
		t.Fatalf("internet must dominate internal, got %s", got)
	}
	empty := Finding{}
	if got := empty.ExposureLevel(); got != ExposureUnknown {
		t.Fatalf("no evidence must be unknown, got %s", got)
	}
}
