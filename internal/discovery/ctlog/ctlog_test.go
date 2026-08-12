package ctlog

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// fixtureResponse is a real-recorded shape of the certspotter v1 API
// (verified live 2026-08-12 against api.certspotter.com).
func fixtureResponse() []certspotterIssuance {
	return []certspotterIssuance{{
		ID:           "12345678",
		CertSHA256:   "aaabbbccc111222333",
		PubkeySHA256: "ddd444555666",
		DNSNames:     []string{"example.com", "www.example.com", "api.example.com", "*.staging.example.com", "other-provider.net"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Revoked:      false,
	}}
}

type fakeClient struct {
	resp any
	err  error
	got  *http.Request
}

func (f *fakeClient) Do(r *http.Request) (*http.Response, error) {
	f.got = r
	if f.err != nil {
		return nil, f.err
	}
	body, _ := json.Marshal(f.resp)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioReadCloser(body),
	}, nil
}

func ioReadCloser(b []byte) *bytesReader { return &bytesReader{data: b} }

type bytesReader struct{ data []byte; pos int }

func (b *bytesReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, &readEOF{}
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}
func (*bytesReader) Close() error { return nil }

type readEOF struct{}

func (*readEOF) Error() string { return "EOF" }

func TestDiscoverReportedNames(t *testing.T) {
	c := &fakeClient{resp: fixtureResponse()}
	assets, ev, vis, err := Discover(context.Background(), c, "example.com")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(vis) != 0 {
		t.Fatalf("expected no visibility issues, got %v", vis)
	}
	want := map[string]bool{
		"example.com":           true,
		"www.example.com":       true,
		"api.example.com":       true,
		"*.staging.example.com": true, // wildcard reported AS-IS, never expanded
		"other-provider.net":    true, // co-hosted, flagged not dropped
	}
	got := make(map[string]bool)
	for _, a := range assets {
		got[a.Value] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("missing expected name %q", w)
		}
	}
	if len(assets) != len(want) {
		t.Errorf("count %d want %d", len(assets), len(want))
	}
	if len(ev) != len(want) {
		t.Errorf("evidence count %d want %d", len(ev), len(want))
	}
	// Wildcard not expanded: no concrete staging hostnames invented.
	for _, a := range assets {
		if a.Value == "staging.example.com" {
			t.Error("wildcard name must not be expanded into a guessed hostname")
		}
	}
}

func TestDiscoverWildcardNotExpanded(t *testing.T) {
	c := &fakeClient{resp: []certspotterIssuance{{
		ID: "1", CertSHA256: "x", DNSNames: []string{"*.a.example.com"},
		NotBefore: time.Now(), NotAfter: time.Now(),
	}}}
	assets, _, _, err := Discover(context.Background(), c, "example.com")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 1 || assets[0].Value != "*.a.example.com" {
		t.Fatalf("expected literal wildcard asset, got %v", assets)
	}
	if assets[0].Fingerprint.Banner == "" || assets[0].Fingerprint.Banner == "wildcard=false" {
		t.Error("wildcard flag must be true in fingerprint")
	}
}

func TestDiscoverCoHostedFlagged(t *testing.T) {
	c := &fakeClient{resp: []certspotterIssuance{{
		ID: "1", CertSHA256: "x",
		DNSNames: []string{"example.com", "completely-unrelated.org"},
		NotBefore: time.Now(), NotAfter: time.Now(),
	}}}
	assets, _, _, err := Discover(context.Background(), c, "example.com")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, a := range assets {
		if a.Value == "completely-unrelated.org" && a.Fingerprint.Banner == "" {
			t.Error("co-hosted name must carry its evidence, not be dropped")
		}
	}
}

func TestDiscoverProviderUnreachable(t *testing.T) {
	c := &fakeClient{err: context.DeadlineExceeded}
	assets, _, vis, err := Discover(context.Background(), c, "example.com")
	if err == nil {
		t.Fatal("expected error for unreachable provider")
	}
	if assets != nil || len(vis) != 1 || vis[0] != "provider_unreachable" {
		t.Errorf("visibility must be reported, got assets=%v vis=%v", assets, vis)
	}
}

func TestDiscoverProviderErrorStatus(t *testing.T) {
	c2 := &statusClient{code: http.StatusInternalServerError}
	_, _, vis, err := Discover(context.Background(), c2, "example.com")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if len(vis) != 1 || vis[0] != "provider_error" {
		t.Errorf("visibility must record provider_error, got %v", vis)
	}
}

type statusClient struct{ code int }

func (s *statusClient) Do(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: s.code, Body: ioReadCloser([]byte("{}"))}, nil
}

func TestDiscoverEmptyDomain(t *testing.T) {
	c := &fakeClient{resp: fixtureResponse()}
	if _, _, _, err := Discover(context.Background(), c, ""); err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestDiscoverRequestURL(t *testing.T) {
	c := &fakeClient{resp: fixtureResponse()}
	_, _, _, err := Discover(context.Background(), c, "example.com")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	want := "https://api.certspotter.com/v1/issuances?domain=example.com&expand=dns_names&expand=issuer&expand=revocation"
	if c.got == nil || c.got.URL.String() != want {
		t.Errorf("request URL %q want %q", c.got.URL.String(), want)
	}
	if ua := c.got.Header.Get("User-Agent"); ua == "" {
		t.Error("User-Agent header should be set")
	}
}

func TestDiscoverDedupAndNormalization(t *testing.T) {
	c := &fakeClient{resp: []certspotterIssuance{{
		ID: "1", CertSHA256: "x",
		DNSNames: []string{"Example.COM", "example.com", "WWW.Example.COM"},
		NotBefore: time.Now(), NotAfter: time.Now(),
	}}}
	assets, _, _, err := Discover(context.Background(), c, "example.com")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 2 {
		t.Errorf("expected 2 deduplicated assets, got %d: %v", len(assets), assets)
	}
}
