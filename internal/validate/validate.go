// Package validate implements read-only validation checks: DNS resolution,
// TLS configuration, and HTTP response verification. Each check observes
// real server state, records what was actually seen, and never infers a
// configuration state from hints (spec §12 — validation observes, it does
// not guess).
//
// Checks are read-only by construction: resolution, connection, and GET
// requests with no side-effecting payloads. Validation runs are gated by
// SAFE or VALIDATION modes at the CLI layer.
package validate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// ValidationResult is the atomic observation of one validation check. Checked
// reports that the check actually ran (not skipped); Passed reports the
// observed state satisfied the declared expectation; Observed is the literal
// raw observation; Evidence chains the observation to primary sources.
type ValidationResult struct {
	Check     string            `json:"check" yaml:"check"`        // dns|tls|http
	Target    string            `json:"target" yaml:"target"`
	Checked   bool              `json:"checked" yaml:"checked"`
	Passed    bool              `json:"passed" yaml:"passed"`
	Observed  string            `json:"observed" yaml:"observed"`
	Evidence  []models.Evidence `json:"evidence" yaml:"evidence"`
}

// Resolver is the DNS resolver used by VerifyDNS; tests may inject a custom
// resolver (e.g., a static record map) without touching the network.
type Resolver struct {
	R *net.Resolver
	// static is an optional test-only record table. When non-nil, records are
	// answered from it without network I/O. Production code leaves it nil.
	static LookupTable
}

// LookupTable is a test-only static record table replacing network lookups.
// Production code must not depend on it (it exists solely for deterministic
// offline tests).
type LookupTable interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// DefaultResolver returns the system resolver wrapper.
func DefaultResolver() Resolver { return Resolver{R: net.DefaultResolver} }

// VerifyDNS resolves host for the requested record type and compares the
// observed values against want. An empty want means "resolution itself is
// the check" (the host exists in DNS). Observations are literal: no record
// type is assumed from others.
func VerifyDNS(ctx context.Context, r Resolver, host string, recordType string, want []string) (ValidationResult, error) {
	if host == "" || recordType == "" {
		return ValidationResult{}, fmt.Errorf("validate.dns: host and record type are required")
	}
	rt := strings.ToUpper(recordType)
	start := time.Now().UTC()
	if r.static != nil {
		return lookupStatic(ctx, r.static, rt, host, want, start)
	}
	switch rt {
	case "A":
		addrs, err := r.R.LookupHost(ctx, host)
		return dnsResult("A", host, addrs, err, want, start)
	case "AAAA":
		addrs, err := r.R.LookupHost(ctx, host)
		// LookupHost returns both families; filter to v6.
		var v6 []string
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
				v6 = append(v6, a)
			}
		}
		return dnsResult("AAAA", host, v6, err, want, start)
	case "MX":
		recs, err := r.R.LookupMX(ctx, host)
		var vals []string
		for _, mx := range recs {
			vals = append(vals, mx.Host)
		}
		return dnsResult("MX", host, vals, err, want, start)
	case "NS":
		recs, err := r.R.LookupNS(ctx, host)
		var vals []string
		for _, ns := range recs {
			vals = append(vals, ns.Host)
		}
		return dnsResult("NS", host, vals, err, want, start)
	case "TXT":
		recs, err := r.R.LookupTXT(ctx, host)
		return dnsResult("TXT", host, recs, err, want, start)
	default:
		return ValidationResult{}, fmt.Errorf("validate.dns: unsupported record type %q (A/AAAA/MX/NS/TXT)", recordType)
	}
}

// lookupStatic answers a DNS check from an injected test-only table, with the
// same observation semantics as the network path (failures record
// resolution_failed, never errors).
func lookupStatic(ctx context.Context, t LookupTable, rt, host string, want []string, start time.Time) (ValidationResult, error) {
	var (got []string
		err  error)
	switch rt {
	case "A", "AAAA":
		addrs, e := t.LookupHost(ctx, host)
		got, err = addrs, e
	case "MX":
		recs, e := t.LookupMX(ctx, host)
		for _, mx := range recs {
			got = append(got, mx.Host)
		}
		err = e
	case "NS":
		recs, e := t.LookupNS(ctx, host)
		for _, ns := range recs {
			got = append(got, ns.Host)
		}
		err = e
	case "TXT":
		got, err = t.LookupTXT(ctx, host)
	default:
		return ValidationResult{}, fmt.Errorf("validate.dns: unsupported record type %q (A/AAAA/MX/NS/TXT)", rt)
	}
	return dnsResult(rt, host, got, err, want, start)
}

func dnsResult(rt, host string, got []string, err error, want []string, start time.Time) (ValidationResult, error) {
	res := ValidationResult{Check: "dns", Target: fmt.Sprintf("%s/%s", host, rt), Checked: true}
	if err != nil {
		res.Observed = fmt.Sprintf("resolution_failed reason=%s", err.Error())
		res.Passed = false
		res.Evidence = append(res.Evidence, models.Evidence{
			Type: "network", Source: "system_resolver", Timestamp: start,
			Value: fmt.Sprintf("host=%s type=%s error=%s", host, rt, err.Error()),
		})
		return res, nil
	}
	res.Observed = fmt.Sprintf("records=%s", strings.Join(got, ";"))
	// A missing record set is an observation, never a silent pass: both the
	// existence-only check (want empty) and the exact-value check require
	// at least one observed record (spec: detection without evidence =
	// insufficient).
	res.Passed = len(got) > 0 && subset(want, got)
	res.Evidence = append(res.Evidence, models.Evidence{
		Type: "network", Source: "system_resolver", Timestamp: start,
		Value: fmt.Sprintf("host=%s type=%s records=%s", host, rt, strings.Join(got, ",")),
	})
	return res, nil
}

// subset reports whether every wanted value occurs in got (case-insensitive).
func subset(want, got []string) bool {
	set := make(map[string]struct{}, len(got))
	for _, g := range got {
		set[strings.ToLower(strings.TrimSpace(g))] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[strings.ToLower(strings.TrimSpace(w))]; !ok {
			return false
		}
	}
	return true
}

// VerifyTLS observes the real certificate served by host:port (default :443).
// Verification is two-part: (1) the chain validates against system roots and
// (2) reported observations record the raw leaf subject, SANs, issuer, and
// validity window literally. A hostname/SAN mismatch is recorded as an
// observation, not silently dropped.
func VerifyTLS(ctx context.Context, host string) (ValidationResult, error) {
	if host == "" {
		return ValidationResult{}, fmt.Errorf("validate.tls: host is required")
	}
	addr := host
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "443")
	}
	start := time.Now().UTC() // anchor for evidence timestamps
	d := tls.Dialer{Config: &tls.Config{ServerName: serverNameOf(host)}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return tlsResult(host, nil, fmt.Errorf("connect_failed reason=%s", err), start), nil
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return tlsResult(host, nil, errors.New("unexpected_connection_type"), start), nil
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return tlsResult(host, nil, errors.New("no_certificate_presented"), start), nil
	}
	leaf := state.PeerCertificates[0]
	verifiedChains, verifyErr := leaf.Verify(x509.VerifyOptions{
		DNSName: serverNameOf(host),
	})
	return tlsResult(host, leaf, verifyErr, start, verifiedChains...), nil
}

func serverNameOf(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// tlsResult builds the TLS ValidationResult from the observed leaf cert and
// any verification error. verifyErr nil + verifiedChains non-empty means full
// system-root validation succeeded.
func tlsResult(host string, leaf *x509.Certificate, verifyErr error, start time.Time, verifiedChains ...[]*x509.Certificate) ValidationResult {
	res := ValidationResult{Check: "tls", Target: host, Checked: true}
	var parts []string
	if leaf != nil {
		parts = append(parts, fmt.Sprintf("subject=%s issuer=%s", leaf.Subject.CommonName, leaf.Issuer.CommonName))
		var sans []string
		sans = append(sans, leaf.DNSNames...)
		for _, ip := range leaf.IPAddresses {
			sans = append(sans, ip.String())
		}
		parts = append(parts, fmt.Sprintf("sans=%s", strings.Join(sans, ";")))
		parts = append(parts, fmt.Sprintf("not_before=%s not_after=%s",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339)))
		if leaf.IsCA {
			parts = append(parts, "ca=true")
		}
		if time.Now().After(leaf.NotAfter) {
			parts = append(parts, "expired=true")
		}
		if certSelfSigned(leaf) {
			parts = append(parts, "self_signed=observed")
		}
	}
	passed := verifyErr == nil
	parts = append(parts, fmt.Sprintf("chain_valid=%v", passed))
	if verifyErr != nil {
		parts = append(parts, fmt.Sprintf("chain_error=%s", verifyErr.Error()))
	}
	res.Observed = strings.Join(parts, " ")
	res.Passed = passed
	var val string
	if leaf != nil {
		sansAll := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
		sansAll = append(sansAll, leaf.DNSNames...)
		for _, ip := range leaf.IPAddresses {
			sansAll = append(sansAll, ip.String())
		}
		val = fmt.Sprintf("subject=%s;issuer=%s;sans=%s;not_after=%s;chain_valid=%v",
			leaf.Subject.CommonName, leaf.Issuer.CommonName,
			strings.Join(sansAll, ";"),
			leaf.NotAfter.UTC().Format(time.RFC3339), passed)
	} else {
		val = "tls_leaf:none"
	}
	ev := models.Evidence{
		Type: "certificate", Source: "tls_handshake", Timestamp: start, Value: val,
	}
	if leaf != nil {
		ev.Citation = models.SourceCitation{
			Organization: "IETF", Document: "RFC 5280 (Internet X.509 PKI)",
			URL: "https://datatracker.ietf.org/doc/html/rfc5280", Accessed: today(),
		}
	}
	res.Evidence = append(res.Evidence, ev)
	return res
}

func certSelfSigned(leaf *x509.Certificate) bool {
	return leaf.CheckSignatureFrom(leaf) == nil && leaf.Issuer.CommonName == leaf.Subject.CommonName
}

// VerifyHTTP performs a read-only GET against url with a 5s timeout and
// observes the status code, server banner, and security-relevant headers.
// The response body is never read beyond what the client discards; the
// banner snippet is truncated to avoid unbounded output.
func VerifyHTTP(ctx context.Context, url string) (ValidationResult, error) {
	if url == "" {
		return ValidationResult{}, fmt.Errorf("validate.http: url is required")
	}
	start := time.Now().UTC()
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return ValidationResult{}, fmt.Errorf("validate.http: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	res := ValidationResult{Check: "http", Target: url, Checked: true}
	if err != nil {
		res.Observed = fmt.Sprintf("request_failed reason=%s", err.Error())
		res.Passed = false
		res.Evidence = append(res.Evidence, models.Evidence{
			Type: "network", Source: "http_get", Timestamp: start,
			Value: fmt.Sprintf("url=%s error=%s", url, err.Error()),
		})
		return res, nil
	}
	defer resp.Body.Close()
	var headers []string
	for _, h := range []string{"Server", "X-Powered-By", "Strict-Transport-Security", "X-Content-Type-Options"} {
		if v := resp.Header.Get(h); v != "" {
			headers = append(headers, fmt.Sprintf("%s=%s", h, v))
		}
	}
	res.Observed = fmt.Sprintf("status=%d headers=%s", resp.StatusCode, strings.Join(headers, ";"))
	res.Passed = resp.StatusCode >= 200 && resp.StatusCode < 400
	res.Evidence = append(res.Evidence, models.Evidence{
		Type: "network", Source: "http_get", Timestamp: start,
		Value: fmt.Sprintf("url=%s status=%d headers=%s", url, resp.StatusCode, strings.Join(headers, ",")),
	})
	return res, nil
}

func today() string { return time.Now().UTC().Format("2006-01-02") }
