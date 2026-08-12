// Package aws implements read-only AWS cloud discovery without the AWS SDK:
// SigV4 signing and the XML Query APIs for STS, EC2, S3, and IAM.
//
// Source of truth: the SigV4 algorithm is specified in the AWS Signature
// Version 4 documentation
// (https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html);
// this implementation follows the canonical GET-request example steps:
// canonical request → string to sign → signing key → signature. All cloud
// discovery is read-only (Describe/List/GetCallerIdentity only).
package aws

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const aws4Request = "aws4_request"

// Sign produces the Authorization header, the x-amz-date header, and the
// payload hash for a signed AWS request (query API GET style). The payload
// hash for unsigned query requests is the fixed constant for empty payloads,
// per the AWS examples.
func Sign(method, host, uri, query string, body []byte, accessKey, secretKey, region, service string, now time.Time) (authHeader, amzDate, payloadHash string) {
	amzDate = now.UTC().Format("20060102T150405Z")
	dateStamp := amzDate[:8]
	credentialScope := fmt.Sprintf("%s/%s/%s/%s", dateStamp, region, service, aws4Request)

	payloadHash = hashHex(body)

	canonicalQuery := canonicalizeQuery(query)
	signedHeaders := "host;x-amz-date"
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-date:%s\n", host, amzDate)
	canonicalRequest := strings.Join([]string{
		method, uri, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")
	canonicalRequestHash := hashHex([]byte(canonicalRequest))

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credentialScope, canonicalRequestHash,
	}, "\n")

	signingKey := deriveSigningKey(secretKey, dateStamp, region, service)
	signature := hmacHex(signingKey, []byte(stringToSign))

	authHeader = fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature)
	return authHeader, amzDate, payloadHash
}

// NewSignedRequest builds an http.Request with the SigV4 Authorization and
// x-amz-date headers applied. The request is returned without sending it —
// sending happens in the client layer.
func NewSignedRequest(method, urlStr string, body []byte, accessKey, secretKey, region, service string, now time.Time) (*http.Request, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("aws.sign: invalid url: %w", err)
	}
	// Query API hosts are endpoint-specific (e.g., ec2.us-east-1.amazonaws.com)
	// but the signing host header is the request host; for STS/IAM use the
	// global host.
	auth, amzDate, _ := Sign(method, u.Host, u.Path, u.RawQuery, body,
		accessKey, secretKey, region, service, now)
	req, err := http.NewRequestWithContext(context.Background(), method, urlStr, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("aws.sign: %w", err)
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", hashHex(body))
	return req, nil
}

func canonicalizeQuery(query string) string {
	params, err := url.ParseQuery(query)
	if err != nil {
		return query
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		for j, v := range params[k] {
			if j > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}

func deriveSigningKey(key, date, region, service string) []byte {
	kDate := hmacSHA([]byte("AWS4"+key), []byte(date))
	kRegion := hmacSHA(kDate, []byte(region))
	kService := hmacSHA(kRegion, []byte(service))
	return hmacSHA(kService, []byte(aws4Request))
}

func hmacSHA(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func hmacHex(key, data []byte) string {
	return hex.EncodeToString(hmacSHA(key, data))
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
