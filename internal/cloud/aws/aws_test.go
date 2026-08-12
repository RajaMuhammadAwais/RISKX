package aws

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSigV4AgainstAWSSDK verifies the signing implementation against the
// AWS SDK (botocore, v1.43.62) signer for identical inputs. Botocore is the
// reference implementation used by AWS services to verify signatures, so
// matching it is the acceptance criterion. Expected values were produced
// with botocore.auth.SigV4Auth on 2026-08-12 (see
// docs/research/schemas/_ref_sigv4.py).
func TestSigV4AgainstAWSSDK(t *testing.T) {
	const (
		secret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		accessKey = "AKIAIOSFODNN7EXAMPLE"
		method    = http.MethodGet
		host      = "iam.amazonaws.com"
		uri       = "/"
		query     = "Action=ListUsers&Version=2010-05-08"
		region    = "us-east-1"
		service   = "iam"
	)
	now := parseTime("2015-08-30T12:36:00Z")
	auth, amzDate, hash := Sign(method, host, uri, query, nil, accessKey, secret, region, service, now)

	// Header values: botocore reference output for the same inputs.
	if amzDate != "20150830T123600Z" {
		t.Errorf("x-amz-date = %q, want 20150830T123600Z", amzDate)
	}
	if hash != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("payload hash must be the SHA-256 of the empty string")
	}
	wantAuth := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date, Signature=dad145687cde2dbf9684236b386711320b5997e4d31b3b5efe762858f46cc755"
	if auth != wantAuth {
		t.Errorf("authorization header mismatch:\ngot : %s\nwant: %s", auth, wantAuth)
	}
	// Internal consistency check: re-derive the signature from the canonical
	// request we compute and confirm the path still terminates at the same
	// value (guards against silent drift in the signing pipeline).
	canonical := "GET\n/\n" + query + "\nhost:" + host + "\nx-amz-date:" + amzDate + "\n\nhost;x-amz-date\n" + hash
	crHash := hashHex([]byte(canonical))
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n20150830/us-east-1/iam/aws4_request\n" + crHash
	sig := hmacHex(deriveSigningKey(secret, "20150830", region, service), []byte(stringToSign))
	if sig != "dad145687cde2dbf9684236b386711320b5997e4d31b3b5efe762858f46cc755" {
		t.Errorf("internal signature derivation mismatch: %s", sig)
	}
}

func parseTime(s string) time.Time { return timeOf(s) }

// timeOf parses a fixed RFC3339 time for tests.
func timeOf(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// canonicalization covers query-parameter ordering and percent-encoding.
func TestCanonicalizeQuery(t *testing.T) {
	got := canonicalizeQuery("Version=2010-05-08&Action=ListUsers")
	want := "Action=ListUsers&Version=2010-05-08"
	if got != want {
		t.Errorf("canonicalizeQuery = %q, want %q", got, want)
	}
}

// query() signs against the request host; verify the Authorization header is
// sent and the signed canonical request includes the real query.
func TestClientSendsSignedRequest(t *testing.T) {
	var receivedAuth, receivedDate, receivedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedDate = r.Header.Get("x-amz-date")
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/ro</Arn><UserId>ABCDE12345</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(strings.TrimPrefix(srv.URL, "http://"), "https://")
	client := NewClientWithOptions(Config{
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region: "us-east-1",
	}, func(c *Client) {
		c.http = srv.Client()
		c.testScheme = "http"
	})
	id, err := client.query(context.Background(), host, "sts", "GetCallerIdentity", nil)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if receivedAuth == "" || receivedDate == "" {
		t.Error("signed request must carry Authorization and x-amz-date headers")
	}
	if !strings.Contains(receivedQuery, "Action=GetCallerIdentity") {
		t.Errorf("query missing Action parameter: %s", receivedQuery)
	}
	if !strings.Contains(string(id), "123456789012") {
		t.Error("response body not returned")
	}
}

// API error surfaces as an explicit RISKX error with the status code.
func TestClientAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Forbidden"))
	}))
	defer srv.Close()
	client := NewClientWithOptions(Config{
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region: "us-east-1",
	}, func(c *Client) {
		c.http = srv.Client()
		c.testScheme = "http"
	})
	_, err := client.query(context.Background(), strings.TrimPrefix(strings.TrimPrefix(srv.URL, "http://"), "https://"), "sts", "GetCallerIdentity", nil)
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error must report status code: %v", err)
	}
}

// ConfigFromEnv: missing credentials are an explicit error.
func TestConfigFromEnvMissing(t *testing.T) {
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		_ = os.Unsetenv(key)
	}
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("expected explicit error without credentials")
	}
}

// XML projections: small hand-written fixtures (no recorded network traffic —
// schema shapes verified against the published AWS API reference docs).
const fixtureSTS = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/ro</Arn><UserId>ABCDE12345</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`

const fixtureEC2 = `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<reservationSet><item><instancesSet><item><instanceId>i-0abc123</instanceId><instanceType>t3.micro</instanceType><instanceState><name>running</name></instanceState><ipAddress>203.0.113.10</ipAddress><privateIpAddress>10.0.0.5</privateIpAddress><launchTime>2026-01-02T03:04:05Z</launchTime></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`

const fixtureS3 = `<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets><Bucket><Name>bucket-one</Name><CreationDate>2026-01-02T03:04:05Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>`

const fixtureIAM = `<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListUsersResult><Users><member><UserName>alice</UserName><UserId>UIDALICE</UserId><Arn>arn:aws:iam::123456789012:user/alice</Arn><CreateDate>2026-01-02T03:04:05Z</CreateDate></member></Users><IsTruncated>false</IsTruncated></ListUsersResult></ListUsersResponse>`

func TestParseSTS(t *testing.T) {
	var r stsResponse
	if err := xml.Unmarshal([]byte(fixtureSTS), &r); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Result.Acct != "123456789012" {
		t.Errorf("account = %q, want 123456789012", r.Result.Acct)
	}
}

func TestParseEC2(t *testing.T) {
	var r ec2Response
	if err := xml.Unmarshal([]byte(fixtureEC2), &r); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(r.Reservations) == 0 || r.Reservations[0].Instances[0].InstanceID != "i-0abc123" {
		t.Error("instance parse failed")
	}
}

func TestParseS3(t *testing.T) {
	var r s3Response
	if err := xml.Unmarshal([]byte(fixtureS3), &r); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(r.Buckets.Items) != 1 || r.Buckets.Items[0].Name != "bucket-one" {
		t.Error("bucket parse failed")
	}
}

func TestParseIAM(t *testing.T) {
	var r iamResponse
	if err := xml.Unmarshal([]byte(fixtureIAM), &r); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(r.ListResult.Users.Items) != 1 || r.ListResult.Users.Items[0].UserName != "alice" {
		t.Error("user parse failed")
	}
	if r.ListResult.IsTruncated != "false" {
		t.Error("isTruncated must be false for single-page fixture")
	}
}

// ToAssets maps discovered resources to canonical assets with cloud provenance.
func TestToAssetsMapping(t *testing.T) {
	assets := ToAssets(
		Identity{Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/ro"},
		[]EC2Instance{{InstanceID: "i-0abc123", PublicIP: "203.0.113.10", State: "running"},
			{InstanceID: "i-0def456", State: "running"}},
		[]S3Bucket{{Name: "bucket-one"}},
		[]IAMIdentity{{UserName: "alice", UserID: "UIDALICE"}},
	)
	if len(assets) != 4 {
		t.Fatalf("expected 4 assets, got %d", len(assets))
	}
	byKind := map[string]int{}
	for _, a := range assets {
		byKind[string(a.Kind)]++
		if a.Provenance.Source != "aws_discovery" {
			t.Errorf("asset %s provenance source must be aws_discovery", a.ID)
		}
		if a.Provenance.Confidence != "high" {
			t.Errorf("asset %s confidence must be high (direct API observation)", a.ID)
		}
		if a.ID == "" {
			t.Error("asset must have a stable content-addressed ID")
		}
	}
	if byKind["cloud_resource"] != 3 || byKind["identity"] != 1 {
		t.Errorf("kind mapping mismatch: %v", byKind)
	}
	// Public IP maps to internet exposure; absence maps to internal.
	for _, a := range assets {
		if a.Value == "i-0abc123" && a.Exposure != "internet" {
			t.Errorf("i-0abc123 exposure = %s, want internet", a.Exposure)
		}
		if a.Value == "i-0def456" && a.Exposure != "internal" {
			t.Errorf("i-0def456 exposure = %s, want internal", a.Exposure)
		}
	}
}

// nextTokenFrom covers EC2 pagination extraction.
func TestNextTokenFrom(t *testing.T) {
	body := []byte(`<DescribeInstancesResponse><nextToken>page2token</nextToken></DescribeInstancesResponse>`)
	if got := nextTokenFrom(body); got != "page2token" {
		t.Errorf("nextTokenFrom = %q, want page2token", got)
	}
	if got := nextTokenFrom([]byte(`<x/>`)); got != "" {
		t.Errorf("nextTokenFrom with no token must be empty, got %q", got)
	}
}
