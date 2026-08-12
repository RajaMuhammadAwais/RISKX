package aws

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// Model version for cloud discovery outputs.
const ModelVersion = "cloud-v1"

const (
	defaultRegion = "us-east-1"
)

// Config carries readonly AWS credentials from environment. Deliberately
// minimal: only env-based configuration is supported (no config-file
// parsing), matching the read-only, explicit-credential posture required by
// the CLI contract.
type Config struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
}

// ConfigFromEnv builds a Config from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
// / AWS_REGION. Missing credentials are an explicit error (never an anonymous
// fallback): anonymous access to these APIs is not a discovery capability.
func ConfigFromEnv() (Config, error) {
	ak := os.Getenv("AWS_ACCESS_KEY_ID")
	sk := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if ak == "" || sk == "" {
		return Config{}, errs.New("input", "aws.config",
		"aws credentials not configured: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = defaultRegion
	}
	return Config{AccessKeyID: ak, SecretAccessKey: sk, Region: region}, nil
}

// Client performs read-only AWS discovery over the XML Query APIs. Only the
// following actions are supported, all read-only: STS GetCallerIdentity,
// EC2 DescribeInstances, S3 ListBuckets, IAM ListUsers (paginated).
type Client struct {
	cfg        Config
	http       *http.Client
	testScheme string
	received   time.Time
}

// NewClient builds a discovery client from the given config.
func NewClient(cfg Config) *Client {
	return &Client{
		cfg: cfg,
		http: defaultHTTPClient(),
	}
}

// WithHTTPClient is a test hook: tests inject an httptest.Server transport so
// no real AWS traffic is generated. Production code must not use it.
func WithHTTPClient(h *http.Client) ClientOption { return func(c *Client) { c.http = h } }

// ClientOption configures optional Client behaviour.
type ClientOption func(*Client)

// NewClientWithOptions builds a discovery client with functional options.
func NewClientWithOptions(cfg Config, opts ...ClientOption) *Client {
	c := &Client{cfg: cfg, http: defaultHTTPClient(), testScheme: ""}
	for _, o := range opts {
		o(c)
	}
	return c
}

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// testScheme, when non-empty, overrides the default "https" scheme in query.
// It exists solely for httptest-backed unit tests; production code leaves it
// empty.

// Identity is the STS GetCallerIdentity observation.
type Identity struct {
	Account string `json:"account" yaml:"account"`
	Arn     string `json:"arn" yaml:"arn"`
	UserID  string `json:"user_id" yaml:"user_id"`
}

// EC2Instance is one observed EC2 instance (DescribeInstances projection).
type EC2Instance struct {
	InstanceID     string   `json:"instance_id" yaml:"instance_id"`
	InstanceType   string   `json:"instance_type" yaml:"instance_type"`
	State          string   `json:"state" yaml:"state"`
	Platform       string   `json:"platform" yaml:"platform"`
	PublicIP       string   `json:"public_ip" yaml:"public_ip"`
	PrivateIP      string   `json:"private_ip" yaml:"private_ip"`
	LaunchTime     string   `json:"launch_time" yaml:"launch_time"`
	Tags           []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	SecurityGroups []string `json:"security_groups,omitempty" yaml:"security_groups,omitempty"`
}

// S3Bucket is one observed S3 bucket (ListBuckets projection).
type S3Bucket struct {
	Name         string `json:"name" yaml:"name"`
	CreationDate string `json:"creation_date" yaml:"creation_date"`
}

// IAMIdentity is one observed IAM user (ListUsers projection).
type IAMIdentity struct {
	UserName string `json:"user_name" yaml:"user_name"`
	UserID   string `json:"user_id" yaml:"user_id"`
	Arn      string `json:"arn" yaml:"arn"`
	CreateDate string `json:"create_date" yaml:"create_date"`
}

// STS XML responses (GetCallerIdentity).
type stsResponse struct {
	XMLName xml.Name `xml:"GetCallerIdentityResponse"`
	Result  struct {
		ARN    string `xml:"Arn"`
		UserID string `xml:"UserId"`
		Acct   string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
}

// EC2 XML responses (DescribeInstances).
type ec2Response struct {
	XMLName    xml.Name `xml:"DescribeInstancesResponse"`
	RequestID  string   `xml:"requestId"`
	Reservations []struct {
		Instances []struct {
			InstanceID   string `xml:"instanceId"`
			InstanceType string `xml:"instanceType"`
			State        struct {
				Name string `xml:"name"`
			} `xml:"instanceState"`
			Platform    string `xml:"platform"`
			PublicIP    string `xml:"ipAddress"`
			PrivateIP   string `xml:"privateIpAddress"`
			LaunchTime  string `xml:"launchTime"`
			SecGroups   struct {
				Items []struct{ GroupName string } `xml:"item"`
			} `xml:"groupSet"`
			Tags struct {
				Items []struct {
					Key   string `xml:"key"`
					Value string `xml:"value"`
				} `xml:"item"`
			} `xml:"tagSet"`
		} `xml:"instancesSet>item"`
	} `xml:"reservationSet>item"`
}

// S3 XML responses (ListBuckets).
type s3Response struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Buckets struct {
		Items []struct {
			Name         string `xml:"Name"`
			CreationDate string `xml:"CreationDate"`
		} `xml:"Bucket"`
	} `xml:"Buckets"`
}

// IAM XML responses (ListUsers).
type iamResponse struct {
	XMLName     xml.Name `xml:"ListUsersResponse"`
	ListResult  struct {
		Users struct {
			Items []struct {
				UserName   string `xml:"UserName"`
				UserID     string `xml:"UserId"`
				Arn        string `xml:"Arn"`
				CreateDate string `xml:"CreateDate"`
			} `xml:"member"`
		} `xml:"Users"`
		IsTruncated string `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
	} `xml:"ListUsersResult"`
}

// query runs a signed AWS query-API request and decodes the XML body.
func (c *Client) query(ctx context.Context, endpoint, service, action string, params map[string]string) ([]byte, error) {
	q := urlValues(params)
	q.Set("Version", apiVersion(service))
	q.Set("Action", action)
	scheme := c.testScheme
	if scheme == "" {
		scheme = "https"
	}
	reqURL := fmt.Sprintf("%s://%s?%s", scheme, strings.TrimSuffix(endpoint, "/"), q.Encode())
	req, err := NewSignedRequest(http.MethodGet, reqURL, nil, c.cfg.AccessKeyID,
		c.cfg.SecretAccessKey, c.cfg.Region, service, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("aws.sign: %w", err)
	}
	req = req.WithContext(ctx)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aws.request %s: %w", action, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("aws.read %s: %w", action, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errs.New("internal", "aws.api",
			fmt.Sprintf("%s returned %d: %s — check credentials, region, and read-only permissions",
				action, resp.StatusCode, firstLine(string(body))))
	}
	c.received = time.Now().UTC()
	return body, nil
}

func apiVersion(service string) string {
	switch service {
	case "sts":
		return "2011-06-15"
	case "ec2":
		return "2016-11-15"
	case "s3":
		return "2006-03-01"
	case "iam":
		return "2010-05-08"
	default:
		return ""
	}
}

func urlValues(m map[string]string) url.Values {
	q := url.Values{}
	for k, v := range m {
		q.Set(k, v)
	}
	return q
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// Whoami returns the STS GetCallerIdentity observation (no IAM permissions
// required). It is the primary evidence that credentials are valid and
// scoped.
func (c *Client) Whoami(ctx context.Context) (Identity, error) {
	endpoint := "sts.amazonaws.com"
	body, err := c.query(ctx, endpoint, "sts", "GetCallerIdentity", nil)
	if err != nil {
		return Identity{}, err
	}
	var r stsResponse
	if err := xml.Unmarshal(body, &r); err != nil {
		return Identity{}, fmt.Errorf("aws.parse sts: %w", err)
	}
	return Identity{Account: r.Result.Acct, Arn: r.Result.ARN, UserID: r.Result.UserID}, nil
}

// Instances lists EC2 instances in the configured region (DescribeInstances,
// paginated via NextToken).
func (c *Client) Instances(ctx context.Context) ([]EC2Instance, error) {
	endpoint := fmt.Sprintf("ec2.%s.amazonaws.com", c.cfg.Region)
	var out []EC2Instance
	var nextToken string
	for {
		params := map[string]string{"MaxResults": "1000"}
		if nextToken != "" {
			params["NextToken"] = nextToken
		}
		body, err := c.query(ctx, endpoint, "ec2", "DescribeInstances", params)
		if err != nil {
			return nil, err
		}
		var r ec2Response
		if err := xml.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("aws.parse ec2: %w", err)
		}
		for _, res := range r.Reservations {
			for _, inst := range res.Instances {
				var tags, sgs []string
				for _, t := range inst.Tags.Items {
					tags = append(tags, t.Key+"="+t.Value)
				}
				for _, g := range inst.SecGroups.Items {
					sgs = append(sgs, g.GroupName)
				}
				out = append(out, EC2Instance{
					InstanceID:     inst.InstanceID,
					InstanceType:   inst.InstanceType,
					State:          inst.State.Name,
					Platform:       inst.Platform,
					PublicIP:       inst.PublicIP,
					PrivateIP:      inst.PrivateIP,
					LaunchTime:     inst.LaunchTime,
					Tags:           tags,
					SecurityGroups: sgs,
				})
			}
		}
		// EC2 DescribeInstances pagination: NextToken present means more pages.
		if nt := nextTokenFrom(body); nt == "" {
			break
		} else {
			nextToken = nt
		}
	}
	return out, nil
}

// Buckets lists S3 buckets (ListBuckets; unpaginated per AWS docs — the
// result set is always the full bucket list).
func (c *Client) Buckets(ctx context.Context) ([]S3Bucket, error) {
	endpoint := "s3.amazonaws.com"
	body, err := c.query(ctx, endpoint, "s3", "ListBuckets", nil)
	if err != nil {
		return nil, err
	}
	var r s3Response
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("aws.parse s3: %w", err)
	}
	var out []S3Bucket
	for _, b := range r.Buckets.Items {
		out = append(out, S3Bucket{Name: b.Name, CreationDate: b.CreationDate})
	}
	return out, nil
}

// Identities lists IAM users (ListUsers, paginated via Marker).
func (c *Client) Identities(ctx context.Context) ([]IAMIdentity, error) {
	endpoint := "iam.amazonaws.com"
	var out []IAMIdentity
	var marker string
	for {
		params := map[string]string{"MaxItems": "1000"}
		if marker != "" {
			params["Marker"] = marker
		}
		body, err := c.query(ctx, endpoint, "iam", "ListUsers", params)
		if err != nil {
			return nil, err
		}
		var r iamResponse
		if err := xml.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("aws.parse iam: %w", err)
		}
		for _, u := range r.ListResult.Users.Items {
			out = append(out, IAMIdentity{
				UserName:   u.UserName,
				UserID:     u.UserID,
				Arn:        u.Arn,
				CreateDate: u.CreateDate,
			})
		}
		if r.ListResult.IsTruncated != "true" {
			break
		}
		marker = r.ListResult.Marker
		if marker == "" {
			break
		}
	}
	return out, nil
}

// nextTokenFrom scans raw EC2 XML for a NextToken value without a full
// second parse — a deliberate optimization since the page loop already
// holds the bytes; correctness is covered by fixture tests.
func nextTokenFrom(body []byte) string {
	start := strings.Index(string(body), "<nextToken>")
	end := strings.Index(string(body), "</nextToken>")
	if start < 0 || end < 0 || end <= start {
		return ""
	}
	return strings.TrimSpace(string(body[start+len("<nextToken>") : end]))
}

// ToAssets converts discovered cloud resources into canonical models.Asset
// records with cloud-provenance metadata. Kind mapping is explicit and
// documented (spec §15 asset taxonomy).
func ToAssets(identity Identity, instances []EC2Instance, buckets []S3Bucket, users []IAMIdentity) []models.Asset {
	now := time.Now().UTC()
	var assets []models.Asset
	for _, i := range instances {
		assets = append(assets, models.Asset{
			Kind:     models.KindCloudResource,
			Value:    i.InstanceID,
			Host:     i.PublicIP,
			Port:     0,
			Protocol: "aws_ec2",
			Exposure: exposureOfInstance(i),
			Provenance: models.Provenance{
				Source: "aws_discovery", Method: "ec2.DescribeInstances",
				Timestamp: now, Confidence: models.ConfidenceHigh,
			},
			LastSeen: now, FirstSeen: now,
		})
	}
	for _, b := range buckets {
		assets = append(assets, models.Asset{
			Kind:     models.KindCloudResource,
			Value:    "s3://" + b.Name,
			Protocol: "aws_s3",
			Exposure: models.ExposureUnknown,
			Provenance: models.Provenance{
				Source: "aws_discovery", Method: "s3.ListBuckets",
				Timestamp: now, Confidence: models.ConfidenceHigh,
			},
			LastSeen: now, FirstSeen: now,
		})
	}
	for _, u := range users {
		assets = append(assets, models.Asset{
			Kind:     models.KindIdentity,
			Value:    u.UserName,
			Protocol: "aws_iam",
			Exposure: models.ExposureInternal,
			Provenance: models.Provenance{
				Source: "aws_discovery", Method: "iam.ListUsers",
				Timestamp: now, Confidence: models.ConfidenceHigh,
			},
			LastSeen: now, FirstSeen: now,
		})
	}
	for i := range assets {
		assets[i].ID = idOf(assets[i])
		assets[i].Schema = models.SchemaAsset
	}
	return assets
}

func exposureOfInstance(i EC2Instance) models.ExposureLevel {
	if i.PublicIP != "" {
		return models.ExposureInternet
	}
	return models.ExposureInternal
}

func idOf(a models.Asset) string {
	return models.ContentID(string(a.Kind), a.Value, a.Host)
}
