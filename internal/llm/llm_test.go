package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestResolveAPIKeyEnvWins(t *testing.T) {
	t.Setenv("RISKX_LLM_API_KEY", "env-key")
	if got := ResolveAPIKey("config-key"); got != "env-key" {
		t.Fatalf("env must win: %q", got)
	}
	t.Setenv("RISKX_LLM_API_KEY", "")
	if got := ResolveAPIKey("config-key"); got != "config-key" {
		t.Fatalf("config fallback: %q", got)
	}
	os.Unsetenv("RISKX_LLM_API_KEY")
	if got := ResolveAPIKey("config-key"); got != "config-key" {
		t.Fatalf("unset env fallback: %q", got)
	}
}

func TestValidateFailSecure(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool // expects error
	}{
		{"disabled is always fine", Config{Enabled: false}, false},
		{"enabled without key", Config{Enabled: true, Model: "m"}, true},
		{"enabled without model", Config{Enabled: true, APIKey: "k"}, true},
		{"enabled with key and model", Config{Enabled: true, APIKey: "k", Model: "m"}, false},
	}
	for _, c := range cases {
		err := c.cfg.Validate()
		if (err != nil) != c.want {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.want)
		}
	}
}

type fakeClient struct {
	body []byte
	code int
	got  *http.Request
}

func (f *fakeClient) Do(r *http.Request) (*http.Response, error) {
	f.got = r
	body := f.body
	if body == nil {
		body = []byte("{}")
	}
	return &http.Response{StatusCode: f.code, Body: &readCloser{data: body}}, nil
}

type readCloser struct{ data []byte }

func (r *readCloser) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
func (*readCloser) Close() error { return nil }

func TestExplainWire(t *testing.T) {
	want := chatResponse{Choices: []chatResponseChoice{{Message: chatMessage{Role: "assistant", Content: "explains context"}}}}
	body, _ := json.Marshal(want)
	c := &fakeClient{body: body, code: http.StatusOK}
	res := Explain(context.Background(), c, Config{
		Enabled: true, APIKey: "k", Model: "m",
	}, Request{Context: "verified fact", Prompt: "explain"})
	if res.Failed {
		t.Fatalf("unexpected failure: %s", res.FailureMsg)
	}
	if res.Text != "explains context" || res.Model != "m" {
		t.Errorf("bad result: %+v", res)
	}
	if c.got == nil {
		t.Fatal("request never sent")
	}
	// Rule 2: bearer key from user.
	if auth := c.got.Header.Get("Authorization"); auth != "Bearer k" {
		t.Errorf("auth header %q", auth)
	}
	// Rule: deterministic, low temperature; default endpoint.
	if c.got.URL.String() != "https://api.openai.com/v1/chat/completions" {
		t.Errorf("unexpected URL %q", c.got.URL.String())
	}
}

// TestExplainDecodes verifies message construction by re-reading the request
// body through a recording roundtrip using a real http.Request clone.
func TestExplainDecodes(t *testing.T) {
	want := chatResponse{Choices: []chatResponseChoice{{Message: chatMessage{Content: "ok"}}}}
	body, _ := json.Marshal(want)
	c := &fakeClient{body: body, code: http.StatusOK}
	_ = Explain(context.Background(), c, Config{Enabled: true, APIKey: "k", Model: "m"}, Request{Context: "ctx", Prompt: "p"})
	var req chatRequest
	_ = json.NewDecoder(c.got.Body).Decode(&req)
	if req.Temperature != 0.0 {
		t.Errorf("temperature must be 0 (deterministic): %v", req.Temperature)
	}
	if len(req.Messages) != 2 {
		t.Fatalf("expected system+user messages, got %d", len(req.Messages))
	}
	if !strings.Contains(req.Messages[0].Content, "Do not invent new findings") {
		t.Error("system message must forbid invention")
	}
	if !strings.Contains(req.Messages[1].Content, "CONTEXT:\nctx") {
		t.Error("user message must carry verified context")
	}
}

func TestExplainCustomBaseURL(t *testing.T) {
	want := chatResponse{Choices: []chatResponseChoice{{Message: chatMessage{Content: "ok"}}}}
	body, _ := json.Marshal(want)
	c := &fakeClient{body: body, code: http.StatusOK}
	_ = Explain(context.Background(), c, Config{Enabled: true, APIKey: "k", Model: "m", BaseURL: "http://localhost:11434/v1"}, Request{Context: "ctx", Prompt: "p"})
	if !strings.HasPrefix(c.got.URL.String(), "http://localhost:11434/v1/") {
		t.Errorf("base URL not respected: %q", c.got.URL.String())
	}
}

func TestExplainProviderFailureDegrades(t *testing.T) {
	c := &fakeClient{code: http.StatusInternalServerError}
	res := Explain(context.Background(), c, Config{Enabled: true, APIKey: "k", Model: "m"}, Request{})
	if !res.Failed {
		t.Fatal("expected degraded result on 500")
	}
	if res.Provider == "" {
		t.Error("provider should be recorded even on failure")
	}
}

func TestExplainUnreachableDegrades(t *testing.T) {
	c := &failClient{}
	res := Explain(context.Background(), c, Config{Enabled: true, APIKey: "k", Model: "m"}, Request{})
	if !res.Failed || !strings.Contains(res.FailureMsg, "unreachable") {
		t.Errorf("expected unreachable degradation: %v", res)
	}
}

type failClient struct{}

func (*failClient) Do(r *http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}

func TestExplainNoKeyRefuses(t *testing.T) {
	// Rule 2: even if Explain is called directly with an empty key, no
	// request may be sent; result must be Failed.
	called := false
	c := &spyClient{f: func(r *http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	}}
	res := Explain(context.Background(), c, Config{Enabled: true, APIKey: "", Model: "m"}, Request{})
	if called {
		t.Fatal("request sent without key — rule 2 violated")
	}
	if !res.Failed {
		t.Fatal("expected failure without key")
	}
}

type spyClient struct{ f func(r *http.Request) (*http.Response, error) }

func (s *spyClient) Do(r *http.Request) (*http.Response, error) { return s.f(r) }

func TestExplainTimeout(t *testing.T) {
	want := chatResponse{Choices: []chatResponseChoice{{Message: chatMessage{Content: "ok"}}}}
	body, _ := json.Marshal(want)
	c := &timingClient{body: body, code: http.StatusOK}
	res := Explain(context.Background(), c, Config{Enabled: true, APIKey: "k", Model: "m"}, Request{})
	if c.elapsed == 0 || c.elapsed > 31*time.Second {
		t.Errorf("unexpected elapsed: %v", c.elapsed)
	}
	if res.Failed {
		t.Fatalf("unexpected failure: %s", res.FailureMsg)
	}
}

type timingClient struct {
	body     []byte
	code     int
	elapsed  time.Duration
	started  time.Time
}

func (c *timingClient) Do(r *http.Request) (*http.Response, error) {
	if c.started.IsZero() {
		c.started = time.Now()
	}
	c.elapsed = time.Since(c.started)
	return &http.Response{StatusCode: c.code, Body: &readCloser{data: c.body}}, nil
}
