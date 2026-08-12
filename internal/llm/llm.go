// Package llm is the OPTIONAL LLM augmentation layer (roadmap P0: agentic
// data consumers). It is governed by four hard rules:
//
//  1. OFF by default. The tool is fully functional with Enabled=false.
//  2. User-supplied key only. The API key arrives from RISKX_LLM_API_KEY or
//     llm.api_key in config (env wins); config loading refuses to run with
//     llm.enabled=true and no key. The binary never contains or logs keys.
//  3. Evidence-only output. The LLM MAY explain or contextualize what RISKX
//     has already verified (findings, assets, remediation wording) but may
//     NEVER set severity, confidence, status, classification, or remediation
//     values — those come only from deterministic models and verified feeds.
//     A finding never depends on the LLM to exist or to be rated.
//  4. Fail secure. Any LLM error degrades to "unavailable" with the native
//     output unchanged. The caller never blocks on the LLM.
//
// Provider: OpenAI-compatible chat completions (POST /v1/chat/completions)
// with Bearer auth — the same wire protocol used by OpenAI, and compatible
// with local/self-hosted providers (e.g. Ollama, vLLM) via base_url config.
// Only the model requested by the operator is ever used; the operator names
// their model explicitly (no guessing, spec §15).
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
)

// ResolveAPIKey returns the operator's LLM key: env RISKX_LLM_API_KEY wins
// over the config file value. This mirrors the serve layer's key handling.
func ResolveAPIKey(configKey string) string {
	if k := strings.TrimSpace(os.Getenv("RISKX_LLM_API_KEY")); k != "" {
		return k
	}
	return strings.TrimSpace(configKey)
}

// Config is the operator-facing layer config. Validate() enforces rule 2.
type Config struct {
	Enabled bool
	APIKey  string
	Model   string
	BaseURL string
}

// Validate enforces: enabled without key/model is a configuration error.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if ResolveAPIKey(c.APIKey) == "" {
		return errs.Input("llm.config",
			"llm layer enabled but no API key set",
			"set RISKX_LLM_API_KEY (env, recommended) or llm.api_key (config)")
	}
	if strings.TrimSpace(c.Model) == "" {
		return errs.Input("llm.config",
			"llm layer enabled but no model named",
			"set llm.model to the exact model id you want (operator names it; nothing is guessed)")
	}
	return nil
}

// Client is the HTTP contract for tests.
type Client interface {
	Do(*http.Request) (*http.Response, error)
}

// chatMessage and request/response shape the verified OpenAI-compatible wire.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature"`
}

type chatResponseChoice struct {
	Message chatMessage `json:"message"`
}

type chatResponse struct {
	Choices []chatResponseChoice `json:"choices"`
}

// Request is an operator-initiated explanation request. It carries only
// already-verified native content; the LLM never sees or sets finding
// truth-values.
type Request struct {
	Context string // verified native text to explain (finding/asset/remediation)
	Prompt  string // operator-authored question template
}

// Result carries the LLM's explanatory text plus provenance so downstream
// consumers can distinguish native facts from LLM augmentation.
type Result struct {
	Text       string `json:"text"`
	Model      string `json:"model"`
	Provider   string `json:"provider"`
	Failed     bool   `json:"failed"`
	FailureMsg string `json:"failure,omitempty"`
}

const defaultBaseURL = "https://api.openai.com/v1"

// Explain asks the operator's LLM to explain verified native context. It
// never times out indefinitely (30 s cap) and never fails the caller:
// degradation is reported inside Result.
func Explain(ctx context.Context, client Client, cfg Config, req Request) Result {
	if err := cfg.Validate(); err != nil {
		return Result{Failed: true, FailureMsg: err.Error()}
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		base = defaultBaseURL
	}
	key := ResolveAPIKey(cfg.APIKey)

	body, err := json.Marshal(chatRequest{
		Model:    cfg.Model,
		Temperature: 0.0, // deterministic augmentation; no creative sampling
		MaxTokens: 500,
		Messages: []chatMessage{
			{Role: "system", Content: "You explain ONLY the security context given below, which was produced by an evidence-based scanner. Do not invent new findings, severities, or recommendations. Base your explanation strictly on the provided text."},
			{Role: "user", Content: fmt.Sprintf("%s\n\nCONTEXT:\n%s", req.Prompt, req.Context)},
		},
	})
	if err != nil {
		return Result{Failed: true, FailureMsg: "marshal: " + err.Error(), Provider: base}
	}
	url := base + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Result{Failed: true, FailureMsg: "request: " + err.Error(), Provider: base}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+key)

	resp, err := client.Do(httpReq)
	if err != nil {
		return Result{Failed: true, FailureMsg: "provider unreachable: " + err.Error(), Provider: base}
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Result{Failed: true, FailureMsg: fmt.Sprintf("provider returned %d", resp.StatusCode), Provider: base}
	}
	var out chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Result{Failed: true, FailureMsg: "decode: " + err.Error(), Provider: base}
	}
	if len(out.Choices) == 0 {
		return Result{Failed: true, FailureMsg: "provider returned no choices", Provider: base}
	}
	return Result{
		Text:     out.Choices[0].Message.Content,
		Model:    cfg.Model,
		Provider: base,
	}
}
