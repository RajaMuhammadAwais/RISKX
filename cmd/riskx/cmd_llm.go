package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/config"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/output"
	"github.com/RajaMuhammadAwais/RISKX/internal/llm"
	"github.com/RajaMuhammadAwais/RISKX/internal/storage"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// newExplainCmd implements `riskx explain`: an operator-facing LLM
// explanation command built on the verified, evidence-only LLM layer.
//
// Design rules (spec §15, §46, §47):
//   - The LLM layer is OFF by default; explain refuses to run unless
//     llm.enabled=true with a user-supplied key and an operator-named model.
//   - Output separates NATIVE verified facts from the LLM explanation so
//     downstream consumers never confuse them.
//   - The LLM never sets severity, confidence, status, classification, or
//     remediation; those values are deterministic.
func newExplainCmd() *cobra.Command {
	var (
		fData      string
		fFindingID string
		fText      string
		fPrompt    string
	)
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain a verified finding or text with the optional LLM layer",
		Long: `explain asks the operator's LLM to explain verified native content.

Rules:
  * The LLM layer must be enabled in config (llm.enabled: true) with a
    user-supplied key (RISKX_LLM_API_KEY, recommended) and an operator-named
    model (llm.model). The command refuses to run otherwise.
  * The LLM explains what RISKX verified; it NEVER sets severity, confidence,
    status, classification, or remediation. Those values are deterministic.
  * Failures degrade gracefully: native output is always printed regardless.

Input (exactly one of):
  --finding <id>   the stored finding to explain (native facts first, then LLM text)
  --text <text>    arbitrary verified text to explain

The same OpenAI-compatible wire is used, so local/self-hosted providers work
via llm.base_url.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			cfgFile, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			lcfg := llm.Config{
				Enabled: cfgFile.LLM.Enabled,
				APIKey:  cfgFile.LLM.APIKey,
				Model:   cfgFile.LLM.Model,
				BaseURL: strings.TrimSpace(cfgFile.LLM.BaseURL),
			}
			if err := lcfg.Validate(); err != nil {
				return err
			}

			debugFlag := func() string { v, _ := cmd.Flags().GetString("text"); return v }
			if fFindingID == "" && fText == "" && debugFlag() == "" {
				return fmt.Errorf("explain: provide --finding <id> or --text <text>")
			}
			if fText == "" {
				fText = debugFlag()
			}
			prompt := fPrompt
			if prompt == "" {
				prompt = "Explain this security finding in plain language: what was observed, why it matters, and what the attached evidence shows. Do not invent new findings, severities, or recommendations."
			}

			var native any
			if fFindingID != "" {
				path, ok := resolveDataPath(fData)
				if !ok {
					return fmt.Errorf("explain: no evidence store; set --data or RISKX_DATA")
				}
				s, err := storage.Open(path)
				if err != nil {
					return err
				}
				defer s.Close()
				f, err := findFindingByID(s, fFindingID)
				if err != nil {
					return err
				}
				if f == nil {
					return fmt.Errorf("explain: finding %q not found in store", fFindingID)
				}
				native = f
			} else {
				native = fText
			}

			res := llm.Explain(cmd.Context(), nil, lcfg, llm.Request{
				Context: canonical(native),
				Prompt:  prompt,
			})
			return printer(cmd).EmitJSON(output.Result{
				Meta: output.NewMeta("explain"),
				Payload: map[string]any{
					"native":        native,
					"explanation":   res,
				},
			})
		},
	}
	cmd.Flags().String("data", os.Getenv("RISKX_DATA"), "evidence store path (env RISKX_DATA)")
	cmd.Flags().String("finding", "", "finding id to explain from the store")
	cmd.Flags().String("text", "", "verified text to explain")
	cmd.Flags().String("prompt", "", "override the explanation prompt")
	return cmd
}

// findFindingByID locates a finding by id through the store's listing. A
// dedicated index is out of scope for v0.3; the store remains the single
// source of truth.
func findFindingByID(s *storage.Store, id string) (*models.Finding, error) {
	findings, err := s.ListFindings()
	if err != nil {
		return nil, err
	}
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i], nil
		}
	}
	return nil, nil
}

// canonical renders a finding as stable text for the LLM context window.
// It is a presentation artifact only: no data values are changed.
func canonical(v any) string {
	switch x := v.(type) {
	case *models.Finding:
		data, _ := json.Marshal(x)
		return fmt.Sprintf("title=%s severity=%s confidence=%s status=%s asset=%s\n%s",
			x.Title, x.Severity, x.Confidence, x.Status, x.AssetValue, string(data))
	default:
		return fmt.Sprint(v)
	}
}

// ensure imports usage consistency with other commands.
var _ = startedNow
