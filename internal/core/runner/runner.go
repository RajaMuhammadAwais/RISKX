// Package runner implements the CLI execution contract (spec §7, §33).
//
// Exit codes (documented exactly, spec §33):
//
//	0 = command completed, no policy violation
//	1 = command completed, policy violation found
//	2 = execution error
//
// Runners compose the security mode, the authorizer, and the policy evaluator;
// command handlers return (result, exitCode, error) and the runner emits the
// output and exits with the correct code.
package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/config"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/log"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/mode"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/output"
	"github.com/RajaMuhammadAwais/RISKX/internal/policy"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// Command is the interface every CLI command implements.
type Command interface {
	Name() string
	Usage() string
	Run(ctx context.Context) (output.Result, error)
}

// Options configure a Run invocation.
type Options struct {
	Mode        mode.SecurityMode
	Actions     []mode.Action // planned actions for intrusive modes
	CI          bool
	Preapproved bool
	PolicyFile  string
	JSON        bool
	Findings    []models.Finding
	Scores      []models.RiskScore
}

// Outcome holds the post-run result.
type Outcome struct {
	Result   output.Result
	ExitCode int
}

// Run executes a command with mode gating, policy evaluation, and output.
func Run(cmd Command, opts Options, stdout, stderr io.Writer) Outcome {
	// Mode gating: intrusive modes require explicit authorization.
	auth := mode.NewAuthorizer(stdout, os.Stdin, opts.CI, opts.Preapproved)
	if err := auth.Require(opts.Mode, opts.Actions); err != nil {
		writeErr(stderr, err)
		return Outcome{ExitCode: 2}
	}

	result, err := cmd.Run(context.Background())
	if err != nil {
		writeErr(stderr, err)
		var re *errs.RISKX
		if err != nil && isRISKX(err) {
			// Policy violations are a clean policy outcome (exit 1), not an
			// execution error.
			if re.Code == errs.CodePolicyViolation {
				return Outcome{ExitCode: 1}
			}
		}
		return Outcome{ExitCode: 2}
	}

	eval := policy.Evaluate(policy.DefaultPolicy(), opts.Findings, opts.Scores, now())
	if eval.Violated {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("policy violation: %d rule(s) failed; see 'riskx policy'", len(eval.Outcomes)))
	}

	printer := output.NewPrinter(stdout)
	if opts.JSON {
		if err := printer.EmitJSON(result); err != nil {
			writeErr(stderr, err)
			return Outcome{ExitCode: 2}
		}
	} else {
		if err := printer.HumanSummary(result); err != nil {
			writeErr(stderr, err)
			return Outcome{ExitCode: 2}
		}
	}

	if eval.Violated {
		return Outcome{Result: result, ExitCode: 1}
	}
	return Outcome{Result: result, ExitCode: 0}
}

func writeErr(w io.Writer, err error) {
	fmt.Fprintf(w, "error: %v\n", err)
	var re *errs.RISKX
	if errs.As(err, &re) && re.Hint != "" {
		fmt.Fprintf(w, "hint: %s\n", re.Hint)
	}
}

// isRISKX reports whether err is (or wraps) a *errs.RISKX.
func isRISKX(err error) bool {
	var re *errs.RISKX
	return errs.As(err, &re)
}

// As reports whether err (or its chain) is *errs.RISKX, giving callers the
// typed error access they need for exit-code mapping.
func As(err error, target **errs.RISKX) bool { return errs.As(err, target) }

// now is a package-level hook for deterministic testing.
var now = func() time.Time { return time.Now().UTC() }

// Init configures the default logger from the loaded config.
func Init(cfg *config.Config, jsonMode bool) {
	if cfg.Output.JSON || jsonMode {
		log.SetJSON(true)
	}
}
