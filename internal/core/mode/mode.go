// Package mode implements RISKX's security operating modes (spec §7, §8).
//
// PASSIVE: read-only observation only; the default and safe mode.
// SAFE: passive plus authenticated read-only access using user-provided
// credentials.
// ACTIVE: explicitly authorized intrusive checks; requires both the mode flag
// and an interactive/CI confirmation of a printed action plan.
// VALIDATION: validates specific findings against user-authorized steps; a
// pre-execution plan must be acknowledged before anything runs.
//
// Never exploit (spec §8). Never test systems without authorization (spec §28).
package mode

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
)

// SecurityMode enumerates the four operating modes.
type SecurityMode string

const (
	Passive   SecurityMode = "passive"
	Safe      SecurityMode = "safe"
	Active    SecurityMode = "active"
	Validation SecurityMode = "validation"
)

// Parse normalizes and validates a mode string.
func Parse(s string) (SecurityMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "passive":
		return Passive, nil
	case "safe":
		return Safe, nil
	case "active":
		return Active, nil
	case "validation":
		return Validation, nil
	default:
		return "", errs.Input("mode.parse", fmt.Sprintf("unknown mode %q", s),
			"choose one of: passive, safe, active, validation")
	}
}

// String returns the canonical mode name.
func (m SecurityMode) String() string { return string(m) }

// Action describes one concrete step an intrusive mode intends to perform.
type Action struct {
	Description string
	Target      string
	Method      string
}

// Authorizer mediates explicit authorization for ACTIVE and VALIDATION modes
// (spec §8). In CI (--ci) the plan is printed and the run fails unless the
// operator pre-approves; interactively the operator must type "yes".
type Authorizer struct {
	out      io.Writer
	in       io.Reader
	ci       bool
	preapproved bool
}

// NewAuthorizer builds an authorizer. In CI mode preapproved controls whether
// authorization is already granted.
func NewAuthorizer(out io.Writer, in io.Reader, ci bool, preapproved bool) *Authorizer {
	return &Authorizer{out: out, in: in, ci: ci, preapproved: preapproved}
}

// Require checks that the requested mode is permitted and obtains explicit
// authorization for intrusive modes. It returns an actionable error when the
// operator has not consented.
func (a *Authorizer) Require(requested SecurityMode, actions []Action) error {
	switch requested {
	case Passive, Safe:
		return nil
	case Active, Validation:
		if len(actions) == 0 {
			return errs.New(errs.CodeInvalidInput, "mode.authorize",
				"intrusive modes require a non-empty action plan")
		}
		return a.confirm(actions, requested)
	default:
		return errs.New(errs.CodeModeDenied, "mode.authorize",
			fmt.Sprintf("mode %q is not permitted in this context", requested))
	}
}

func (a *Authorizer) confirm(actions []Action, requested SecurityMode) error {
	if _, err := fmt.Fprintf(a.out,
		"\n=== %s MODE: planned actions (these will run only with your explicit approval) ===\n",
		strings.ToUpper(string(requested))); err != nil {
		return errs.Wrap(errs.CodeInternal, "mode.authorize", "cannot print action plan", err)
	}
	for i, act := range actions {
		if _, err := fmt.Fprintf(a.out, "  %d. [%s] %s -> %s\n", i+1, act.Method, act.Description, act.Target); err != nil {
			return errs.Wrap(errs.CodeInternal, "mode.authorize", "cannot print action plan", err)
		}
	}
	if a.ci {
		if !a.preapproved {
			return errs.New(errs.CodeModeDenied, "mode.authorize",
				fmt.Sprintf("%s mode requires --preapprove in CI; re-run with --preapprove after reviewing the plan above", requested),
			)
		}
		return nil
	}
	if a.preapproved {
		return nil
	}
	if _, err := fmt.Fprint(a.out, "Type 'yes' to authorize exactly these actions: "); err != nil {
		return errs.Wrap(errs.CodeInternal, "mode.authorize", "cannot prompt operator", err)
	}
	answer, err := bufio.NewReader(a.in).ReadString('\n')
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "mode.authorize", "cannot read operator response", err)
	}
	if strings.TrimSpace(strings.ToLower(answer)) != "yes" {
		return errs.New(errs.CodeModeDenied, "mode.authorize",
			"operator did not authorize the planned actions; run aborted with no changes")
	}
	return nil
}

// DefaultAuthorizer is used by commands unless testing injects another.
func DefaultAuthorizer(ci, preapproved bool) *Authorizer {
	return NewAuthorizer(os.Stdout, os.Stdin, ci, preapproved)
}
