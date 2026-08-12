// Package errs defines RISKX's explicit error taxonomy (spec §24).
//
// Rules: no ignored errors; every error is typed; user-visible errors carry a
// remediation hint; feed/visibility problems produce StaleDataError and
// VisibilityIncompleteError rather than silently degrading (spec §48).
package errs

import (
	"errors"
	"fmt"
)

// RISKX is the typed error returned by core operations.
type RISKX struct {
	Code    string `json:"code"`
	Op      string `json:"op"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	Cause   error  `json:"-"`
}

func (e *RISKX) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %s: %v", e.Code, e.Op, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s: %s", e.Code, e.Op, e.Message)
}

func (e *RISKX) Unwrap() error { return e.Cause }

// New builds a typed RISKX error.
func New(code, op, message string) *RISKX {
	return &RISKX{Code: code, Op: op, Message: message}
}

// Wrap builds a typed RISKX error with a cause.
func Wrap(code, op, message string, cause error) *RISKX {
	return &RISKX{Code: code, Op: op, Message: message, Cause: cause}
}

// Common error codes.
const (
	CodeInvalidInput    = "RISKX_E_INVALID_INPUT"
	CodeConfigError     = "RISKX_E_CONFIG"
	CodeFeedUnavailable = "RISKX_E_FEED_UNAVAILABLE"
	CodeRateLimited     = "RISKX_E_RATE_LIMITED"
	CodeAuthRequired    = "RISKX_E_AUTH_REQUIRED"
	CodeInternal        = "RISKX_E_INTERNAL"
	CodeNotImplemented  = "RISKX_E_NOT_IMPLEMENTED"
	CodeModeDenied      = "RISKX_E_MODE_DENIED"
	CodePolicyViolation = "RISKX_E_POLICY_VIOLATION" // maps to exit code 1
)

// StaleDataError is raised when a data source cannot be confirmed current.
// Callers must mark feeds stale in output metadata, never pretend data is
// current (spec §48).
type StaleDataError struct {
	Feed string
	Err  error
}

func (e *StaleDataError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("feed %q cannot be confirmed current: %v", e.Feed, e.Err)
	}
	return fmt.Sprintf("feed %q cannot be confirmed current", e.Feed)
}

func (e *StaleDataError) Unwrap() error { return e.Err }

// VisibilityIncompleteError is raised when a source denies full visibility
// (e.g., cloud API permission denied). Findings must not assume absence
// (spec §48).
type VisibilityIncompleteError struct {
	Source string
	Detail string
}

func (e *VisibilityIncompleteError) Error() string {
	return fmt.Sprintf("visibility into %q is incomplete: %s", e.Source, e.Detail)
}

// Is reports whether err (or its chain) is the given typed error.
func Is(err, target error) bool { return errors.Is(err, target) }

// As unwraps err into target (like errors.As). Kept here so the errs package
// remains the single dependency for typed error handling.
func As(err error, target any) bool { return errors.As(err, target) }

// Input wraps an invalid-input error with a hint.
func Input(op, message, hint string) *RISKX {
	return &RISKX{Code: CodeInvalidInput, Op: op, Message: message, Hint: hint}
}

// Feed wraps an external-feed error with an operator hint.
func Feed(op, message, hint string) *RISKX {
	return &RISKX{Code: CodeFeedUnavailable, Op: op, Message: message, Hint: hint}
}
