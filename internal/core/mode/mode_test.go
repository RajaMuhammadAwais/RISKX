package mode

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseModes(t *testing.T) {
	cases := []struct {
		in   string
		want SecurityMode
	}{
		{"passive", Passive}, {"PASSIVE", Passive}, {"", Passive},
		{"safe", Safe}, {"active", Active}, {"validation", Validation},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q) unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("Parse(%q) = %s, want %s", c.in, got, c.want)
		}
	}
	if _, err := Parse("dangerous"); err == nil {
		t.Fatal("unknown mode must error")
	}
}

func TestPassiveNeverRequiresAuthorization(t *testing.T) {
	auth := NewAuthorizer(&bytes.Buffer{}, strings.NewReader(""), false, false)
	if err := auth.Require(Passive, nil); err != nil {
		t.Fatalf("passive must never require authorization: %v", err)
	}
}

func TestActiveRequiresPlan(t *testing.T) {
	auth := NewAuthorizer(&bytes.Buffer{}, strings.NewReader(""), false, false)
	if err := auth.Require(Active, nil); err == nil {
		t.Fatal("active mode without an action plan must error")
	}
}

func TestActiveRequiresExplicitConsent(t *testing.T) {
	var out bytes.Buffer
	auth := NewAuthorizer(&out, strings.NewReader("no\n"), false, false)
	err := auth.Require(Active, []Action{{Description: "probe", Target: "host", Method: "connect"}})
	if err == nil {
		t.Fatal("operator refusing must abort the run")
	}
	if !strings.Contains(out.String(), "planned actions") {
		t.Fatal("the printed plan must include the planned-actions header")
	}
}

func TestActiveProceedsWithConsent(t *testing.T) {
	auth := NewAuthorizer(&bytes.Buffer{}, strings.NewReader("yes\n"), false, false)
	if err := auth.Require(Active, []Action{{Description: "probe", Target: "host", Method: "connect"}}); err != nil {
		t.Fatalf("explicit yes must proceed: %v", err)
	}
}

func TestCIModeRequiresPreapprove(t *testing.T) {
	auth := NewAuthorizer(&bytes.Buffer{}, nil, true, false)
	err := auth.Require(Active, []Action{{Description: "probe", Target: "host", Method: "connect"}})
	if err == nil {
		t.Fatal("CI mode without --preapprove must deny intrusive modes")
	}
	if !strings.Contains(err.Error(), "--preapprove") {
		t.Fatal("the denial must tell the operator how to pre-approve")
	}
}

func TestCIModePreapprovedProceeds(t *testing.T) {
	auth := NewAuthorizer(&bytes.Buffer{}, nil, true, true)
	if err := auth.Require(Active, []Action{{Description: "probe", Target: "host", Method: "connect"}}); err != nil {
		t.Fatalf("preapproved CI run must proceed: %v", err)
	}
}
