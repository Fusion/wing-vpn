package cli

import (
	"strings"
	"testing"

	"wing/config"
)

func TestHandleKeygenRootKey(t *testing.T) {
	out := captureStdout(t, func() {
		if err := HandleKeygen(false, true, false, false, ""); err != nil {
			t.Fatalf("HandleKeygen error: %v", err)
		}
	})
	if !strings.Contains(out, "root_private_key:") {
		t.Fatalf("expected root_private_key in output, got %q", out)
	}
	if !strings.Contains(out, "root_public_key:") {
		t.Fatalf("expected root_public_key in output, got %q", out)
	}
}

func TestHandleKeygenIssuePeerKey(t *testing.T) {
	rootPriv, _, err := config.GenerateRootKeypair()
	if err != nil {
		t.Fatalf("GenerateRootKeypair error: %v", err)
	}
	out := captureStdout(t, func() {
		if err := HandleKeygen(false, false, true, false, rootPriv); err != nil {
			t.Fatalf("HandleKeygen error: %v", err)
		}
	})
	for _, needle := range []string{
		"\"private_key\":",
		"\"public_key\":",
		"\"control_private_key\":",
		"\"control_public_key\":",
		"\"root_public_key\":",
		"\"identity_signature\":",
	} {
		if !strings.Contains(out, needle) {
			t.Fatalf("expected %q in output, got %q", needle, out)
		}
	}
	if strings.Contains(out, "{") || strings.Contains(out, "}") {
		t.Fatalf("expected no outer braces, got %q", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), ",") {
		t.Fatalf("expected trailing comma, got %q", out)
	}
}
