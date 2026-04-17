package main

import (
	"testing"

	"wing/config"
)

func TestValidatePublicKey(t *testing.T) {
	_, pub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair error: %v", err)
	}
	if err := config.ValidatePublicKey(pub); err != nil {
		t.Fatalf("validatePublicKey error: %v", err)
	}
	if err := config.ValidatePublicKey("nope"); err == nil {
		t.Fatalf("validatePublicKey expected error")
	}
}
