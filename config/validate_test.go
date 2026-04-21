package config

import "testing"

func TestValidatePublicKey(t *testing.T) {
	_, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	if err := ValidatePublicKey(pub); err != nil {
		t.Fatalf("ValidatePublicKey error: %v", err)
	}
	if err := ValidatePublicKey("nope"); err == nil {
		t.Fatalf("ValidatePublicKey expected error")
	}
}
