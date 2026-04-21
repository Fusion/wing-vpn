package config

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func GenerateKeypair() (string, string, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	return privB64, pubB64, nil
}

func GeneratePSK() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func GenerateRootKeypair() (string, string, error) {
	return GenerateControlKeypair()
}

type IssuedPeerIdentity struct {
	PrivateKey        string `json:"private_key"`
	PublicKey         string `json:"public_key"`
	ControlPrivateKey string `json:"control_private_key"`
	ControlPublicKey  string `json:"control_public_key"`
	RootPublicKey     string `json:"root_public_key"`
	IdentitySignature string `json:"identity_signature"`
}

func IssuePeerIdentity(rootPrivateKey string) (*IssuedPeerIdentity, error) {
	rootPrivateKey = strings.TrimSpace(rootPrivateKey)
	if rootPrivateKey == "" {
		return nil, errors.New("root private key is required")
	}
	wgPriv, wgPub, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	controlPriv, controlPub, err := GenerateControlKeypair()
	if err != nil {
		return nil, err
	}
	rootPriv, err := ParseControlPrivateKey(rootPrivateKey)
	if err != nil {
		return nil, err
	}
	rootPub := base64.StdEncoding.EncodeToString(rootPriv.Public().(ed25519.PublicKey))
	signature, err := SignIdentityBinding(rootPrivateKey, wgPub, controlPub)
	if err != nil {
		return nil, err
	}
	return &IssuedPeerIdentity{
		PrivateKey:        wgPriv,
		PublicKey:         wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
		RootPublicKey:     rootPub,
		IdentitySignature: signature,
	}, nil
}

func SignIdentityBinding(rootPrivateKey, wgPublicKey, controlPublicKey string) (string, error) {
	msg, err := identityBindingPayload(wgPublicKey, controlPublicKey)
	if err != nil {
		return "", err
	}
	return SignControlMessage(rootPrivateKey, msg)
}

func VerifyIdentityBinding(rootPublicKey, wgPublicKey, controlPublicKey, signature string) error {
	msg, err := identityBindingPayload(wgPublicKey, controlPublicKey)
	if err != nil {
		return err
	}
	return VerifyControlMessage(rootPublicKey, msg, signature)
}

func identityBindingPayload(wgPublicKey, controlPublicKey string) ([]byte, error) {
	wgPublicKey = strings.TrimSpace(wgPublicKey)
	controlPublicKey = strings.TrimSpace(controlPublicKey)
	if err := ValidatePublicKey(wgPublicKey); err != nil {
		return nil, fmt.Errorf("invalid wg public key: %v", err)
	}
	if err := ValidateControlPublicKey(controlPublicKey); err != nil {
		return nil, fmt.Errorf("invalid control public key: %v", err)
	}
	payload := struct {
		WGPublicKey      string `json:"wg_public_key"`
		ControlPublicKey string `json:"control_public_key"`
	}{
		WGPublicKey:      wgPublicKey,
		ControlPublicKey: controlPublicKey,
	}
	return json.Marshal(payload)
}
