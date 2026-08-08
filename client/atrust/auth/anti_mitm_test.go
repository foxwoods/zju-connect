package auth

import (
	"encoding/hex"
	"testing"
)

func TestSangforSignatureKeyVector(t *testing.T) {
	const want = "a1bdafc52485a6d34fd8f56853a3c4938a696d014b77db54613654989f88e228"

	got := hex.EncodeToString(sangforSignatureKey(antiMITMAttackData{
		DevicePubKeyMod: "device-public-key-modulus",
		DevicePubKeyExp: "010001",
		Challenge:       "server-challenge",
	}))
	if got != want {
		t.Fatalf("sangforSignatureKey() = %q, want %q", got, want)
	}
}

func TestAntiMITMRequestSignature(t *testing.T) {
	const (
		requestURI = "/controller/v1/public/reportEnv?clientType=SDPClient&platform=Mac"
		want       = "390C699604E02EECB61520B27A195DC31199BD0BB9EE19D35A5B5EAC5D0F6DA9"
	)
	signKey, _ := hex.DecodeString("447fc3fa0a20f4e5159737428d20d96d91efef011b432049a2c73250c0f44125")

	if got := antiMITMRequestSignature(signKey, requestURI, []byte("encrypted-body")); got != want {
		t.Fatalf("antiMITMRequestSignature() = %q, want %q", got, want)
	}
}

func TestAntiMITMRequestSignatureRejectsEmptyKey(t *testing.T) {
	if got := antiMITMRequestSignature(nil, "/path", nil); got != "" {
		t.Fatalf("antiMITMRequestSignature() = %q, want empty", got)
	}
}
