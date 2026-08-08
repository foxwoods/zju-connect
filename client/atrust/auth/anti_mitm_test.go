package auth

import "testing"

func TestDeriveAntiMITMSignKey(t *testing.T) {
	const (
		mod       = "device-public-key-modulus"
		exponent  = "010001"
		challenge = "server-challenge"
		want      = "a1bdafc52485a6d34fd8f56853a3c4938a696d014b77db54613654989f88e228"
	)

	if got := deriveAntiMITMSignKey(mod, exponent, challenge); got != want {
		t.Fatalf("deriveAntiMITMSignKey() = %q, want %q", got, want)
	}
}

func TestAntiMITMRequestSignature(t *testing.T) {
	const (
		signKey    = "447fc3fa0a20f4e5159737428d20d96d91efef011b432049a2c73250c0f44125"
		requestURI = "/controller/v1/public/reportEnv?clientType=SDPClient&platform=Mac"
		want       = "390C699604E02EECB61520B27A195DC31199BD0BB9EE19D35A5B5EAC5D0F6DA9"
	)

	if got := antiMITMRequestSignature(signKey, requestURI, []byte("encrypted-body")); got != want {
		t.Fatalf("antiMITMRequestSignature() = %q, want %q", got, want)
	}
}

func TestAntiMITMRequestSignatureRejectsInvalidKey(t *testing.T) {
	if got := antiMITMRequestSignature("not-hex", "/path", nil); got != "" {
		t.Fatalf("antiMITMRequestSignature() = %q, want empty", got)
	}
}
