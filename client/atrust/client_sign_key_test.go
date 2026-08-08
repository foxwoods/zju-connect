package atrust

import (
	"testing"

	"github.com/mythologyli/zju-connect/client/atrust/auth"
)

func TestApplyLoginResultUsesNegotiatedSignKey(t *testing.T) {
	client := NewClient(ClientOptions{Session: SessionOptions{SignKey: "fallback-key"}})
	client.applyLoginResult(auth.LoginResult{
		Username: "tester",
		SID:      "sid",
		SignKey:  "negotiated-key",
	})

	if client.Username != "tester" || client.SID != "sid" {
		t.Fatalf("login identity = %q/%q, want tester/sid", client.Username, client.SID)
	}
	if client.SignKey != "negotiated-key" {
		t.Fatalf("sign key = %q, want negotiated-key", client.SignKey)
	}
}

func TestApplyLoginResultKeepsFallbackSignKey(t *testing.T) {
	client := NewClient(ClientOptions{Session: SessionOptions{SignKey: "fallback-key"}})
	client.applyLoginResult(auth.LoginResult{})

	if client.SignKey != "fallback-key" {
		t.Fatalf("sign key = %q, want fallback-key", client.SignKey)
	}
}
