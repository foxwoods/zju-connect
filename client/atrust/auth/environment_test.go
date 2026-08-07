package auth

import (
	"runtime"
	"strings"
	"testing"
)

func TestPlatformForGOOS(t *testing.T) {
	tests := map[string]string{
		"darwin":  "Mac",
		"windows": "Windows",
		"linux":   "Linux",
		"freebsd": "Linux",
	}

	for goos, expected := range tests {
		if actual := platformForGOOS(goos); actual != expected {
			t.Errorf("platformForGOOS(%q) = %q, want %q", goos, actual, expected)
		}
	}
}

func TestUserAgentForGOOS(t *testing.T) {
	tests := map[string]string{
		"darwin":  "aTrustTray-MacOS",
		"windows": "aTrustTray-Windows",
		"linux":   "aTrustTray-Linux",
	}

	for goos, marker := range tests {
		userAgent := userAgentForGOOS(goos)
		if !strings.Contains(userAgent, marker) {
			t.Errorf("userAgentForGOOS(%q) = %q, want marker %q", goos, userAgent, marker)
		}
		if !strings.Contains(userAgent, "aTrustTray/"+atrustClientVersion) {
			t.Errorf("userAgentForGOOS(%q) = %q, want aTrust version %q", goos, userAgent, atrustClientVersion)
		}
	}
}

func TestCollectEndpointEnvironment(t *testing.T) {
	env := collectEndpointEnvironment("device-id")

	if env.DeviceID != "device-id" {
		t.Fatalf("device ID = %q, want device-id", env.DeviceID)
	}
	if env.OS.Family != osFamilyForGOOS(runtime.GOOS) {
		t.Errorf("OS family = %q, want %q", env.OS.Family, osFamilyForGOOS(runtime.GOOS))
	}
	if env.OS.Arch == "" {
		t.Error("OS architecture must not be empty")
	}
	if env.MACAddresses == nil || env.ClientIPs == nil {
		t.Error("network environment slices must be encoded as arrays, not null")
	}
	if env.ATrustClient.Version != atrustClientVersion {
		t.Errorf("client version = %q, want %q", env.ATrustClient.Version, atrustClientVersion)
	}
}
