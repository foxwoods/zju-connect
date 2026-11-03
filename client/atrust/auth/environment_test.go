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
		if !strings.Contains(userAgent, "aTrustTray/"+atrustClientVersionForGOOS(goos)) {
			t.Errorf("userAgentForGOOS(%q) = %q, want aTrust version %q", goos, userAgent, atrustClientVersionForGOOS(goos))
		}
	}
}

func TestWindowsOfficialClientIdentity(t *testing.T) {
	const want = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/200.4.10.25002 Chrome/87.0.4280.141 Electron/11.5.0 Safari/537.36 aTrustTray-Windows-Plat SPCClientType"
	if got := userAgentForGOOS("windows"); got != want {
		t.Errorf("userAgentForGOOS(windows) = %q, want %q", got, want)
	}
	if got := windowsVersion("\r\nMicrosoft Windows [Version 10.0.22631.4317]\r\n"); got != "10.0.22631" {
		t.Errorf("windowsVersion() = %q, want 10.0.22631", got)
	}
}

func TestCollectEndpointEnvironment(t *testing.T) {
	env := collectEndpointEnvironment("device-id")

	if env.DeviceID != "device-id" {
		t.Fatalf("device ID = %q, want device-id", env.DeviceID)
	}
	if env.OSFamily != osFamilyForGOOS(runtime.GOOS) {
		t.Errorf("OS family = %q, want %q", env.OSFamily, osFamilyForGOOS(runtime.GOOS))
	}
	if env.OSArch == "" {
		t.Error("OS architecture must not be empty")
	}
	if env.MACAddresses == nil || env.ClientIPs == nil {
		t.Error("network environment slices must be encoded as arrays, not null")
	}
	if env.ATrustClientVersion != atrustClientVersion {
		t.Errorf("client version = %q, want %q", env.ATrustClientVersion, atrustClientVersion)
	}
	if env.UEMClientVersion != "" {
		t.Errorf("UEM client version = %q, want empty without a UEM client", env.UEMClientVersion)
	}
	if env.UEMSecureEvents == nil {
		t.Error("UEM secure events must be encoded as an array, not null")
	}
}

func TestEmulateWindows(t *testing.T) {
	SetEmulateWindows(true)
	defer SetEmulateWindows(false)

	if got := effectivePlatform(); got != "Windows" {
		t.Errorf("effectivePlatform() = %q, want Windows", got)
	}
	if !strings.Contains(UserAgent, "aTrustTray-Windows") {
		t.Errorf("UserAgent = %q, want Windows marker", UserAgent)
	}

	env := collectEndpointEnvironment("device-id")
	if env.OSFamily != "Windows" {
		t.Errorf("OS family = %q, want Windows", env.OSFamily)
	}
	if env.OSSubOS != "Windows" {
		t.Errorf("OS sub_os = %q, want Windows", env.OSSubOS)
	}
	if env.OSVersion != "10.0.22631" {
		t.Errorf("OS version = %q, want 10.0.22631", env.OSVersion)
	}
	if env.OSArch != "x64" {
		t.Errorf("OS arch = %q, want x64", env.OSArch)
	}
	if env.ATrustClientVersion != "200.4.10.25002" {
		t.Errorf("client version = %q, want 200.4.10.25002", env.ATrustClientVersion)
	}
	if env.DeviceBrand != "HP" {
		t.Errorf("device brand = %q, want HP", env.DeviceBrand)
	}
	if env.DeviceModel != "HP EliteBook 840 14 inch G9 Notebook PC" {
		t.Errorf("device model = %q, want HP EliteBook 840 14 inch G9 Notebook PC", env.DeviceModel)
	}
}
