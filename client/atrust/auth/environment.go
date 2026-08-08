package auth

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"github.com/mythologyli/zju-connect/log"
)

const atrustClientVersion = "2.4.10.50"

type endpointEnvironment struct {
	OSHostname                     string        `json:"endpoint.os.hostname"`
	DeviceModel                    string        `json:"endpoint.device_model"`
	DeviceID                       string        `json:"endpoint.device_id"`
	ATrustClientVersion            string        `json:"endpoint.atrust_client.version"`
	MACAddresses                   []string      `json:"endpoint.mac_addresses"`
	ClientIPs                      []string      `json:"endpoint.client_ips"`
	DomainName                     string        `json:"endpoint.domain_name"`
	OSFamily                       string        `json:"endpoint.os.family"`
	OSVersion                      string        `json:"endpoint.os.version"`
	OSArch                         string        `json:"endpoint.os.arch"`
	FirewallEnabled                bool          `json:"endpoint.security.is_firewall_enabled"`
	DeviceType                     string        `json:"endpoint.device.type"`
	AntivirusEnabled               bool          `json:"endpoint.security.is_antivirus_enabled"`
	DomainJoined                   bool          `json:"endpoint.security.is_domain"`
	AntivirusLatest                bool          `json:"endpoint.antivirus.is_latest"`
	SandboxType                    string        `json:"endpoint.sandboxType"`
	EDRAgentID                     string        `json:"endpoint.edr_agentid"`
	OSSubOS                        string        `json:"endpoint.os.sub_os"`
	DeviceBrand                    string        `json:"endpoint.device_brand"`
	UEMClientVersion               string        `json:"endpoint.uem_client.version"`
	UEMSecureEvents                []interface{} `json:"endpoint.uem_client.secure_events"`
	SkipCheckSandboxWebResource    bool          `json:"endpoint.uem_client.application.skip_check_sandbox_web_resource"`
	SkipCheckVirtualNetWebResource bool          `json:"endpoint.uem_client.application.skip_check_virtualnet_web_resource"`
}

func collectEndpointEnvironment(deviceID string) endpointEnvironment {
	hostname, _ := os.Hostname()
	osFamily := osFamilyForGOOS(runtime.GOOS)
	osVersion, subOS := collectOSDetails(runtime.GOOS, osFamily)
	deviceBrand, deviceModel := collectDeviceIdentity(runtime.GOOS)

	macAddresses, clientIPs := collectNetworkEnvironment()

	return endpointEnvironment{
		OSHostname:          hostname,
		DeviceModel:         deviceModel,
		DeviceID:            deviceID,
		ATrustClientVersion: atrustClientVersion,
		MACAddresses:        macAddresses,
		ClientIPs:           clientIPs,
		DomainName:          os.Getenv("USERDOMAIN"),
		OSFamily:            osFamily,
		OSVersion:           osVersion,
		OSArch:              runtime.GOARCH,
		FirewallEnabled:     false,
		DeviceType:          deviceModel,
		AntivirusEnabled:    false,
		DomainJoined:        false,
		AntivirusLatest:     false,
		SandboxType:         "WithUem",
		EDRAgentID:          "",
		OSSubOS:             subOS,
		DeviceBrand:         deviceBrand,
		UEMClientVersion:    atrustClientVersion,
		UEMSecureEvents:     []interface{}{},
	}
}

func osFamilyForGOOS(goos string) string {
	switch goos {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	default:
		return "Linux"
	}
}

func collectOSDetails(goos, fallbackSubOS string) (string, string) {
	switch goos {
	case "darwin":
		return commandOutput("sw_vers", "-productVersion"), "macOS"
	case "windows":
		return commandOutput("cmd", "/c", "ver"), "Windows"
	case "linux":
		id, version := readOSRelease()
		if id == "" {
			id = fallbackSubOS
		}
		return version, id
	default:
		return "", fallbackSubOS
	}
}

func collectDeviceIdentity(goos string) (string, string) {
	switch goos {
	case "darwin":
		return "Apple", commandOutput("sysctl", "-n", "hw.model")
	case "linux":
		brand, _ := os.ReadFile("/sys/devices/virtual/dmi/id/sys_vendor")
		model, _ := os.ReadFile("/sys/devices/virtual/dmi/id/product_name")
		return strings.TrimSpace(string(brand)), strings.TrimSpace(string(model))
	default:
		return "", ""
	}
}

func commandOutput(name string, args ...string) string {
	output, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func readOSRelease() (string, string) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "", ""
	}
	defer func() {
		_ = file.Close()
	}()

	var id, version string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch key {
		case "ID":
			id = value
		case "VERSION_ID":
			version = value
		}
	}
	return id, version
}

func collectNetworkEnvironment() ([]string, []string) {
	macSet := make(map[string]struct{})
	ipSet := make(map[string]struct{})

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Warning: failed to list network interfaces for aTrust environment report: %v", err)
		return []string{}, []string{}
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if mac := strings.ToUpper(iface.HardwareAddr.String()); mac != "" {
			macSet[mac] = struct{}{}
		}

		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			ipSet[ip.String()] = struct{}{}
		}
	}

	macAddresses := mapKeys(macSet)
	clientIPs := mapKeys(ipSet)
	return macAddresses, clientIPs
}

func mapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}
