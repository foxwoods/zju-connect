package tun

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	singtun "github.com/mythologyli/sing-tun"
)

// Opt-in, root-only kernel regression: an unbound UDP socket must select the
// current VIP after each change, not the removed address. No packets are sent.
// Uses a dedicated temporary utun and documentation-only destinations; closing
// that interface removes its routes without touching other interfaces or DNS.
func TestDarwinVIPRouteSourceIntegration(t *testing.T) {
	if os.Getenv("ZJU_CONNECT_TUN_INTEGRATION") != "1" {
		t.Skip("set ZJU_CONNECT_TUN_INTEGRATION=1 and run as root for kernel route validation")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel route validation requires root")
	}
	oldIP, newIP := "100.127.255.250", "100.127.255.251"
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && (ip.String() == oldIP || ip.String() == newIP) {
			t.Fatalf("test VIP already exists: %s", ip)
		}
	}
	targets := []struct{ prefix, destination string }{
		{"192.0.2.254/32", "192.0.2.254"},
		{"198.51.100.252/30", "198.51.100.253"},
	}
	for _, target := range targets {
		output, err := exec.Command("route", "-n", "get", target.destination).CombinedOutput()
		if err != nil {
			t.Fatalf("check existing route: %v: %s", err, output)
		}
		// Other VPNs may have broad catch-all routes. Do not alter those, and
		// refuse to shadow any specific (/17 or longer) test-resource route.
		broadRoute := strings.Contains(string(output), "destination: default")
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "mask:" {
				if mask := net.ParseIP(fields[1]).To4(); mask != nil {
					bits, total := net.IPMask(mask).Size()
					broadRoute = total == 32 && bits <= 16
				}
			}
		}
		if !broadRoute {
			t.Fatalf("refusing to shadow an existing specific route for %s: %s", target.destination, output)
		}
	}
	name := singtun.CalculateInterfaceName("utun0")
	device, err := singtun.New(singtun.Options{Name: name, MTU: MTU, Inet4Address: []netip.Prefix{netip.MustParsePrefix(oldIP + "/32")}, AutoRoute: false})
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	ip := net.ParseIP(oldIP)
	s := &Stack{endpoint: &Endpoint{ifceName: name, ip: ip, tcpDialer: &net.Dialer{LocalAddr: &net.TCPAddr{IP: ip}}, udpDialer: &net.Dialer{LocalAddr: &net.UDPAddr{IP: ip}}}}
	for _, target := range targets {
		if err := s.AddRoute(target.prefix); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{oldIP, newIP, oldIP, newIP} {
		if err := s.updateIP(net.ParseIP(want)); err != nil {
			t.Fatal(err)
		}
		for _, target := range targets {
			conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(target.destination), Port: 9})
			if err != nil {
				t.Fatalf("unbound socket after VIP %s: %v", want, err)
			}
			got := conn.LocalAddr().(*net.UDPAddr).IP.String()
			conn.Close()
			if got != want {
				t.Fatalf("kernel selected source %s, want current VIP %s for %s", got, want, target.destination)
			}
			t.Logf("%s: kernel selected current source %s", target.destination, got)
		}
	}
}
