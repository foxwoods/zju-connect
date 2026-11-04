package tun

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

type routeState struct {
	addresses map[string]bool
	routes    map[string]string
	commands  []string
	fail      []string
}

func (r *routeState) run(name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, cmd)
	if len(r.fail) > 0 && strings.Contains(cmd, r.fail[0]) {
		r.fail = r.fail[1:]
		return nil, errors.New("injected command failure")
	}
	if name == "ifconfig" {
		if args[len(args)-1] == "alias" {
			r.addresses[args[2]] = true
		} else {
			delete(r.addresses, args[2])
		}
	} else if name == "route" {
		ip := "100.64.0.1" // kernel's cached source from the original address
		for i, arg := range args {
			if arg == "-ifa" {
				ip = args[i+1]
			}
		}
		r.routes[args[3]] = ip
	}
	return nil, nil
}

func newRouteTestStack() (*Stack, *routeState) {
	ip := net.ParseIP("100.64.0.1")
	r := &routeState{addresses: map[string]bool{ip.String(): true}, routes: map[string]string{"203.0.113.1/32": "other-vpn"}}
	s := &Stack{endpoint: &Endpoint{ifceName: "utun-test", ip: ip, command: r.run,
		tcpDialer: &net.Dialer{LocalAddr: &net.TCPAddr{IP: ip}}, udpDialer: &net.Dialer{LocalAddr: &net.UDPAddr{IP: ip}}}}
	return s, r
}

func TestUpdateIPRefreshesOnlyManagedRoutes(t *testing.T) {
	s, r := newRouteTestStack()
	for _, target := range []string{"192.0.2.1/32", "198.51.100.0/24"} {
		if err := s.AddRoute(target); err != nil {
			t.Fatal(err)
		}
	}
	for _, ip := range []string{"100.64.0.2", "100.64.0.1"} {
		if err := s.updateIP(net.ParseIP(ip)); err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{"192.0.2.1/32", "198.51.100.0/24"} {
			if r.routes[target] != ip {
				t.Fatalf("%s retains stale source %s after VIP changed to %s", target, r.routes[target], ip)
			}
		}
		if r.routes["203.0.113.1/32"] != "other-vpn" {
			t.Fatal("changed another VPN's route")
		}
		if len(r.addresses) != 1 || !r.addresses[ip] {
			t.Fatalf("addresses = %v", r.addresses)
		}
		if s.endpoint.tcpDialer.LocalAddr.(*net.TCPAddr).IP.String() != ip || s.endpoint.udpDialer.LocalAddr.(*net.UDPAddr).IP.String() != ip {
			t.Fatal("stale dialer address")
		}
	}
	before := len(r.commands)
	if err := s.updateIP(net.ParseIP("100.64.0.1")); err != nil {
		t.Fatal(err)
	}
	if len(r.commands) != before {
		t.Fatal("same VIP should not change network state")
	}
}

func TestUpdateIPRollsBackRoutesAndAddress(t *testing.T) {
	for _, fail := range []string{"ifconfig utun-test inet 100.64.0.2", "change -net 198.51.100.0/24", "ifconfig utun-test inet 100.64.0.1 -alias"} {
		t.Run(fail, func(t *testing.T) {
			s, r := newRouteTestStack()
			for _, target := range []string{"192.0.2.1/32", "198.51.100.0/24"} {
				if err := s.AddRoute(target); err != nil {
					t.Fatal(err)
				}
			}
			want := map[string]string{}
			for target, ip := range r.routes {
				want[target] = ip
			}
			r.fail = []string{fail}
			if err := s.updateIP(net.ParseIP("100.64.0.2")); err == nil {
				t.Fatal("expected injected failure")
			}
			if !reflect.DeepEqual(want, r.routes) {
				t.Fatalf("routes not rolled back: %v", r.routes)
			}
			if len(r.addresses) != 1 || !r.addresses["100.64.0.1"] {
				t.Fatalf("addresses not rolled back: %v", r.addresses)
			}
			if s.endpoint.ip.String() != "100.64.0.1" {
				t.Fatal("committed VIP despite failure")
			}
		})
	}
}

func TestFailedAddRouteIsNotManaged(t *testing.T) {
	s, r := newRouteTestStack()
	r.fail = []string{"add -net 192.0.2.1/32"}
	if err := s.AddRoute("192.0.2.1/32"); err == nil {
		t.Fatal("expected route add failure")
	}
	if err := s.updateIP(net.ParseIP("100.64.0.2")); err != nil {
		t.Fatal(err)
	}
	if _, exists := r.routes["192.0.2.1/32"]; exists {
		t.Fatal("refreshed a route that we never installed")
	}
	before := len(r.commands)
	if err := s.AddRoute("not-a-prefix"); err == nil {
		t.Fatal("accepted invalid route")
	}
	if len(r.commands) != before {
		t.Fatal("invalid prefix reached OS command")
	}
}

func TestUpdateIPKeepsAliasIfRouteRollbackFails(t *testing.T) {
	s, r := newRouteTestStack()
	for _, target := range []string{"192.0.2.1/32", "198.51.100.0/24"} {
		if err := s.AddRoute(target); err != nil {
			t.Fatal(err)
		}
	}
	r.fail = []string{"change -net 198.51.100.0/24", "change -net 192.0.2.1/32"}
	err := s.updateIP(net.ParseIP("100.64.0.2"))
	if err == nil || !strings.Contains(err.Error(), "incomplete route rollback") {
		t.Fatalf("got %v, want rollback error", err)
	}
	if !r.addresses["100.64.0.2"] || !r.addresses["100.64.0.1"] {
		t.Fatalf("removed a still-referenced address: %v", r.addresses)
	}
	if s.endpoint.ip.String() != "100.64.0.1" {
		t.Fatal("committed VIP despite rollback failure")
	}
}
