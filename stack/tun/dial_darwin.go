package tun

import (
	"context"
	"net"

	"github.com/mythologyli/zju-connect/resolve"
	"inet.af/netaddr"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if s.endpoint.client.CanUseTCPTunnel() && !resolve.TCPPrefersL3(ctx) {
		return s.endpoint.client.DialTCP(ctx, addr)
	}

	s.endpoint.configMu.RLock()
	dialer := net.Dialer{}
	prefix, ok := netaddr.FromStdIP(addr.IP)
	if ok && s.endpoint.ipSet != nil && s.endpoint.ipSet.Contains(prefix) {
		// Snapshot the options while locked: updateIP replaces LocalAddr.
		// Never hold the lock across I/O, which may itself need a VIP update.
		dialer = *s.endpoint.tcpDialer
	}
	s.endpoint.configMu.RUnlock()
	return dialer.DialContext(ctx, "tcp4", addr.String())
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	s.endpoint.configMu.RLock()
	dialer := net.Dialer{}
	prefix, ok := netaddr.FromStdIP(addr.IP)
	if ok && s.endpoint.ipSet != nil && s.endpoint.ipSet.Contains(prefix) {
		dialer = *s.endpoint.udpDialer
	}
	s.endpoint.configMu.RUnlock()
	return dialer.DialContext(ctx, "udp4", addr.String())
}
