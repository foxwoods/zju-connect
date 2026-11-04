package tun

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
)

type l3OnlyTestClient struct{ client.Client }

func (l3OnlyTestClient) CanUseTCPTunnel() bool { return false }

func newLoopbackDialStack(t *testing.T, resource bool) *Stack {
	t.Helper()
	s, _ := newRouteTestStack()
	s.endpoint.client = l3OnlyTestClient{}
	target := "192.0.2.1/32"
	if resource {
		target = "127.0.0.1/32"
	}
	if err := s.AddRoute(target); err != nil {
		t.Fatal(err)
	}
	// No real routes or interfaces are modified; sockets are loopback-only.
	s.endpoint.tcpDialer = &net.Dialer{Timeout: 2 * time.Second}
	s.endpoint.udpDialer = &net.Dialer{Timeout: 2 * time.Second}
	return s
}

func loopbackDial(t *testing.T, s *Stack, network string) func(context.Context) (net.Conn, error) {
	t.Helper()
	if network == "tcp" {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		return func(ctx context.Context) (net.Conn, error) { return s.DialTCP(ctx, listener.Addr().(*net.TCPAddr)) }
	}
	return func(ctx context.Context) (net.Conn, error) {
		return s.DialUDP(ctx, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	}
}

func TestVIPUpdateDoesNotWaitForPendingDial(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			s := newLoopbackDialStack(t, true)
			dial := loopbackDial(t, s, network)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			control := func(string, string, syscall.RawConn) error {
				close(entered)
				select {
				case <-release:
					return nil
				case <-time.After(2 * time.Second):
					return errors.New("test dial safety timeout")
				}
			}
			if network == "tcp" {
				s.endpoint.tcpDialer.Control = control
			} else {
				s.endpoint.udpDialer.Control = control
			}
			dialDone := make(chan error, 1)
			go func() {
				conn, err := dial(context.Background())
				if conn != nil {
					conn.Close()
				}
				dialDone <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("dial did not reach controlled stall")
			}
			updateDone := make(chan error, 1)
			go func() { updateDone <- s.updateIP(net.ParseIP("100.64.0.2")) }()
			blocked := false
			select {
			case err := <-updateDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(100 * time.Millisecond):
				blocked = true
				t.Error("VIP update blocked by pending dial holding configMu.RLock")
			}
			unblock()
			select {
			case err := <-dialDone:
				if err != nil {
					t.Errorf("loopback dial: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("dial did not finish")
			}
			if blocked {
				select {
				case err := <-updateDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("VIP update still blocked after dial finished")
				}
			}
		})
	}
}

func TestDarwinDialRespectsCanceledContext(t *testing.T) {
	for _, resource := range []bool{true, false} {
		path := "direct"
		if resource {
			path = "tun"
		}
		for _, network := range []string{"tcp", "udp"} {
			for _, expired := range []bool{false, true} {
				state := "canceled"
				if expired {
					state = "deadline"
				}
				t.Run(path+"/"+network+"/"+state, func(t *testing.T) {
					s := newLoopbackDialStack(t, resource)
					dial := loopbackDial(t, s, network)
					ctx, cancel := context.WithCancel(context.Background())
					want := context.Canceled
					if expired {
						cancel()
						ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
						want = context.DeadlineExceeded
					}
					cancel()
					conn, err := dial(ctx)
					if conn != nil {
						conn.Close()
					}
					if !errors.Is(err, want) {
						t.Fatalf("got connection=%t error=%v, want %v", conn != nil, err, want)
					}
				})
			}
		}
	}
}

func TestDarwinDialCancelsInFlight(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			s := newLoopbackDialStack(t, true)
			dial := loopbackDial(t, s, network)
			entered := make(chan struct{})
			control := func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
				close(entered)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(2 * time.Second):
					return errors.New("test dial safety timeout")
				}
			}
			if network == "tcp" {
				s.endpoint.tcpDialer.ControlContext = control
			} else {
				s.endpoint.udpDialer.ControlContext = control
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := dial(ctx)
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("dial did not start")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("in-flight dial ignored caller cancellation")
			}
		})
	}
}
