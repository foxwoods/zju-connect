package atrust

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type blockingUnderlayDialer struct{}

func (blockingUnderlayDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// Exercise the real SetupContext -> deferred cleanup -> periodic Refresh path,
// without logging in to a real gateway or using any real credentials.
func TestSetupSessionOutlivesSetupContext(t *testing.T) {
	var refreshes atomic.Int32
	enteredRefresh := make(chan struct{}, 1)
	blockedRefreshCanceled := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/manifest":
			io.WriteString(w, `{"code":0,"data":{}}`)
		case "/passport/v1/public/authConfig":
			if refreshes.Add(1) == 1 {
				io.WriteString(w, `{"code":0,"data":{"isLogin":1}}`)
				return
			}
			enteredRefresh <- struct{}{}
			<-r.Context().Done()
			blockedRefreshCanceled <- struct{}{}
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "https://")
	host, port, _ := net.SplitHostPort(addr)
	portNum, _ := strconv.Atoi(port)
	dialer := setupTestDialer{tlsConfig: server.TLS}
	c := NewClient(ClientOptions{
		UnderlayDialer: dialer,
		Session:        SessionOptions{SID: "test-sid", DeviceID: "test-device"},
	})
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	persisted := make(chan struct{}, 4)
	_, err := c.SetupContext(ctx, SetupOptions{
		ServerAddress: host, ServerPort: portNum,
		ResourceData:           []byte(`{"data":{"appList":{"data":{"config":{"nodeGroupConf":{"majorNodeGroup":{"id":"test"},"nodeGroupList":[{"id":"test","addressInfo":[{"address":"node.example:441","type":"wan"}]}]}}}}}}`),
		SessionRefreshInterval: 20 * time.Millisecond,
		SaveClientData:         func([]byte) error { persisted <- struct{}{}; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	<-persisted // initial setup save, not a periodic refresh
	cancel()    // caller's setup context must no longer own the live session
	select {
	case <-persisted:
	case <-time.After(time.Second):
		t.Fatalf("session refresh failed after SetupContext returned; gateway refresh requests = %d", refreshes.Load())
	}
	select {
	case <-enteredRefresh:
	case <-time.After(time.Second):
		t.Fatal("second refresh did not start")
	}
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel in-flight refresh")
	}
	select {
	case <-blockedRefreshCanceled:
	case <-time.After(time.Second):
		t.Fatal("gateway request was not canceled on Close")
	}
}

type setupTestDialer struct{ tlsConfig *tls.Config }

func (d setupTestDialer) ExcludeIP(net.IP) {}

func (d setupTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address != "node.example:441" {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	local, remote := net.Pipe()
	go func() {
		conn := tls.Server(remote, d.tlsConfig)
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		// Node probes handshake and close; only the IP request sends data.
		header := make([]byte, 7)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		payload := make([]byte, int(binary.BigEndian.Uint16(header[5:7]))+10)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		response := append([]byte{0x05, 0xD0, 0x53, 0x00, 0x00, 0x0A}, []byte(`{"code":0}`)...)
		// Auth JSON is 10 bytes. Then the IPv4 VIP header and payload.
		response = append(response, l3Version, 0x00, 0x00, 0x01, 100, 64, 0, 1, 0, 0)
		conn.Write(response)
		io.Copy(io.Discard, conn)
	}()
	return local, nil
}

func (blockingUnderlayDialer) ExcludeIP(net.IP) {}

func TestSetupContextCancellationReachesManifestDial(t *testing.T) {
	client := NewClient(ClientOptions{UnderlayDialer: blockingUnderlayDialer{}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.SetupContext(ctx, SetupOptions{ServerAddress: "vpn.example", ServerPort: 443})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetupContext did not cancel in-flight manifest dial")
	}
}

func TestClientCloseCancelsSetupContext(t *testing.T) {
	client := NewClient(ClientOptions{UnderlayDialer: blockingUnderlayDialer{}})
	done := make(chan error, 1)
	go func() {
		_, err := client.SetupContext(context.Background(), SetupOptions{ServerAddress: "vpn.example", ServerPort: 443})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	client.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Client.Close did not cancel in-flight setup")
	}
}
