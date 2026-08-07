package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

func TestEndpointStrategyAndReportEnv(t *testing.T) {
	const (
		loginTicket  = "login-ticket"
		reportTicket = "report-ticket"
		deviceID     = "device-id"
	)

	strategyCalled := false
	reportCalled := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/controller/v1/public/endpointStrategy":
			strategyCalled = true
			if r.Method != http.MethodGet {
				t.Errorf("endpointStrategy method = %s, want GET", r.Method)
			}
			if got := r.URL.Query().Get("ticket"); got != loginTicket {
				t.Errorf("endpointStrategy ticket = %q, want %q", got, loginTicket)
			}
			if got := r.URL.Query().Get("timing"); got != "pre-login" {
				t.Errorf("endpointStrategy timing = %q, want pre-login", got)
			}
			if got := r.URL.Query().Get("platform"); got != platformForGOOS(runtime.GOOS) {
				t.Errorf("endpointStrategy platform = %q, want %q", got, platformForGOOS(runtime.GOOS))
			}
			_, _ = w.Write([]byte(`{"code":0,"message":"OK","data":{"ticket":"report-ticket","interval":0}}`))

		case "/controller/v1/public/reportEnv":
			reportCalled = true
			if r.Method != http.MethodPost {
				t.Errorf("reportEnv method = %s, want POST", r.Method)
			}
			var payload struct {
				Ticket   string `json:"ticket"`
				DeviceID string `json:"deviceId"`
				Env      struct {
					Endpoint endpointEnvironment `json:"endpoint"`
				} `json:"env"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode reportEnv payload: %v", err)
			}
			if payload.Ticket != reportTicket {
				t.Errorf("reportEnv ticket = %q, want %q", payload.Ticket, reportTicket)
			}
			if payload.DeviceID != deviceID || payload.Env.Endpoint.DeviceID != deviceID {
				t.Errorf("reportEnv device IDs = %q/%q, want %q", payload.DeviceID, payload.Env.Endpoint.DeviceID, deviceID)
			}
			if payload.Env.Endpoint.OS.Family == "" {
				t.Error("reportEnv must include endpoint.os.family")
			}
			_, _ = w.Write([]byte(`{"code":0,"message":"OK"}`))

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &Session{
		client:    server.Client(),
		baseURL:   server.URL,
		ticket:    loginTicket,
		deviceID:  deviceID,
		csrfToken: "csrf-token",
	}

	gotReportTicket, err := session.endpointStrategy("pre-login")
	if err != nil {
		t.Fatalf("endpointStrategy: %v", err)
	}
	if gotReportTicket != reportTicket {
		t.Fatalf("report ticket = %q, want %q", gotReportTicket, reportTicket)
	}
	if err := session.reportEnv(gotReportTicket); err != nil {
		t.Fatalf("reportEnv: %v", err)
	}
	if !strategyCalled || !reportCalled {
		t.Fatalf("strategy/report calls = %t/%t, want both true", strategyCalled, reportCalled)
	}
}

func TestEndpointStrategyRejectsEmptyReportTicket(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"message":"OK","data":{"ticket":""}}`))
	}))
	defer server.Close()

	session := &Session{client: server.Client(), baseURL: server.URL, ticket: "login-ticket"}
	if _, err := session.endpointStrategy("pre-login"); err == nil {
		t.Fatal("endpointStrategy returned nil error for an empty report ticket")
	}
}
