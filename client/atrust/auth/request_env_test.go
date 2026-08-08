package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

func TestEndpointStrategyAndReportEnv(t *testing.T) {
	const (
		endpointTicket = "endpoint-ticket"
		reportTicket   = "report-ticket"
		deviceID       = "device-id"
		signKey        = "447fc3fa0a20f4e5159737428d20d96d91efef011b432049a2c73250c0f44125"
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
			if got := r.URL.Query().Get("ticket"); got != endpointTicket {
				t.Errorf("endpointStrategy ticket = %q, want %q", got, endpointTicket)
			}
			if got := r.URL.Query().Get("timing"); got != "pre-login" {
				t.Errorf("endpointStrategy timing = %q, want pre-login", got)
			}
			if got := r.URL.Query().Get("platform"); got != platformForGOOS(runtime.GOOS) {
				t.Errorf("endpointStrategy platform = %q, want %q", got, platformForGOOS(runtime.GOOS))
			}
			if got := r.URL.Query().Get("clientType"); got != "SDPClient" {
				t.Errorf("endpointStrategy clientType = %q, want SDPClient", got)
			}
			wantQuery := "timing=pre-login&ticket=endpoint-ticket&platform=" + platformForGOOS(runtime.GOOS) + "&clientType=SDPClient"
			if r.URL.RawQuery != wantQuery {
				t.Errorf("endpointStrategy query = %q, want %q", r.URL.RawQuery, wantQuery)
			}
			if got, want := r.Header.Get("X-Request-Sig"), antiMITMRequestSignature(signKey, r.URL.RequestURI(), nil); got != want {
				t.Errorf("endpointStrategy request signature = %q, want %q", got, want)
			}
			w.Header().Set("x-sdp-random", "interface-random")
			_, _ = w.Write([]byte(`{"code":0,"message":"OK","data":{"ticket":"report-ticket","interval":0}}`))

		case "/controller/v1/public/reportEnv":
			reportCalled = true
			if r.Method != http.MethodPost {
				t.Errorf("reportEnv method = %s, want POST", r.Method)
			}
			if got := r.URL.Query().Get("platform"); got != platformForGOOS(runtime.GOOS) {
				t.Errorf("reportEnv platform = %q, want %q", got, platformForGOOS(runtime.GOOS))
			}
			if got := r.URL.Query().Get("lang"); got != "" {
				t.Errorf("reportEnv lang = %q, want empty", got)
			}
			wantQuery := "platform=" + platformForGOOS(runtime.GOOS) + "&clientType=SDPClient"
			if r.URL.RawQuery != wantQuery {
				t.Errorf("reportEnv query = %q, want %q", r.URL.RawQuery, wantQuery)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read reportEnv payload: %v", err)
			}
			if got, want := r.Header.Get("x-sdp-signature"), interfaceRequestSignature("interface-random", body); got != want {
				t.Errorf("reportEnv signature = %q, want %q", got, want)
			}
			if got, want := r.Header.Get("X-Request-Sig"), antiMITMRequestSignature(signKey, r.URL.RequestURI(), body); got != want {
				t.Errorf("reportEnv request signature = %q, want %q", got, want)
			}
			var payload struct {
				DeviceID string                 `json:"deviceId"`
				AccessIP string                 `json:"accessIp"`
				Env      map[string]interface{} `json:"env"`
				Failure  []interface{}          `json:"failure"`
				Ticket   string                 `json:"ticket"`
				Timing   string                 `json:"timing"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode reportEnv payload: %v", err)
			}
			if payload.Ticket != reportTicket {
				t.Errorf("reportEnv ticket = %q, want report ticket %q", payload.Ticket, reportTicket)
			}
			if payload.DeviceID != deviceID {
				t.Errorf("reportEnv deviceId = %q, want %q", payload.DeviceID, deviceID)
			}
			if payload.AccessIP != "" || payload.Failure == nil {
				t.Errorf("reportEnv base result = accessIp:%q env:%v failure:%v", payload.AccessIP, payload.Env, payload.Failure)
			}
			for _, key := range []string{
				"endpoint.os.hostname",
				"endpoint.device_id",
				"endpoint.atrust_client.version",
				"endpoint.mac_addresses",
				"endpoint.client_ips",
				"endpoint.security.is_firewall_enabled",
				"endpoint.uem_client.secure_events",
			} {
				if _, ok := payload.Env[key]; !ok {
					t.Errorf("reportEnv environment is missing %q", key)
				}
			}
			if _, nested := payload.Env["endpoint"]; nested {
				t.Error("reportEnv environment must use flat dotted keys")
			}
			if payload.Timing != "pre-login" {
				t.Errorf("reportEnv timing = %q, want pre-login", payload.Timing)
			}
			_, _ = w.Write([]byte(`{"code":0,"message":"OK"}`))

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &Session{
		client:          server.Client(),
		baseURL:         server.URL,
		endpointTicket:  endpointTicket,
		deviceID:        deviceID,
		csrfToken:       "csrf-token",
		antiMITMSignKey: signKey,
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

	session := &Session{client: server.Client(), baseURL: server.URL, endpointTicket: "endpoint-ticket"}
	if _, err := session.endpointStrategy("pre-login"); err == nil {
		t.Fatal("endpointStrategy returned nil error for an empty report ticket")
	}
}
