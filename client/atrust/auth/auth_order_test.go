package auth

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type orderRecordingLogin struct {
	steps *[]string
}

func (m orderRecordingLogin) AuthType() string {
	return "auth/psw"
}

func (m orderRecordingLogin) LoginDomain() string {
	return "local"
}

func (m orderRecordingLogin) login(_ *Session, _ AuthInfo) error {
	*m.steps = append(*m.steps, "credential")
	return nil
}

func TestLoginReportsEndpointEnvironmentAfterCredentialAndBeforeAuthCheck(t *testing.T) {
	var steps []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/passport/v1/public/authConfig":
			steps = append(steps, "authConfig")
			_, _ = w.Write([]byte(`{"code":0,"data":{"isLogin":0,"authServerInfoList":[{"loginDomain":"local","authType":"auth/psw"}],"antiMITMAttackData":{"ticket":"endpoint-ticket"}}}`))
		case "/controller/v1/public/endpointStrategy":
			steps = append(steps, "endpointStrategy")
			w.Header().Set("x-sdp-random", "interface-random")
			_, _ = w.Write([]byte(`{"code":0,"data":{"ticket":"report-ticket"}}`))
		case "/controller/v1/public/reportEnv":
			steps = append(steps, "reportEnv")
			_, _ = w.Write([]byte(`{"code":0}`))
		case "/passport/v1/auth/authCheck":
			steps = append(steps, "authCheck")
			_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
		case "/passport/v1/user/onlineInfo":
			steps = append(steps, "onlineInfo")
			_, _ = w.Write([]byte(`{"code":0,"data":{"username":"tester"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")
	session := NewSession(host, nil)
	session.client.Transport = server.Client().Transport

	result, err := session.Login(orderRecordingLogin{steps: &steps}, LoginOptions{DeviceID: "device-id"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.Username != "tester" {
		t.Fatalf("username = %q, want tester", result.Username)
	}

	want := []string{"authConfig", "credential", "endpointStrategy", "reportEnv", "authCheck", "onlineInfo"}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("login request order = %v, want %v", steps, want)
	}
}
