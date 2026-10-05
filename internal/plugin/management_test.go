package plugin

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"

	"opencode-go-cliproxyapi/internal/config"
)

func TestManagementRegistrationIncludesQuotaResource(t *testing.T) {
	m := NewManager(nil)
	var got struct {
		Routes    []struct{ Method, Path string }            `json:"routes"`
		Resources []struct{ Path, Menu, Description string } `json:"resources"`
	}
	decodeResult(t, mustHandle(t, m, pluginabi.MethodManagementRegister, []byte(`{}`)), &got)
	if len(got.Routes) != 1 || got.Routes[0].Method != http.MethodPost || got.Routes[0].Path != "/plugins/"+pluginName+"/quota-usage" {
		t.Fatalf("routes = %+v", got.Routes)
	}
	if len(got.Resources) != 1 || got.Resources[0].Path != "/quota" || got.Resources[0].Menu != "OpenCode Go Quota" {
		t.Fatalf("resources = %+v", got.Resources)
	}
	var registration registrationResult
	decodeResult(t, registrationEnvelope(), &registration)
	if !registration.Capabilities.ManagementAPI {
		t.Fatal("registration did not advertise management_api")
	}
}

func TestLegacyQuotaResourceUsesNativeQuotaProvider(t *testing.T) {
	const key = "legacy-quota-key"
	f := &fakeCaller{responder: func(method string, payload []byte) ([]byte, error) {
		if method != pluginabi.MethodHostHTTPDo {
			return hostOK(map[string]any{}), nil
		}
		var req pluginapi.HTTPRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			t.Fatal(err)
		}
		if req.URL != "https://quota.test/v1/usage" || req.Headers.Get("Authorization") != "Bearer "+key {
			t.Fatalf("unexpected quota request: %+v", req)
		}
		return hostOK(pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"usage":{"rolling":{"percent":12,"resetsAt":"2026-10-05T06:00:00Z"},"weekly":{"percent":8},"monthly":{"percent":5}}}`)}), nil
	}}
	m := NewManager(NewHostBridge(f.call))
	m.cfg = config.Config{BaseURL: "https://quota.test/v1", RequestTimeout: config.DefaultRequestTimeout, APIKeys: []config.APIKey{{Value: key}}}
	id, _ := quotaIdentity(key)
	resp, err := m.HandleManagement(context.Background(), pluginapi.ManagementRequest{
		Method: http.MethodPost,
		Path:   "/v0/management/plugins/" + pluginName + "/quota-usage",
		Body:   []byte(`{"key_id":"` + id + `"}`),
	})
	if err != nil || resp.StatusCode != 0 {
		t.Fatalf("quota response = %+v err=%v", resp, err)
	}
	var card legacyQuotaCard
	if err := json.Unmarshal(resp.Body, &card); err != nil {
		t.Fatal(err)
	}
	if card.Usage == nil || math.Abs(card.Usage.Rolling.Percent-12) > 1e-9 || math.Abs(card.Usage.Weekly.Percent-8) > 1e-9 || math.Abs(card.Usage.Monthly.Percent-5) > 1e-9 {
		t.Fatalf("usage = %+v", card.Usage)
	}
	resource, err := m.HandleManagement(context.Background(), pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/resource/plugins/" + pluginName + "/quota",
	})
	if err != nil || resource.Headers.Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(string(resource.Body), "OpenCode Go Quota") {
		t.Fatalf("resource = %+v err=%v", resource, err)
	}
}
