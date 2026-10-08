package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"opencode-go-cliproxyapi/internal/config"
)

func TestCredentialSecretLabelAndSaveRejection(t *testing.T) {
	bridge, f := credentialTestHost(t)
	m := NewManager(bridge)
	m.cfg.BaseURL = config.DefaultBaseURL
	resp := postCredential(t, m, `{"base_url":"https://host/v1","api_key":"oc_sk_dummy_redact","name":"Work oc_sk_dummy_redact"}`)
	if resp.StatusCode != 200 || strings.Contains(string(resp.Body), "oc_sk_dummy_redact") {
		t.Fatal("secret in successful response")
	}
	f.responder = func(method string, _ []byte) ([]byte, error) {
		if method == pluginabi.MethodHostAuthSave {
			return hostErr("save", "oc_sk_dummy_rejected"), nil
		}
		return hostOK(hostAuthListResponse{}), nil
	}
	resp = postCredential(t, m, `{"base_url":"https://host/v1","api_key":"oc_sk_dummy_rejected"}`)
	if resp.StatusCode != 502 || strings.Contains(string(resp.Body), "oc_sk_dummy_rejected") {
		t.Fatal("unredacted host rejection")
	}
	for _, call := range f.callsOf(pluginabi.MethodHostLog) {
		if strings.Contains(string(call.payload), "oc_sk_dummy_") {
			t.Fatal("secret logged")
		}
	}
}

func TestCredentialImportedDuplicateAndInspectionFailures(t *testing.T) {
	for _, tt := range []struct {
		name, raw, path string
		status          int
	}{
		{"imported duplicate", `{"type":"opencode-go","api_key":"imported-dummy"}`, "absolute", 409},
		{"invalid JSON", `{`, "absolute", 502},
		{"missing key", `{"type":"opencode-go"}`, "absolute", 502},
		{"unreadable", `{}`, "missing", 502},
		{"relative path", `{}`, "relative", 502},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "Imported.json")
			if err := os.WriteFile(path, []byte(tt.raw), 0600); err != nil {
				t.Fatal(err)
			}
			switch tt.path {
			case "missing":
				path = filepath.Join(t.TempDir(), "absent.json")
			case "relative":
				path = "Imported.json"
			}
			f := &fakeCaller{responder: func(_ string, _ []byte) ([]byte, error) {
				return hostOK(hostAuthListResponse{Files: []pluginapi.HostAuthFileEntry{{Provider: ProviderID, Name: "Imported.json", Path: path}}}), nil
			}}
			m := NewManager(NewHostBridge(f.call))
			m.cfg.BaseURL = config.DefaultBaseURL
			resp := postCredential(t, m, `{"base_url":"https://opencode.ai/zen/go/v1","api_key":"imported-dummy"}`)
			if resp.StatusCode != tt.status || len(f.callsOf(pluginabi.MethodHostAuthSave)) != 0 {
				t.Fatalf("status=%d", resp.StatusCode)
			}
		})
	}
}

func TestCredentialStorageURLAndInvalidExecution(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, tt := range []struct {
			name, attribute, storage, want string
			ok                             bool
		}{
			{"storage", "", `{"base_url":"https://storage.test/v1"}`, "https://storage.test/v1/chat/completions", true},
			{"attribute beats storage", "https://attribute.test/v1", `{"base_url":"https://storage.test/v1"}`, "https://attribute.test/v1/chat/completions", true},
			{"attribute beats malformed storage", "https://attribute.test/v1", `{`, "https://attribute.test/v1/chat/completions", true},
			{"bad storage", "", `{`, "", false},
			{"bad URL", "https://user:dummy@host/v1", `{}`, "", false},
			{"http disallowed", "http://host/v1", `{}`, "", false},
		} {
			t.Run(map[bool]string{false: "non-stream", true: "stream"}[stream]+"/"+tt.name, func(t *testing.T) {
				m, f := newStreamManager(t, streamScript{upstreamID: "up", frames: []string{"data: [DONE]\n\n"}})
				if !stream {
					f.responder = upstreamRouter(t, map[string]string{"/v1/chat/completions": ccResponseBody})
				}
				req := executorRequest{ExecutorRequest: pluginapi.ExecutorRequest{AuthProvider: ProviderID, AuthAttributes: map[string]string{"api_key": "dummy-selected", "base_url": tt.attribute}, StorageJSON: []byte(tt.storage), Model: "opencode-go/glm-5.3", SourceFormat: "openai", OriginalRequest: []byte(ccRequestBody), Stream: stream}, StreamID: "down"}
				method, hostMethod := pluginabi.MethodExecutorExecute, pluginabi.MethodHostHTTPDo
				if stream {
					method, hostMethod = pluginabi.MethodExecutorExecuteStream, pluginabi.MethodHostHTTPDoStream
				}
				before := len(f.callsOf(hostMethod))
				env := decodeEnv(t, mustHandle(t, m, method, mustJSON(req)))
				if env.OK != tt.ok {
					t.Fatalf("envelope=%+v", env.Error)
				}
				if tt.ok {
					if got := lastWire(t, f, hostMethod)["url"]; got != tt.want {
						t.Fatalf("URL=%v", got)
					}
				} else if len(f.callsOf(hostMethod)) != before {
					t.Fatal("invalid auth sent upstream")
				}
			})
		}
	}
}

func TestCredentialPanelQuotaFetchAndLabel(t *testing.T) {
	bridge, f := credentialTestHost(t)
	m := NewManager(bridge)
	m.cfg = config.Config{BaseURL: config.DefaultBaseURL, APIKeys: []config.APIKey{{Value: "same-dummy", Name: "Configured"}}}
	resp := postCredential(t, m, `{"base_url":"https://panel.test/v1","api_key":"same-dummy","name":"Panel"}`)
	var created struct {
		ID string `json:"id"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(resp.Body, &created) != nil {
		t.Fatal("create failed")
	}
	calls := f.callsOf(pluginabi.MethodHostAuthSave)
	var saved pluginapi.HostAuthSaveRequest
	if err := json.Unmarshal(calls[0].payload, &saved); err != nil {
		t.Fatal(err)
	}
	parsed, err := (authProvider{cfg: m.cfg}).ParseAuth(context.Background(), pluginapi.AuthParseRequest{Provider: ProviderID, FileName: saved.Name, RawJSON: saved.JSON})
	if err != nil || parsed.Auth.Label != "Panel" || parsed.Auth.ID != saved.Name {
		t.Fatal("panel identity/label not preserved")
	}
	original := f.responder
	f.responder = func(method string, payload []byte) ([]byte, error) {
		if method != pluginabi.MethodHostHTTPDo {
			return original(method, payload)
		}
		var req pluginapi.HTTPRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			t.Fatal(err)
		}
		if req.URL != "https://panel.test/v1/usage" {
			t.Fatalf("URL=%s", req.URL)
		}
		return hostOK(pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"usage":{"weekly":{"percent":5}}}`)}), nil
	}
	resp, err = m.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/v0/management/plugins/" + pluginName + "/quota-usage", Body: mustJSON(legacyQuotaRequest{KeyID: created.ID})})
	var card legacyQuotaCard
	if err != nil || json.Unmarshal(resp.Body, &card) != nil || card.KeyID != created.ID || card.Label != "Panel" || card.Usage == nil {
		t.Fatalf("quota=%s err=%v", resp.Body, err)
	}
}

func TestCredentialExplicitNamesSurviveParsingAndQuota(t *testing.T) {
	for _, name := range []string{"opencode-go-key-personal", "OpenCode Go credential Personal"} {
		bridge, _ := credentialTestHost(t)
		m := NewManager(bridge)
		m.cfg.BaseURL = config.DefaultBaseURL
		resp := postCredential(t, m, string(mustJSON(map[string]string{"base_url": "https://panel.test/v1", "api_key": "dummy-alias", "name": name})))
		if resp.StatusCode != http.StatusOK {
			t.Fatal("create failed")
		}
		entries, err := bridge.AuthList(context.Background())
		if err != nil || len(entries) != 1 {
			t.Fatal("list failed")
		}
		raw, err := os.ReadFile(entries[0].Path)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := (authProvider{cfg: m.cfg}).ParseAuth(context.Background(), pluginapi.AuthParseRequest{Provider: ProviderID, FileName: entries[0].Name, RawJSON: raw})
		if err != nil || parsed.Auth.Label != name {
			t.Fatalf("parsed label=%s err=%v", parsed.Auth.Label, err)
		}
		records, err := m.quotaCredentials(context.Background(), m.cfg, false)
		if err != nil || len(records) != 1 || records[0].Label != name {
			t.Fatal("quota label changed")
		}
	}
}

func TestCredentialBrokenFileDoesNotBreakConfiguredQuota(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Broken.json")
	if err := os.WriteFile(path, []byte(`{`), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakeCaller{responder: func(method string, _ []byte) ([]byte, error) {
		if method == pluginabi.MethodHostAuthList {
			return hostOK(hostAuthListResponse{Files: []pluginapi.HostAuthFileEntry{{Provider: ProviderID, Path: path}}}), nil
		}
		return hostOK(pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"usage":{"rolling":{"percent":5}}}`)}), nil
	}}
	m := NewManager(NewHostBridge(f.call))
	m.cfg = config.Config{BaseURL: config.DefaultBaseURL, APIKeys: []config.APIKey{{Value: "healthy-dummy"}}}
	id, _ := quotaIdentity("healthy-dummy")
	resp, err := m.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/v0/management/plugins/" + pluginName + "/quota-usage", Body: mustJSON(legacyQuotaRequest{KeyID: id})})
	var card legacyQuotaCard
	if err != nil || json.Unmarshal(resp.Body, &card) != nil || card.Usage == nil {
		t.Fatalf("quota=%s err=%v", resp.Body, err)
	}
	if resp := postCredential(t, m, `{"base_url":"https://new.test/v1","api_key":"new-dummy"}`); resp.StatusCode != 502 {
		t.Fatal("duplicate inspection did not fail closed")
	}
}

func TestCredentialColdStartDifferentBaseDoesNotHideConfiguredKey(t *testing.T) {
	for _, base := range []string{config.DefaultBaseURL, "https://different.test/v1"} {
		bridge, f := credentialTestHost(t)
		m := NewManager(bridge)
		m.cfg.BaseURL = config.DefaultBaseURL
		if resp := postCredential(t, m, `{"base_url":"`+base+`","api_key":"cold-start-dummy"}`); resp.StatusCode != 200 {
			t.Fatal("create failed")
		}
		cfg := config.Config{BaseURL: config.DefaultBaseURL, APIKeys: []config.APIKey{{Value: "cold-start-dummy"}}}
		if err := m.materializeAuthRecords(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		want := 1
		if base != config.DefaultBaseURL {
			want = 2
		}
		if got := len(f.callsOf(pluginabi.MethodHostAuthSave)); got != want {
			t.Fatalf("saves=%d want=%d", got, want)
		}
	}
}
