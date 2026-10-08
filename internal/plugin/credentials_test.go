package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"opencode-go-cliproxyapi/internal/config"
)

// Model the host's persisted auth list, including a fresh Manager after restart.
func credentialTestHost(t *testing.T) (*HostBridge, *fakeCaller) {
	t.Helper()
	dir := t.TempDir()
	var mu sync.Mutex
	files := []pluginapi.HostAuthFileEntry{}
	f := &fakeCaller{responder: func(method string, payload []byte) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		switch method {
		case pluginabi.MethodHostAuthList:
			return hostOK(hostAuthListResponse{Files: files}), nil
		case pluginabi.MethodHostAuthSave:
			var req pluginapi.HostAuthSaveRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				return nil, err
			}
			path := filepath.Join(dir, req.Name)
			if err := os.WriteFile(path, req.JSON, 0600); err != nil {
				return nil, err
			}
			var record struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(req.JSON, &record); err != nil {
				return nil, err
			}
			files = append(files, pluginapi.HostAuthFileEntry{ID: record.ID, Name: req.Name, Path: path, Provider: ProviderID})
		}
		return hostOK(struct{}{}), nil
	}}
	return NewHostBridge(f.call), f
}

func postCredential(t *testing.T, m *Manager, body string) pluginapi.ManagementResponse {
	t.Helper()
	var resp pluginapi.ManagementResponse
	decodeResult(t, mustHandle(t, m, pluginabi.MethodManagementHandle, mustJSON(pluginapi.ManagementRequest{
		Method: http.MethodPost, Path: "/v0/management/plugins/" + pluginName + "/credentials", Body: []byte(body),
	})), &resp)
	return resp
}

func TestCredentialCreatePersistDuplicateAndQuota(t *testing.T) {
	const key = "oc_sk_dummy_form_key"
	bridge, f := credentialTestHost(t)
	m := NewManager(bridge)
	m.cfg = config.Config{BaseURL: config.DefaultBaseURL, APIKeys: []config.APIKey{{Value: "dummy-config"}}}
	body := `{"base_url":"https://form.test/v1/","api_key":"` + key + `","name":"Personal","unknown":true}`
	resp := postCredential(t, m, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
	}
	var got struct {
		OK    bool   `json:"ok"`
		ID    string `json:"id"`
		Label string `json:"label"`
	}
	if err := json.Unmarshal(resp.Body, &got); err != nil {
		t.Fatal(err)
	}
	if !got.OK || !strings.HasPrefix(got.ID, "opencode-go-key-") || got.Label != "Personal" || strings.Contains(string(resp.Body), key) {
		t.Fatal("invalid or unredacted response")
	}
	entries, err := bridge.AuthList(context.Background())
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	raw, err := os.ReadFile(entries[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["type"] != ProviderID || stored["label"] != "Personal" || stored["id"] != got.ID || stored["api_key"] != key || stored["base_url"] != "https://form.test/v1" {
		t.Fatal("incorrect stored credential")
	}
	parsed, err := (authProvider{cfg: m.cfg}).ParseAuth(context.Background(), pluginapi.AuthParseRequest{Provider: ProviderID, RawJSON: raw})
	if err != nil || parsed.Auth.Attributes["base_url"] != stored["base_url"] || parsed.Auth.Label != "Personal" {
		t.Fatalf("parse: %v", err)
	}
	// Duplicates are recognized from disk, not a process-local cache.
	restarted := NewManager(bridge)
	restarted.cfg = m.cfg
	duplicate := postCredential(t, restarted, strings.ReplaceAll(body, "/v1/", "/v1"))
	if duplicate.StatusCode != http.StatusConflict || !strings.Contains(string(duplicate.Body), "already exists") {
		t.Fatalf("duplicate=%d %s", duplicate.StatusCode, duplicate.Body)
	}
	if len(f.callsOf(pluginabi.MethodHostAuthSave)) != 1 {
		t.Fatal("duplicate wrote a credential")
	}
	list, err := restarted.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/v0/management/plugins/" + pluginName + "/quota-usage", Body: []byte(`{}`)})
	var cards legacyQuotaList
	if err != nil || json.Unmarshal(list.Body, &cards) != nil || len(cards.Cards) != 2 {
		t.Fatalf("quota list=%s err=%v", list.Body, err)
	}
	if cards.Cards[1].KeyID != got.ID || cards.Cards[1].Label != "Personal" {
		t.Fatalf("card=%+v", cards.Cards[1])
	}
	for _, call := range f.callsOf(pluginabi.MethodHostLog) {
		if strings.Contains(string(call.payload), key) {
			t.Fatal("key logged")
		}
	}
	different := postCredential(t, restarted, strings.ReplaceAll(body, "form.test", "other.test"))
	if different.StatusCode != http.StatusOK {
		t.Fatalf("different base URL: %s", different.Body)
	}
}

func TestCredentialValidation(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		allowHTTP  bool
		status     int
	}{
		{"missing URL", `{"api_key":"dummy"}`, false, 400},
		{"empty URL", `{"base_url":"","api_key":"dummy"}`, false, 400},
		{"relative URL", `{"base_url":"/v1","api_key":"dummy"}`, false, 400},
		{"missing host", `{"base_url":"https:///v1","api_key":"dummy"}`, false, 400},
		{"unsupported scheme", `{"base_url":"ftp://host/v1","api_key":"dummy"}`, false, 400},
		{"userinfo", `{"base_url":"https://user:dummy@host/v1","api_key":"dummy"}`, false, 400},
		{"query", `{"base_url":"https://host/v1?q=dummy","api_key":"dummy"}`, false, 400},
		{"fragment", `{"base_url":"https://host/v1#dummy","api_key":"dummy"}`, false, 400},
		{"empty query", `{"base_url":"https://host/v1?","api_key":"dummy"}`, false, 400},
		{"empty fragment", `{"base_url":"https://host/v1#","api_key":"dummy"}`, false, 400},
		{"empty hostname", `{"base_url":"https://:443/v1","api_key":"dummy"}`, false, 400},
		{"key in URL", `{"base_url":"https://host/dummy/v1","api_key":"dummy"}`, false, 400},
		{"key with newline", `{"base_url":"https://host/v1","api_key":"dummy\nkey"}`, false, 400},
		{"http forbidden", `{"base_url":"http://host/v1","api_key":"dummy"}`, false, 400},
		{"http allowed", `{"base_url":"http://host/v1","api_key":"dummy"}`, true, 200},
		{"missing key", `{"base_url":"https://host/v1"}`, false, 400},
		{"blank key", `{"base_url":"https://host/v1","api_key":"  "}`, false, 400},
		{"malformed", `{"api_key":"dummy"`, false, 400},
		{"default name", `{"base_url":"https://host/v1","api_key":"dummy"}`, false, 200},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bridge, f := credentialTestHost(t)
			m := NewManager(bridge)
			m.cfg = config.Config{BaseURL: config.DefaultBaseURL, AllowHTTP: tt.allowHTTP}
			resp := postCredential(t, m, tt.body)
			if resp.StatusCode != tt.status || strings.Contains(string(resp.Body), "dummy") {
				t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
			}
			if tt.status != 200 && len(f.callsOf(pluginabi.MethodHostAuthSave)) != 0 {
				t.Fatal("invalid request persisted")
			}
			if tt.name == "default name" && !strings.Contains(string(resp.Body), `"label":"OpenCode Go"`) {
				t.Fatal("missing default label")
			}
		})
	}
}

func TestCredentialHostFailuresAreRedactedAndDoNotPublish(t *testing.T) {
	const body = `{"base_url":"https://host/v1","api_key":"oc_sk_dummy_failure"}`
	for _, method := range []string{pluginabi.MethodHostAuthList, pluginabi.MethodHostAuthSave} {
		t.Run(method, func(t *testing.T) {
			f := &fakeCaller{responder: func(called string, _ []byte) ([]byte, error) {
				if called == method {
					return nil, errors.New(body)
				}
				return hostOK(struct{}{}), nil
			}}
			m := NewManager(NewHostBridge(f.call))
			m.cfg.BaseURL = config.DefaultBaseURL
			resp := postCredential(t, m, body)
			if resp.StatusCode != 502 || strings.Contains(string(resp.Body), "oc_sk_dummy_failure") {
				t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
			}
			if len(f.authFiles) != 0 {
				t.Fatal("failed write published credential")
			}
		})
	}
	m := NewManager(nil)
	if resp := postCredential(t, m, body); resp.StatusCode != 503 {
		t.Fatalf("unavailable status=%d", resp.StatusCode)
	}
}

func TestCredentialConfiguredDuplicateAndConcurrentCreate(t *testing.T) {
	bridge, f := credentialTestHost(t)
	m := NewManager(bridge)
	m.cfg = config.Config{BaseURL: config.DefaultBaseURL, APIKeys: []config.APIKey{{Value: "configured-dummy"}}}
	if resp := postCredential(t, m, `{"base_url":"https://opencode.ai/zen/go/v1","api_key":"configured-dummy"}`); resp.StatusCode != 409 {
		t.Fatalf("configured duplicate=%d", resp.StatusCode)
	}
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := m.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/v0/management/plugins/" + pluginName + "/credentials", Body: []byte(`{"base_url":"https://host/v1","api_key":"concurrent-dummy"}`)})
			if err != nil {
				statuses <- 0
			} else {
				statuses <- resp.StatusCode
			}
		}()
	}
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[200] != 1 || counts[409] != 1 || len(f.callsOf(pluginabi.MethodHostAuthSave)) != 1 {
		t.Fatalf("concurrent statuses=%v", counts)
	}
}

func TestCredentialBaseURLExecutionPrecedence(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, base := range []string{"", "https://credential.test/v1"} {
			t.Run(strings.Join([]string{map[bool]string{false: "non-stream", true: "stream"}[stream], map[bool]string{false: "fallback", true: "credential"}[base != ""]}, "/"), func(t *testing.T) {
				m, f := newStreamManager(t, streamScript{upstreamID: "up", frames: []string{"data: [DONE]\n\n"}})
				if !stream {
					f.responder = upstreamRouter(t, map[string]string{"/v1/chat/completions": ccResponseBody})
				}
				req := executorRequest{ExecutorRequest: pluginapi.ExecutorRequest{AuthProvider: ProviderID, AuthAttributes: map[string]string{"api_key": "dummy-selected", "base_url": base}, Model: "opencode-go/glm-5.3", SourceFormat: "openai", OriginalRequest: []byte(ccRequestBody), Stream: stream}, StreamID: "down"}
				method, hostMethod := pluginabi.MethodExecutorExecute, pluginabi.MethodHostHTTPDo
				if stream {
					method, hostMethod = pluginabi.MethodExecutorExecuteStream, pluginabi.MethodHostHTTPDoStream
				}
				env := decodeEnv(t, mustHandle(t, m, method, mustJSON(req)))
				if !env.OK {
					t.Fatalf("execute=%+v", env.Error)
				}
				want := base
				if want == "" {
					want = config.DefaultBaseURL
				}
				if got := lastWire(t, f, hostMethod)["url"]; got != want+"/chat/completions" {
					t.Fatalf("URL=%v want=%s", got, want+"/chat/completions")
				}
			})
		}
	}
}

func TestCredentialQuotaBaseURLPrecedence(t *testing.T) {
	for _, base := range []string{"", "https://credential.test/v1"} {
		f := &fakeCaller{responder: func(_ string, payload []byte) ([]byte, error) {
			var req pluginapi.HTTPRequest
			_ = json.Unmarshal(payload, &req)
			want := base
			if want == "" {
				want = config.DefaultBaseURL
			}
			if req.URL != want+"/usage" {
				t.Errorf("URL=%s want=%s", req.URL, want+"/usage")
			}
			return hostOK(pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"usage":{"rolling":{"percent":1}}}`)}), nil
		}}
		m := NewManager(NewHostBridge(f.call))
		m.cfg.BaseURL = config.DefaultBaseURL
		if _, err := m.FetchQuota(context.Background(), pluginapi.QuotaFetchRequest{Provider: ProviderID, Attributes: map[string]string{"api_key": "dummy", "base_url": base}}); err != nil {
			t.Fatal(err)
		}
	}
}
