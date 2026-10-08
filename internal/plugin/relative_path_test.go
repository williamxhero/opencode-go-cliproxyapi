package plugin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"opencode-go-cliproxyapi/internal/config"
)

// The live host reports plugin-managed auth records with a path relative to its own
// working directory. The credential route must still create new credentials and still
// detect duplicates instead of failing closed with "cannot inspect credentials".
func TestCredentialRouteToleratesRelativeHostPaths(t *testing.T) {
	dir, err := os.MkdirTemp(".", "relpath-creds-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	existingKey := "sk-oc-existing-dummy"
	id, _ := quotaIdentity(existingKey)
	record, _ := json.Marshal(map[string]string{
		"type": ProviderID, "id": id, "api_key": existingKey, "label": "Existing",
	})
	abs := filepath.Join(absDir, "Existing.json")
	if err := os.WriteFile(abs, record, 0600); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil {
		t.Fatalf("cannot build a relative path: %v", err)
	}

	saves := 0
	f := &fakeCaller{responder: func(method string, payload []byte) ([]byte, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			return hostOK(hostAuthListResponse{Files: []pluginapi.HostAuthFileEntry{
				{Provider: ProviderID, ID: id, Name: "Existing.json", Path: rel},
			}}), nil
		case pluginabi.MethodHostAuthSave:
			saves++
			return hostOK(pluginapi.HostAuthSaveResponse{}), nil
		}
		return hostOK(nil), nil
	}}
	m := NewManager(NewHostBridge(f.call))
	m.cfg = config.Config{BaseURL: config.DefaultBaseURL, AllowHTTP: false}

	// (a) a brand-new key is created even though an existing record has a relative path.
	resp := postCredential(t, m, `{"base_url":"https://example.test/v1","api_key":"brand-new-dummy","name":"Panel"}`)
	if resp.StatusCode != 200 || saves != 1 {
		t.Fatalf("create with a relative host path failed: status=%d saves=%d body=%s", resp.StatusCode, saves, resp.Body)
	}

	// (b) the credential that is already on disk is still rejected as a duplicate.
	resp = postCredential(t, m, `{"base_url":"`+config.DefaultBaseURL+`","api_key":"`+existingKey+`"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate not detected with a relative host path: status=%d body=%s", resp.StatusCode, resp.Body)
	}
	if saves != 1 {
		t.Fatalf("duplicate was persisted: saves=%d", saves)
	}

	// (c) quota keeps working as well (the legacy card path uses the same listing).
	id2, _ := quotaIdentity(existingKey)
	if _, err := m.quotaCredentials(context.Background(), m.cfg, false); err != nil {
		t.Fatalf("non-strict listing must tolerate relative paths: %v (id=%s)", err, id2)
	}
}
