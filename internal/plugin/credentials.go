package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"opencode-go-cliproxyapi/internal/config"
)

type credentialRecord struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Label   string `json:"label"`
	APIKey  string `json:"api_key"`
	BaseURL string `json:"base_url,omitempty"`
}

func credentialIdentity(key, baseURL string) string {
	digest := sha256.Sum256([]byte(key + "\x00" + baseURL))
	return "opencode-go-key-" + hex.EncodeToString(digest[:])
}

func credentialFailure(status int, reason string) (pluginapi.ManagementResponse, error) {
	resp, err := quotaJSON(map[string]string{"error": reason})
	resp.StatusCode = status
	return resp, err
}

func (m *Manager) createCredential(ctx context.Context, body []byte) (pluginapi.ManagementResponse, error) {
	var input struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
		Name    string `json:"name"`
	}
	if json.Unmarshal(body, &input) != nil {
		return credentialFailure(http.StatusBadRequest, "invalid request")
	}
	input.BaseURL = strings.TrimRight(strings.TrimSpace(input.BaseURL), "/")
	input.APIKey = strings.TrimSpace(input.APIKey)
	if input.APIKey == "" || strings.ContainsAny(input.APIKey, "\r\n\x00") {
		return credentialFailure(http.StatusBadRequest, "invalid api_key")
	}
	// Serialize list/check/save with other submissions and configured-key materialization.
	m.lifeMu.Lock()
	defer m.lifeMu.Unlock()
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()
	if config.ValidateCredentialBaseURL(input.BaseURL, cfg.AllowHTTP) != nil {
		return credentialFailure(http.StatusBadRequest, "invalid base_url")
	}
	if strings.Contains(input.BaseURL, input.APIKey) {
		return credentialFailure(http.StatusBadRequest, "base_url must not contain api_key")
	}
	label := strings.TrimSpace(input.Name)
	if label == "" {
		// No alias: show the key masked (first4...last4) instead of a generic name.
		label = maskAPIKey(input.APIKey)
	}
	label = strings.ReplaceAll(label, input.APIKey, "[redacted]")
	if m.bridge == nil {
		return credentialFailure(http.StatusServiceUnavailable, "credential API unavailable")
	}
	records, err := m.quotaCredentials(ctx, cfg, true)
	if err != nil {
		return credentialFailure(http.StatusBadGateway, "cannot inspect credentials")
	}
	for _, record := range records {
		if record.APIKey == input.APIKey && record.BaseURL == input.BaseURL {
			return credentialFailure(http.StatusConflict, "credential already exists")
		}
	}
	id := credentialIdentity(input.APIKey, input.BaseURL)
	record, err := json.Marshal(credentialRecord{Type: ProviderID, ID: id, Label: label, APIKey: input.APIKey, BaseURL: input.BaseURL})
	if err != nil {
		return credentialFailure(http.StatusInternalServerError, "cannot encode credential")
	}
	// AuthSave owns persistence. Do not time out a mutating callback and report a
	// failure while it can still finish saving in the host; await its final result.
	if err := m.bridge.AuthSave(context.WithoutCancel(ctx), pluginapi.HostAuthSaveRequest{Name: id + ".json", JSON: record}); err != nil {
		return credentialFailure(http.StatusBadGateway, "cannot save credential")
	}
	resp, err := quotaJSON(struct {
		OK    bool   `json:"ok"`
		ID    string `json:"id"`
		Label string `json:"label"`
	}{true, id, label})
	resp.StatusCode = http.StatusOK
	return resp, err
}

// quotaCredentials preserves configured key_id values and adds host-persisted
// credentials. Absolute paths come from the same host API used at cold start.
// Duplicate checks fail closed; quota skips broken files so healthy keys work.
func (m *Manager) quotaCredentials(ctx context.Context, cfg config.Config, strict bool) ([]credentialRecord, error) {
	records := make([]credentialRecord, 0, len(cfg.APIKeys))
	seen := map[string]bool{}
	for _, key := range cfg.APIKeys {
		id, label := quotaIdentity(key.Value)
		base := strings.TrimRight(cfg.BaseURL, "/")
		records = append(records, credentialRecord{Type: ProviderID, ID: id, Label: label, APIKey: key.Value, BaseURL: base})
		seen[credentialIdentity(key.Value, base)] = true
	}
	if m.bridge == nil {
		return records, nil
	}
	entries, err := m.bridge.AuthList(ctx)
	if err != nil {
		if !strict {
			return records, nil
		}
		return nil, fmt.Errorf("cannot list credentials")
	}
	for _, entry := range entries {
		if entry.Provider != ProviderID && entry.Type != ProviderID {
			continue
		}
		// The host reports plugin-managed records with a path relative to its own working
		// directory; resolve it so the duplicate check stays reliable. A record that still
		// cannot be read keeps failing closed (never create a duplicate blindly).
		path := strings.TrimSpace(entry.Path)
		if path != "" && !filepath.IsAbs(path) {
			if abs, err := filepath.Abs(path); err == nil {
				path = abs
			}
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			if !strict {
				continue
			}
			return nil, fmt.Errorf("cannot read credential")
		}
		var record credentialRecord
		if json.Unmarshal(raw, &record) != nil || strings.TrimSpace(record.APIKey) == "" {
			if !strict {
				continue
			}
			return nil, fmt.Errorf("invalid credential record")
		}
		record.APIKey = strings.TrimSpace(record.APIKey)
		panelCredential := record.BaseURL != ""
		if record.BaseURL == "" {
			record.BaseURL = cfg.BaseURL
		}
		record.BaseURL = strings.TrimRight(strings.TrimSpace(record.BaseURL), "/")
		identity := credentialIdentity(record.APIKey, record.BaseURL)
		if seen[identity] {
			continue
		}
		seen[identity] = true
		if record.ID == "" {
			record.ID = entry.ID
		}
		if record.ID == "" {
			record.ID = entry.Name
		}
		if panelCredential {
			record.Label = strings.TrimSpace(record.Label)
			if record.Label == "" {
				record.Label = "OpenCode Go"
			}
		} else {
			record.Label = accountLabel(config.Config{}, record.APIKey, record.Label, 0)
		}
		records = append(records, record)
	}
	return records, nil
}

// Selected auth attributes take precedence over persisted storage, then config.
func credentialBaseURL(attributes map[string]string, storage []byte, cfg config.Config) (string, error) {
	base := attributes["base_url"]
	if base == "" && len(storage) > 0 {
		var record struct {
			BaseURL string `json:"base_url"`
		}
		if json.Unmarshal(storage, &record) != nil {
			return "", fmt.Errorf("selected auth has invalid storage")
		}
		base = record.BaseURL
	}
	if base == "" {
		return cfg.BaseURL, nil
	}
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if config.ValidateCredentialBaseURL(base, cfg.AllowHTTP) != nil {
		return "", fmt.Errorf("selected auth has invalid base_url")
	}
	if key := strings.TrimSpace(attributes["api_key"]); key != "" && strings.Contains(base, key) {
		return "", fmt.Errorf("selected auth has invalid base_url")
	}
	return base, nil
}
