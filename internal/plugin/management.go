package plugin

// This compatibility resource keeps the quota page usable with Management
// Center builds that predate CLIProxyAPI v8's generic quota UI. The native
// quota provider remains the source of truth; this route only adapts its
// response to the legacy embedded page.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"opencode-go-cliproxyapi/resources"
)

type legacyQuotaWindow struct {
	Status   string  `json:"status"`
	Percent  float64 `json:"percent"`
	ResetsAt string  `json:"resets_at"`
}

type legacyQuotaUsage struct {
	Rolling legacyQuotaWindow `json:"rolling"`
	Weekly  legacyQuotaWindow `json:"weekly"`
	Monthly legacyQuotaWindow `json:"monthly"`
}

type legacyQuotaCard struct {
	KeyID string            `json:"key_id"`
	Label string            `json:"label"`
	Usage *legacyQuotaUsage `json:"usage,omitempty"`
}

type legacyQuotaList struct {
	Cards []legacyQuotaCard `json:"cards"`
}

type legacyQuotaRequest struct {
	KeyID string `json:"key_id"`
}

func quotaIdentity(key string) (id, label string) {
	digest := sha256.Sum256([]byte(key))
	hash := hex.EncodeToString(digest[:])
	return "opencode-go-key-" + hash, maskAPIKey(key)
}

func (m *Manager) registerManagement(request []byte) ([]byte, error) {
	var req struct {
		Plugin           pluginapi.Metadata `json:"Plugin"`
		BasePath         string             `json:"BasePath"`
		ResourceBasePath string             `json:"ResourceBasePath"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return ErrEnvelope("invalid_request", "malformed management registration request body"), nil
	}
	return okEnvelope(struct {
		Routes []struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"routes"`
		Resources []struct {
			Path        string `json:"path"`
			Menu        string `json:"menu"`
			Description string `json:"description"`
		} `json:"resources"`
	}{
		Routes: []struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		}{
			{Method: http.MethodPost, Path: "/plugins/" + pluginName + "/quota-usage"},
			{Method: http.MethodPost, Path: "/plugins/" + pluginName + "/credentials"},
		},
		Resources: []struct {
			Path        string `json:"path"`
			Menu        string `json:"menu"`
			Description string `json:"description"`
		}{{Path: "/quota", Menu: "OpenCode Go Quota", Description: "View OpenCode Go quota windows."}},
	}), nil
}

func (m *Manager) handleManagement(request []byte) ([]byte, error) {
	var req struct {
		pluginapi.ManagementRequest
		HostCallbackID string `json:"host_callback_id,omitempty"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return ErrEnvelope("invalid_request", "malformed management request body"), nil
	}
	resp, err := m.HandleManagement(context.Background(), req.ManagementRequest)
	if err != nil {
		return ErrEnvelope("management_failure", err.Error()), nil
	}
	raw, _ := json.Marshal(resp)
	return okEnvelope(json.RawMessage(raw)), nil
}

func (m *Manager) HandleManagement(ctx context.Context, req pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
	if req.Method == http.MethodPost && req.Path == "/v0/management/plugins/"+pluginName+"/credentials" {
		return m.createCredential(ctx, req.Body)
	}
	if req.Method == http.MethodGet && req.Path == "/v0/resource/plugins/"+pluginName+"/quota" {
		return pluginapi.ManagementResponse{
			Headers: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			Body:    []byte(resources.QuotaPage),
		}, nil
	}
	if req.Method != http.MethodPost || req.Path != "/v0/management/plugins/"+pluginName+"/quota-usage" {
		return pluginapi.ManagementResponse{StatusCode: http.StatusNotFound, Body: []byte(`{"error":"not found"}`)}, nil
	}
	var body legacyQuotaRequest
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return pluginapi.ManagementResponse{StatusCode: http.StatusBadRequest, Body: []byte(`{"error":"invalid request"}`)}, nil
		}
	}
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()
	credentials, err := m.quotaCredentials(ctx, cfg, false)
	if err != nil {
		return credentialFailure(http.StatusBadGateway, "cannot inspect credentials")
	}
	if body.KeyID == "" {
		cards := make([]legacyQuotaCard, 0, len(credentials))
		for _, credential := range credentials {
			cards = append(cards, legacyQuotaCard{KeyID: credential.ID, Label: credential.Label})
		}
		return quotaJSON(legacyQuotaList{Cards: cards})
	}
	for _, credential := range credentials {
		id, label := credential.ID, credential.Label
		if id != body.KeyID {
			continue
		}
		fresh, err := m.FetchQuota(ctx, pluginapi.QuotaFetchRequest{
			Provider:   ProviderID,
			Attributes: map[string]string{"api_key": credential.APIKey, "base_url": credential.BaseURL},
		})
		if err != nil || len(fresh.Groups) == 0 {
			return pluginapi.ManagementResponse{StatusCode: http.StatusBadGateway, Body: []byte(`{"error":"quota refresh failed"}`)}, nil
		}
		usage := legacyQuotaUsage{}
		for _, bucket := range fresh.Groups[0].Buckets {
			window := legacyQuotaWindow{Status: "ok", Percent: (1 - bucket.RemainingFraction) * 100, ResetsAt: bucket.ResetTime}
			switch bucket.Window {
			case "rolling":
				usage.Rolling = window
			case "weekly":
				usage.Weekly = window
			case "monthly":
				usage.Monthly = window
			}
		}
		return quotaJSON(legacyQuotaCard{KeyID: id, Label: label, Usage: &usage})
	}
	return pluginapi.ManagementResponse{StatusCode: http.StatusNotFound, Body: []byte(`{"error":"unknown quota key"}`)}, nil
}

func quotaJSON(value any) (pluginapi.ManagementResponse, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return pluginapi.ManagementResponse{}, err
	}
	return pluginapi.ManagementResponse{Headers: http.Header{"Content-Type": []string{"application/json"}}, Body: body}, nil
}
