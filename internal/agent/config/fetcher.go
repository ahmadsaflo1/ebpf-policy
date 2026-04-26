// This file contains the HTTP client used to pull policy rules from the server
// on agent startup and during server reconnects.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

// FetchRules fetches policy rules from the server's /api/rules endpoint.
// When env is non-empty it is passed as a query parameter so the server
// returns only global rules plus rules tagged for that environment.
func FetchRules(serverURL string, env string) ([]models.PolicyRule, error) {
	url := fmt.Sprintf("%s/api/rules?env=%s", serverURL, env)

	resp, err := http.Get(url)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch rules: %w", err)
    }
    defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var rules []models.PolicyRule
	if err := json.Unmarshal(body, &rules); err != nil {
		return nil, err
	}

	return rules, nil
}
