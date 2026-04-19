package config

import (
	"encoding/json"
	"log"
	"fmt"
	"io"
	"net/http"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

// FetchRules fetches all rules from the policy server when the agent starts up.
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

	log.Printf("Fetched %d policies from server\n", len(rules))
	return rules, nil
}
