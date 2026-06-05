// This file contains the HTTP client used to pull policy rules from the server
// on agent startup and during server reconnects.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

// FetchRulesViaNATS sends a request to "policy.fetch" over NATS and returns
// the rules replied by the policy server. Times out after 5 seconds.
func FetchRulesViaNATS(topic string) ([]models.PolicyRule, error) {
	req, _ := json.Marshal(map[string]string{"topic": topic})
	data, err := messaging.Request("policy.fetch", req, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("NATS fetch failed: %w", err)
	}
	var rules []models.PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("could not parse rules response: %w", err)
	}
	return rules, nil
}

// FetchRules fetches policy rules from the server's /api/rules endpoint.
// When topic is non-empty it is passed as a query parameter so the server
// returns only global rules plus rules tagged for that topic.
func FetchRules(serverURL string, topic string) ([]models.PolicyRule, error) {
	url := fmt.Sprintf("%s/api/rules?topic=%s", serverURL, topic)

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
