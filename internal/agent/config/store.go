package config

import (
	"log"
	"sync"
	"os"
	"encoding/json"

	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

const rulesFile = "/tmp/ebpf-policy-rules.json"

// RuleStore keeps all active policy rules in memory
type RuleStore struct {
	mu sync.RWMutex
	rules map[int]models.PolicyRule  // key: rule ID
}

func NewRuleStore() *RuleStore {
	s := &RuleStore{
        rules: make(map[int]models.PolicyRule),
    }
    return s
}

func (s *RuleStore) Upsert(rule models.PolicyRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[rule.ID] = rule
	log.Printf("Rule upserted: Name=%s (threshold: %d req/s)\n",
		rule.Name, rule.Threshold)
	s.saveToDisk()
}

// UpsertSilent adds or updates a rule without logging — used on startup
func (s *RuleStore) UpsertSilent(rule models.PolicyRule) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.rules[rule.ID] = rule
    s.saveToDisk()
}

func (s *RuleStore) Delete(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rules, id)
	log.Printf("Rule deleted: ID=%d\n", id)
	s.saveToDisk()
}

func (s *RuleStore) GetAll() []models.PolicyRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := make([]models.PolicyRule, 0, len(s.rules))
	for _, r := range s.rules {
		rules = append(rules, r)
	}
	return rules
}

// Match finds the first rule that matches the given request rate.
func (s *RuleStore) Match(reqPerSec int) *models.PolicyRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var bestRule *models.PolicyRule


	for _, rule := range s.rules {
		rule := rule // avoid closure capture

		if reqPerSec <= rule.Threshold {
			continue // does not match
		}
		if bestRule == nil {
			bestRule = &rule
			continue
		}

		// Block always beats ratelimit
		if  rule.Action == "block" && bestRule.Action != "ratelimit" {
			bestRule = &rule
			continue
		}
		 
		// Among same action type — pick highest threshold (most specific)
		if rule.Action == bestRule.Action && rule.Threshold > bestRule.Threshold {
            bestRule = &rule
        }
	}

	return bestRule
}

// Clear removes all rules from the store and deletes the cache file
func (s *RuleStore) Clear() {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.rules = make(map[int]models.PolicyRule)
    os.Remove(rulesFile)
    log.Println("Rule store cleared — cache deleted")
}

// LoadFromDisk loads cached rules from local JSON file on startup
func (s *RuleStore) LoadFromDisk() {
    data, err := os.ReadFile(rulesFile)
    if err != nil {
        // File does not exist yet — normal on first run
        log.Println("No cached rules found on disk — starting fresh")
        return
    }

    var rules []models.PolicyRule
    if err := json.Unmarshal(data, &rules); err != nil {
        log.Println("Could not load rules from disk:", err)
        return
    }

    for _, r := range rules {
        s.rules[r.ID] = r
    }

    log.Printf("Loaded %d rules from disk cache:\n", len(rules))
    for _, r := range rules {
        log.Printf("  - %s (threshold: %d req/s, action: %s)\n",
            r.Name, r.Threshold, r.Action)
    }
}

// saveToDisk persists all rules to a local JSON file
func (s *RuleStore) saveToDisk() {
    rules := make([]models.PolicyRule, 0, len(s.rules))
    for _, r := range s.rules {
        rules = append(rules, r)
    }

    data, err := json.Marshal(rules)
    if err != nil {
        log.Println("Could not serialize rules to disk:", err)
        return
    }

    if err := os.WriteFile(rulesFile, data, 0644); err != nil {
        log.Println("Could not write rules to disk:", err)
        return
    }
}