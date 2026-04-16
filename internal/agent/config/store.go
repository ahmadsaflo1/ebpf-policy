package config

import (
	"log"
	"sync"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

// RuleStore keeps all active policy rules in memory
type RuleStore struct {
	mu sync.RWMutex
	rules map[int]models.PolicyRule  // key: rule ID
}

func NewRuleStore() *RuleStore {
	return &RuleStore{
		rules: make(map[int]models.PolicyRule),
	}
}

func (s *RuleStore) Upsert(rule models.PolicyRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[rule.ID] = rule
	log.Printf("Rule upserted: Name=%s (threshold: %d req/s)\n",
		rule.Name, rule.Threshold)
}

func (s *RuleStore) Delete(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rules, id)
	log.Printf("Rule deleted: ID=%d\n", id)
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
	for _, rule := range s.rules {
		if reqPerSec > rule.Threshold {
			return &rule
		}
	}
	return nil
}