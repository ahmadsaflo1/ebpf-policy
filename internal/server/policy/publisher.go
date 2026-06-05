// Package policy publishes rule lifecycle events (create/update/delete) to
// NATS so that enforcement agents receive changes in real time.
package policy

import (
	"encoding/json"
	"log"
	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

const (
	TopicPolicyUpdates = "policy.update"
	TopicPolicyDelete  = "policy.delete"
)

// PublishUpdate serialises rule and publishes it to the appropriate NATS topic.
// Rules with a topic are published to "policy.update.<topic>"; untagged rules
// go to "policy.update" so all agents receive them.
func PublishUpdate(rule models.PolicyRule) {
	data, err := json.Marshal(rule)
	if err != nil {
		log.Println("Could not serialize rule:", err)
		return
	}

	topic := TopicPolicyUpdates
    if rule.Topic != "" {
        topic = TopicPolicyUpdates + "." + rule.Topic
    }

    err = messaging.Publish(topic, data)
    if err != nil {
        log.Println("Could not publish policy update:", err)
        return
    }

    log.Printf("Published policy update: %s (topic: %s)\n", rule.Name, topic)
}

// StartFetchHandler subscribes to "policy.fetch" and replies to each request
// with a JSON array of rules. The request payload may contain a "topic" field
// to filter rules; an empty topic returns all rules.
func StartFetchHandler() error {
	return messaging.RespondToRequests("policy.fetch", func(data []byte) []byte {
		var req struct {
			Topic string `json:"topic"`
		}
		json.Unmarshal(data, &req)

		var rules []models.PolicyRule
		var err error

		if req.Topic != "" {
			rows, queryErr := db.DB.Query(`
				SELECT id, name, threshold, action, duration, topic, created_at
				FROM policy_rules
				WHERE topic = $1 OR topic = ''
				ORDER BY created_at DESC`, req.Topic)
			err = queryErr
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var r models.PolicyRule
					if rows.Scan(&r.ID, &r.Name, &r.Threshold, &r.Action, &r.Duration, &r.Topic, &r.CreatedAt) == nil {
						rules = append(rules, r)
					}
				}
			}
		} else {
			rows, queryErr := db.DB.Query(`
				SELECT id, name, threshold, action, duration, topic, created_at
				FROM policy_rules
				ORDER BY created_at DESC`)
			err = queryErr
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var r models.PolicyRule
					if rows.Scan(&r.ID, &r.Name, &r.Threshold, &r.Action, &r.Duration, &r.Topic, &r.CreatedAt) == nil {
						rules = append(rules, r)
					}
				}
			}
		}

		if err != nil {
			log.Printf("policy.fetch: DB error: %v\n", err)
			return []byte("[]")
		}

		if rules == nil {
			rules = []models.PolicyRule{}
		}

		resp, _ := json.Marshal(rules)
		return resp
	})
}

// PublishDelete publishes the ID of the deleted rule to "policy.delete" (or
// "policy.delete.<topic>" for topic-scoped rules) so agents can remove it locally.
func PublishDelete(rule models.PolicyRule) {
	data, err := json.Marshal(map[string]int{"id": rule.ID})
	if err != nil {
		log.Println("Could not serialize rule-id:", err)
		return
	}

	topic := "policy.delete"
    if rule.Topic != "" {
        topic = "policy.delete." + rule.Topic
    }

	err = messaging.Publish(topic, data)
	if err != nil {
		log.Println("Could not publish policy delete:", err)
	}

	log.Printf("Published rule delete: %s (topic: %s)\n", rule.Name, topic)
}