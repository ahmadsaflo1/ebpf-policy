// Package api implements the HTTP handlers for the policy server's REST API.
// Routes are registered in cmd/server/main.go under the /api/rules prefix.
package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/policy"
)

// GetRules handles GET /api/rules.
// Accepts an optional ?env= query parameter; when supplied, only rules whose
// tag matches env or whose tag is empty (global) are returned.
func GetRules(w http.ResponseWriter, r *http.Request) {
	env := r.URL.Query().Get("env")

	var rows *sql.Rows
	var err error

	if env != "" {
		rows, err = db.DB.Query(`
			SELECT id, name, threshold, action, duration, tag, created_at
			FROM policy_rules
			WHERE tag = $1 OR tag = ''
			ORDER BY created_at DESC`, env)
	} else {
		rows, err = db.DB.Query(`
			SELECT id, name, threshold, action, duration, tag, created_at
			FROM policy_rules
			ORDER BY created_at DESC`)
	}

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	var rules []models.PolicyRule
	for rows.Next() {
		var r models.PolicyRule
		err := rows.Scan(&r.ID, &r.Name, &r.Threshold,
			&r.Action, &r.Duration, &r.Tag, &r.CreatedAt)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}

	writeJSON(w, http.StatusOK, rules)
}

// CreateRule handles POST /api/rules.
// Persists the new rule and publishes an update event to NATS.
func CreateRule(w http.ResponseWriter, r *http.Request) {
	var rule models.PolicyRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	var id int64
	err := db.DB.QueryRow(`
		INSERT INTO policy_rules (name, threshold, action, duration, tag)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		rule.Name, rule.Threshold, rule.Action, rule.Duration, rule.Tag,
	).Scan(&id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	rule.ID = int(id)
	policy.PublishUpdate(rule)

	writeJSON(w, http.StatusCreated, rule)
}

// GetRule handles GET /api/rules/{id}.
// Returns 404 if no rule with the given ID exists.
func GetRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rule models.PolicyRule

	err := db.DB.QueryRow(`
		SELECT id, name, threshold, action, duration, tag, created_at
		FROM policy_rules WHERE id = $1`, id,
	).Scan(&rule.ID, &rule.Name, &rule.Threshold,
		&rule.Action, &rule.Duration, &rule.Tag, &rule.CreatedAt)

	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, rule)
}

// UpdateRule handles PUT /api/rules/{id}.
// Updates the rule in the database and publishes the change to NATS.
// Returns 404 if no rule with the given ID exists.
func UpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rule models.PolicyRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	result, err := db.DB.Exec(`
		UPDATE policy_rules
		SET name=$1, threshold=$2, action=$3, duration=$4, tag=$5
		WHERE id=$6`,
		rule.Name, rule.Threshold, rule.Action, rule.Duration, rule.Tag, id,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}

	ruleID, _ := strconv.Atoi(id)
	rule.ID = ruleID
	policy.PublishUpdate(rule)

	writeJSON(w, http.StatusOK, map[string]string{"message": "rule updated"})
}

// DeleteRule handles DELETE /api/rules/{id}.
// The rule is fetched before deletion so its tag can be included in the NATS
// delete event, ensuring only relevant agents are notified.
func DeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var rule models.PolicyRule
	err := db.DB.QueryRow(`
		SELECT id, name, threshold, action, duration, tag, created_at
		FROM policy_rules WHERE id = $1`, id,
	).Scan(&rule.ID, &rule.Name, &rule.Threshold,
		&rule.Action, &rule.Duration, &rule.Tag, &rule.CreatedAt)

	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	result, err := db.DB.Exec("DELETE FROM policy_rules WHERE id = $1", id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}

	policy.PublishDelete(rule)

	writeJSON(w, http.StatusOK, map[string]string{"message": "rule deleted"})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}