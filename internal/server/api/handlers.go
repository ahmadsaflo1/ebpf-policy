// Package api implements the HTTP handlers for the policy server's REST API.
// Routes are registered in cmd/server/main.go under the /api/rules prefix.
package api

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/policy"
	"github.com/gin-gonic/gin"
)

// GetRules handles GET /api/rules.
// Accepts an optional ?env= query parameter; when supplied, only rules whose
// tag matches env or whose tag is empty (global) are returned.
func GetRules(c *gin.Context) {
    env := c.Query("env")

    var rows *sql.Rows
    var err error

    if env != "" {
        rows, err = db.DB.Query(`
            SELECT id, name, threshold, action, duration, tag, created_at
            FROM policy_rules
            WHERE tag = ? OR tag = ''
            ORDER BY created_at DESC`, env)
    } else {
        rows, err = db.DB.Query(`
            SELECT id, name, threshold, action, duration, tag, created_at
            FROM policy_rules
            ORDER BY created_at DESC`)
    }

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

    c.JSON(http.StatusOK, rules)
}

// CreateRule handles POST /api/rules.
// Persists the new rule and publishes an update event to NATS.
func CreateRule(c *gin.Context) {
    var rule models.PolicyRule
    if err := c.ShouldBindJSON(&rule); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    result, err := db.DB.Exec(`
        INSERT INTO policy_rules (name, threshold, action, duration, tag)
        VALUES (?, ?, ?, ?, ?)`,
        rule.Name, rule.Threshold, rule.Action, rule.Duration, rule.Tag,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    id, _ := result.LastInsertId()
	rule.ID = int(id)

	policy.PublishUpdate(rule)

    c.JSON(http.StatusCreated, rule)
}

// GetRule handles GET /api/rules/:id.
// Returns 404 if no rule with the given ID exists.
func GetRule(c *gin.Context) {
    id := c.Param("id")
    var rule models.PolicyRule

    err := db.DB.QueryRow(`
        SELECT id, name, threshold, action, duration, tag, created_at
        FROM policy_rules WHERE id = ?`, id,
    ).Scan(&rule.ID, &rule.Name, &rule.Threshold,
           &rule.Action, &rule.Duration, &rule.Tag, &rule.CreatedAt)

    if err == sql.ErrNoRows {
        c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
        return
    }
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, rule)
}

// UpdateRule handles PUT /api/rules/:id.
// Updates the rule in the database and publishes the change to NATS.
// Returns 404 if no rule with the given ID exists.
func UpdateRule(c *gin.Context) {
    id := c.Param("id")
    var rule models.PolicyRule
    if err := c.ShouldBindJSON(&rule); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    result, err := db.DB.Exec(`
        UPDATE policy_rules
        SET name=?, threshold=?, action=?, duration=?, tag=?
        WHERE id=?`,
        rule.Name, rule.Threshold, rule.Action, rule.Duration, rule.Tag, id,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	ruleID, _ := strconv.Atoi(id)
	rule.ID = ruleID
	policy.PublishUpdate(rule)

    c.JSON(http.StatusOK, gin.H{"message": "rule updated"})
}

// DeleteRule handles DELETE /api/rules/:id.
// The rule is fetched before deletion so its tag can be included in the NATS
// delete event, ensuring only relevant agents are notified.
func DeleteRule(c *gin.Context) {
	id := c.Param("id")

	var rule models.PolicyRule
    err := db.DB.QueryRow(`
        SELECT id, name, threshold, action, duration, tag, created_at
        FROM policy_rules WHERE id = ?`, id,
    ).Scan(&rule.ID, &rule.Name, &rule.Threshold,
           &rule.Action, &rule.Duration, &rule.Tag, &rule.CreatedAt)

    if err == sql.ErrNoRows {
        c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
        return
    }
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    result, err := db.DB.Exec("DELETE FROM policy_rules WHERE id = ?", id)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
        return
    }

    policy.PublishDelete(rule)

    c.JSON(http.StatusOK, gin.H{"message": "rule deleted"})
}