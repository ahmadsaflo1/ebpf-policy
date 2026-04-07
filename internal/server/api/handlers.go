package api

import (
    "database/sql"
    "net/http"
    "github.com/gin-gonic/gin"
    "github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
    "github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

// GET /api/rules — get all rules
func GetRules(c *gin.Context) {
    rows, err := db.DB.Query(`
        SELECT id, name, threshold, action, duration, created_at
        FROM policy_rules
        ORDER BY created_at DESC
    `)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    defer rows.Close()

    var rules []models.PolicyRule
    for rows.Next() {
        var r models.PolicyRule
        err := rows.Scan(&r.ID, &r.Name, &r.Threshold,
                         &r.Action, &r.Duration, &r.CreatedAt)
        if err != nil {
            continue
        }
        rules = append(rules, r)
    }

    c.JSON(http.StatusOK, rules)
}

// POST /api/rules — create new rule
func CreateRule(c *gin.Context) {
    var rule models.PolicyRule
    if err := c.ShouldBindJSON(&rule); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    result, err := db.DB.Exec(`
        INSERT INTO policy_rules (name, threshold, action, duration)
        VALUES (?, ?, ?, ?)`,
        rule.Name, rule.Threshold, rule.Action, rule.Duration,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    id, _ := result.LastInsertId()
    rule.ID = int(id)
    c.JSON(http.StatusCreated, rule)
}

// GET /api/rules/:id — get a specific rule
func GetRule(c *gin.Context) {
    id := c.Param("id")
    var rule models.PolicyRule

    err := db.DB.QueryRow(`
        SELECT id, name, threshold, action, duration, created_at
        FROM policy_rules WHERE id = ?`, id,
    ).Scan(&rule.ID, &rule.Name, &rule.Threshold,
           &rule.Action, &rule.Duration, &rule.CreatedAt)

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

// PUT /api/rules/:id — update a specific rule
func UpdateRule(c *gin.Context) {
    id := c.Param("id")
    var rule models.PolicyRule
    if err := c.ShouldBindJSON(&rule); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    result, err := db.DB.Exec(`
        UPDATE policy_rules
        SET name=?, threshold=?, action=?, duration=?
        WHERE id=?`,
        rule.Name, rule.Threshold, rule.Action, rule.Duration, id,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

	// Check how many rows were actually deleted
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

    c.JSON(http.StatusOK, gin.H{"message": "rule updated"})
}

// DELETE /api/rules/:id — delete a specific rule
func DeleteRule(c *gin.Context) {
    id := c.Param("id")
    result, err := db.DB.Exec("DELETE FROM policy_rules WHERE id = ?", id)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

	// Check how many rows were actually deleted
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "rule deleted"})
}