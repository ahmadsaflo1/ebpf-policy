// Command agent is the eBPF policy enforcement agent.
// It loads an XDP program onto the configured network interface, fetches
// policy rules from the server, listens for rule changes via NATS, and
// applies block/rate-limit decisions based on per-IP request rates observed
// in kernel space.
package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/agent/config"
	ebpfloader "github.com/ahmadsaflo1/ebpf-policy/internal/agent/ebpf"
	"github.com/ahmadsaflo1/ebpf-policy/internal/agent/reporter"
	"github.com/ahmadsaflo1/ebpf-policy/internal/agent/system"
	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

// serverAvailable tracks whether the policy server is reachable
// Start optimistically as true, and set to false only if connection fails
var serverAvailable = true

func main() {
	log.Println("Starting Policy Agent ...")

	cfg := config.Load()

	messaging.Init()
	defer messaging.Close()

	program, err := ebpfloader.Load(cfg.Interface)
	if err != nil {
		log.Fatalf("Failed to load eBPF: %v", err)
	}
	defer program.Close()

	store := config.NewRuleStore()
	connectToServer(cfg, store)

	listener := config.NewListener(
		func(rule models.PolicyRule) {
			store.Upsert(rule)
		},
		func(ruleID int) {
			store.Delete(ruleID)
		},
	)
	if err := listener.Start(cfg.Env); err != nil {
		log.Fatal("Failed to start policy listener:", err)
	}

	rep := reporter.New(cfg.AgentID, &serverAvailable)
	rep.Start()

	sysReporter := system.NewReporter(cfg.AgentID, &serverAvailable)
	sysMonitor := system.New(cfg.AgentID, 30*time.Second, func(metrics models.SystemMetrics) {
		sysReporter.Report(metrics)
	})
	sysMonitor.Start()

	// Track previous counts to calculate req/s delta between ticks.
	prevCounts := make(map[string]uint64)

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		for range ticker.C {
			stats, err := program.GetAllStats()
			if err != nil {
				log.Println("Failed to read eBPF stats:", err)
				continue
			}

			latencyStats, err := program.GetAllLatencyStats()
			if err != nil {
				log.Println("Failed to read latency stats:", err)
				latencyStats = make(map[string]*ebpfloader.LatencyStats)
			}

			for ipStr, count := range stats {
				prev := prevCounts[ipStr]
				diff := count - prev
				prevCounts[ipStr] = count
				reqPerSec := int(diff) / 10

				ip := net.ParseIP(ipStr)
				rule := store.Match(reqPerSec)
				isBlocked := program.IsBlocked(ip)

				if isBlocked {
					if rule != nil && rule.Action == "block" {
						// Still high traffic — extend the block
						duration := time.Duration(rule.Duration) * time.Second
						program.BlockIP(ip, duration)
						log.Printf("IP %s still active (%d req/s) — extending block\n",
							ipStr, reqPerSec)
					} else {
						// Traffic calmed down — unblock
						program.UnblockIP(ip)
						log.Printf("IP %s calmed down (%d req/s) — unblocking\n",
							ipStr, reqPerSec)
					}
				} else if rule != nil {
					if rule.Action == "block" {
						// Exceeds DDoS threshold — block for X seconds
						duration := time.Duration(rule.Duration) * time.Second
						program.BlockIP(ip, duration)
						log.Printf("IP %s exceeds limit (%d req/s) — blocking for %ds!\n",
							ipStr, reqPerSec, rule.Duration)
					} else if rule.Action == "ratelimit" {
						// Exceeds rate limit — token bucket in eBPF handles dropping
						log.Printf("IP %s is being rate limited (%d req/s)\n",
							ipStr, reqPerSec)
					}
				}

				clientStat := models.ClientStats{
					IP:        ipStr,
					ReqPerSec: reqPerSec,
					Blocked:   boolToInt(isBlocked),
					Passed:    int(diff),
				}

				// Add latency metrics if available
				if latency, ok := latencyStats[ipStr]; ok && latency != nil {
					clientStat.AvgLatencyUs = latency.GetAvgLatencyUs()
					clientStat.MinLatencyUs = latency.GetMinLatencyUs()
					clientStat.MaxLatencyUs = latency.GetMaxLatencyUs()
				}

				rep.AddStat(clientStat)
			}
		}
	}()

	go watchServer(cfg, store)

	log.Println("Agent running — monitoring network traffic and applying policies...")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down agent...")
}

// connectToServer tries to fetch rules from server on startup.
// If server is unreachable after 4 attempts, falls back to cached rules.
func connectToServer(cfg *config.Config, store *config.RuleStore) {
	for attempt := 1; attempt <= 4; attempt++ {
		rules, err := config.FetchRules(cfg.ServerURL, cfg.Env)
		if err == nil {
			filtered := filterRules(rules, cfg.Env)
			for _, rule := range filtered {
				store.UpsertSilent(rule)
			}
			log.Printf("Fetched %d rules from server\n", len(filtered))
			serverAvailable = true
			return
		}

		log.Printf("Could not reach server (attempt %d/4): %v — retrying in 5s\n",
			attempt, err)

		if attempt < 4 {
			time.Sleep(5 * time.Second)
		}
	}

	log.Println("Could not reach server after 4 attempts — using cached rules")
	store.LoadFromDisk()
	serverAvailable = false
}

// watchServer continuously monitors server health while agent is running.
// If server goes down, it logs and continues with current rules.
// When server comes back, it fetches fresh rules and discards cache.
func watchServer(cfg *config.Config, store *config.RuleStore) {
	time.Sleep(30 * time.Second)

	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		rules, err := config.FetchRules(cfg.ServerURL, cfg.Env)
		if err != nil {
			if serverAvailable {
				log.Printf("Server is down: %v — continuing with current rules\n", err)
				serverAvailable = false
			} else {
				log.Println("Server still down — retrying in 15s")
			}
			continue
		}

		if !serverAvailable {
			filtered := filterRules(rules, cfg.Env)
			log.Println("Server is back — loading fresh rules")
			store.Clear()
			for _, rule := range filtered {
				store.Upsert(rule)
			}
			log.Printf("Fetched %d rules from server\n",len(filtered))
			serverAvailable = true
		}
	}
}

// filterRules returns only rules that belong to this agent (matching env or no tag)
func filterRules(rules []models.PolicyRule, env string) []models.PolicyRule {
	var filtered []models.PolicyRule
	for _, rule := range rules {
		if rule.Tag == "" || rule.Tag == env {
            filtered = append(filtered, rule)
        }
    }
    return filtered
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}