package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	agentconfig "github.com/ahmadsaflo1/ebpf-policy/internal/agent/config"
	ebpfloader "github.com/ahmadsaflo1/ebpf-policy/internal/agent/ebpf"
	"github.com/ahmadsaflo1/ebpf-policy/internal/agent/reporter"
	"github.com/ahmadsaflo1/ebpf-policy/internal/agent/system"
	"github.com/ahmadsaflo1/ebpf-policy/internal/config"
	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

// Start initializes the eBPF enforcement agent using settings from the config file.
// It returns once the agent is running; goroutines shut down when ctx is cancelled.
func Start(ctx context.Context, conf *config.Settings) error {
	log.Println("Starting Policy Agent ...")

	cfg := &agentconfig.Config{
		NatsURL:   conf.Nats.Url,
		ServerURL: conf.Agent.ServerURL,
		AgentID:   conf.Agent.AgentID,
		Interface: conf.Agent.Interface,
		Topic:     conf.Agent.Topic,
	}

	log.Printf("Agent configured: ID=%s Interface=%s Topic=%s\n", cfg.AgentID, cfg.Interface, cfg.Topic)

	messaging.Init(cfg.NatsURL)

	program, err := ebpfloader.Load(cfg.Interface)
	if err != nil {
		messaging.Close()
		return fmt.Errorf("failed to load eBPF: %w", err)
	}

	initProtectedPorts(program)

	serverAvailable := true
	store := agentconfig.NewRuleStore()
	connectToServer(cfg, store, &serverAvailable)

	listener := agentconfig.NewListener(
		func(rule models.PolicyRule) { store.Upsert(rule) },
		func(ruleID int) { store.Delete(ruleID) },
	)
	listener.SetWhitelistHandler(func(update models.WhitelistUpdate) {
		ip := net.ParseIP(update.IP)
		if ip == nil {
			log.Printf("Whitelist update: invalid IP %q", update.IP)
			return
		}
		switch update.Action {
		case "add":
			if err := program.AddToBypassList(ip); err != nil {
				log.Printf("Whitelist: failed to add %s to bypass list: %v", update.IP, err)
			} else {
				log.Printf("Whitelist: added %s (trusted) — %s", update.IP, update.Reason)
			}
		case "remove":
			if err := program.RemoveFromBypassList(ip); err != nil {
				log.Printf("Whitelist: failed to remove %s from bypass list: %v", update.IP, err)
			} else {
				log.Printf("Whitelist: removed %s — %s", update.IP, update.Reason)
			}
		}
	})

	if err := listener.Start(cfg.AgentID, cfg.Topic); err != nil {
		program.Close()
		messaging.Close()
		return fmt.Errorf("failed to start policy listener: %w", err)
	}

	fetchWhitelist(program)

	rep := reporter.New(cfg.AgentID, &serverAvailable)
	rep.Start()

	sysReporter := system.NewReporter(cfg.AgentID, cfg.Topic, &serverAvailable)
	sysMonitor := system.New(cfg.AgentID, 30*time.Second, func(metrics models.SystemMetrics) {
		sysReporter.Report(metrics)
	})
	sysMonitor.Start()

	go runLoop(ctx, program, store, rep)
	go watchServer(ctx, cfg, store, &serverAvailable)

	go func() {
		<-ctx.Done()
		program.Close()
		messaging.Close()
		log.Println("Agent shutting down...")
	}()

	log.Println("Agent running — monitoring network traffic and applying policies...")
	return nil
}

func runLoop(ctx context.Context, program *ebpfloader.PolicyProgram, store *agentconfig.RuleStore, rep *reporter.Reporter) {
	prevCounts := make(map[string]uint64)
	prevBlocked := make(map[string]bool)
	activeRateLimits := make(map[string]int)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

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
			isBlocked := program.IsBlocked(ip)
			wasBlocked := prevBlocked[ipStr]
			prevBlocked[ipStr] = isBlocked

			rule := store.Match(reqPerSec)

			if isBlocked {
				if rule != nil && rule.Action == "block" {
					duration := time.Duration(rule.Duration) * time.Second
					program.BlockIP(ip, duration)
					log.Printf("IP %s still active (%d req/s) — extending block\n", ipStr, reqPerSec)
				}
			} else if wasBlocked {
				if rule != nil && rule.Action == "block" {
					duration := time.Duration(rule.Duration) * time.Second
					program.BlockIP(ip, duration)
					log.Printf("IP %s re-evaluated after block: still %d req/s — re-blocking for %ds!\n", ipStr, reqPerSec, rule.Duration)
				} else {
					log.Printf("IP %s re-evaluated after block: %d req/s — unblocked\n", ipStr, reqPerSec)
				}
			} else if rule != nil && rule.Action == "block" {
				duration := time.Duration(rule.Duration) * time.Second
				program.BlockIP(ip, duration)
				log.Printf("IP %s exceeds limit (%d req/s) — blocking for %ds!\n", ipStr, reqPerSec, rule.Duration)
			} else if rule != nil && rule.Action == "rate_limit" {
				if activeRateLimits[ipStr] != rule.Threshold {
					program.SetRateLimit(ip, uint64(rule.Threshold))
					activeRateLimits[ipStr] = rule.Threshold
					log.Printf("IP %s rate limited to %d req/s (traffic: %d req/s)\n", ipStr, rule.Threshold, reqPerSec)
				}
			} else if activeRateLimits[ipStr] != 0 {
				program.RemoveRateLimit(ip)
				delete(activeRateLimits, ipStr)
				log.Printf("IP %s rate limit removed (%d req/s — below threshold)\n", ipStr, reqPerSec)
			}

			clientStat := models.ClientStats{
				IP:          ipStr,
				ReqPerSec:   reqPerSec,
				Blocked:     boolToInt(isBlocked),
				RateLimited: boolToInt(activeRateLimits[ipStr] != 0),
				Passed:      int(diff),
			}

			if latency, ok := latencyStats[ipStr]; ok && latency != nil {
				clientStat.AvgLatencyUs = latency.GetAvgLatencyUs()
				clientStat.MinLatencyUs = latency.GetMinLatencyUs()
				clientStat.MaxLatencyUs = latency.GetMaxLatencyUs()
			}

			rep.AddStat(clientStat)
		}
	}
}

func watchServer(ctx context.Context, cfg *agentconfig.Config, store *agentconfig.RuleStore, serverAvailable *bool) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		rules, err := agentconfig.FetchRules(cfg.ServerURL, cfg.Topic)
		if err != nil {
			if *serverAvailable {
				log.Printf("Server is down: %v — continuing with current rules\n", err)
				*serverAvailable = false
			} else {
				log.Println("Server still down — retrying in 15s")
			}
			continue
		}

		if !*serverAvailable {
			filtered := filterRules(rules, cfg.Topic)
			log.Println("Server is back — loading fresh rules")
			store.Clear()
			for _, rule := range filtered {
				store.Upsert(rule)
			}
			log.Printf("Fetched %d rules from server\n", len(filtered))
			*serverAvailable = true
		}
	}
}

func connectToServer(cfg *agentconfig.Config, store *agentconfig.RuleStore, serverAvailable *bool) {
	rules, err := agentconfig.FetchRulesViaNATS(cfg.Topic)
	if err == nil {
		filtered := filterRules(rules, cfg.Topic)
		for _, rule := range filtered {
			store.UpsertSilent(rule)
		}
		log.Printf("Fetched %d rules via NATS\n", len(filtered))
		*serverAvailable = true
		return
	}
	log.Printf("NATS fetch failed: %v — falling back to HTTP\n", err)

	for attempt := 1; attempt <= 4; attempt++ {
		rules, err := agentconfig.FetchRules(cfg.ServerURL, cfg.Topic)
		if err == nil {
			filtered := filterRules(rules, cfg.Topic)
			for _, rule := range filtered {
				store.UpsertSilent(rule)
			}
			log.Printf("Fetched %d rules via HTTP\n", len(filtered))
			*serverAvailable = true
			return
		}

		log.Printf("Could not reach server (attempt %d/4): %v — retrying in 5s\n", attempt, err)

		if attempt < 4 {
			time.Sleep(5 * time.Second)
		}
	}

	log.Println("Could not reach server after 4 attempts — using cached rules")
	store.LoadFromDisk()
	*serverAvailable = false
}

func initProtectedPorts(program *ebpfloader.PolicyProgram) {
	defaults := []uint16{80, 443, 8080}
	for _, port := range defaults {
		if err := program.AddProtectedPort(port); err != nil {
			log.Printf("Warning: could not register protected port %d: %v", port, err)
		}
	}
	log.Printf("Protected ports initialized: %v", defaults)
}

func filterRules(rules []models.PolicyRule, topic string) []models.PolicyRule {
	var filtered []models.PolicyRule
	for _, rule := range rules {
		if rule.Topic == "" || rule.Topic == topic {
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

// fetchWhitelist requests the current trusted-IP list from the policy server
// via NATS (whitelist.fetch) and seeds the eBPF bypass_list map so whitelisted
// IPs are enforced immediately without waiting for a whitelist.update message.
func fetchWhitelist(program *ebpfloader.PolicyProgram) {
	data, err := messaging.Request("whitelist.fetch", []byte("{}"), 5*time.Second)
	if err != nil {
		log.Printf("Whitelist fetch failed (will apply updates as they arrive): %v", err)
		return
	}
	var resp models.WhitelistFetchResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		log.Printf("Whitelist fetch: bad response: %v", err)
		return
	}
	for _, ipStr := range resp.IPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if err := program.AddToBypassList(ip); err != nil {
			log.Printf("Whitelist fetch: could not add %s: %v", ipStr, err)
		}
	}
	log.Printf("Whitelist fetch: seeded %d trusted IPs into bypass list", len(resp.IPs))
}
