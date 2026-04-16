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
    "github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
    "github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

func main() {
    log.Println("Starting Policy Agent ...")

    cfg := config.Load()

    // Initialize NATS connection for receiving policy updates and sending stats
    messaging.Init()
    defer messaging.Close()

    // Load eBPF program and attach to the specified network interface
    program, err := ebpfloader.Load(cfg.Interface)
    if err != nil {
        log.Fatal("Failed to load eBPF:", err)
    }
    defer program.Close()

    // initialize rule store and fetch initial rules from server
    store := config.NewRuleStore(cfg.AgentID)

    rules, err := config.FetchRules(cfg.ServerURL)
    if err != nil {
        log.Println("Warning: Failed to fetch all rules: ", err)
    } else {
        for _, rule := range rules {
            store.Upsert(rule)
        }
    }

    // Start listening for policy updates from the server
    listener := config.NewListener(
        func(rule models.PolicyRule) {
            store.Upsert(rule)
        },
        func(ruleID int) {
            store.Delete(ruleID)
        },
    )
    if err := listener.Start(); err != nil {
        log.Fatal("Failed to start policy listener:", err)
    }

    // Start metrics reporter to send stats back to the server
    rep := reporter.New(cfg.AgentID)
    rep.Start()

    // Periodically read stats from eBPF and apply policies
    go func() {
        ticker := time.NewTicker(10 * time.Second)
        for range ticker.C {
            // Get all IP stats from the eBPF program
            stats, err := program.GetAllStats()
            if err != nil {
                log.Println("Failed to read eBPF stats:", err)
                continue
            }

            // Check each IP against the policy rules and block if necessary
            for ipStr, count := range stats {
                reqPerSec := int(count) / 10
                rule := store.Match(reqPerSec)

                if rule != nil {
                    log.Printf("IP %s exceeds limit (%d req/s) — blocking!\n",
                        ipStr, reqPerSec)

                    ip := net.ParseIP(ipStr)
                    duration := time.Duration(rule.Duration) * time.Second
                    program.BlockIP(ip, duration)
                }

                // Send stats to the server for monitoring
                rep.AddStat(models.ClientStats{
                    IP:        ipStr,
                    ReqPerSec: reqPerSec,
                    Blocked:   0,
                    Passed:    int(count),
                })
            }
        }
    }()

    log.Println("Agent running — monitoring network traffic and applying policies...")
    
    // Wait for termination signal to gracefully shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Shutting down agent...")
}