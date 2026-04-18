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
    store := config.NewRuleStore()

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
    if err := listener.Start(cfg.Env); err != nil {
        log.Fatal("Failed to start policy listener:", err)
    }

    // Start metrics reporter to send stats back to the server
    rep := reporter.New(cfg.AgentID)
    rep.Start()


    prevCounts := make(map[string]uint64)

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
                prev := prevCounts[ipStr]
                diff := count - prev
                prevCounts[ipStr] = count

                reqPerSec := int(diff) / 10

                ip := net.ParseIP(ipStr)
                rule := store.Match(reqPerSec)
                isBlocked := program.IsBlocked(ip)

                if isBlocked {
                    if rule != nil{
                        // Still high traffic — extend the bloc
                        duration:= time.Duration(rule.Duration) * time.Second
                        program.BlockIP(ip, duration)
                        log.Printf("[%s] IP %s still active (%d req/s) — extending block\n",
                            cfg.AgentID, ipStr, reqPerSec)
                    } else {
                        // Traffic has calmed down — unblock
                        program.UnblockIP(ip)
                        log.Printf("[%s] IP %s calmed down (%d req/s) — unblocking\n",
                            cfg.AgentID, ipStr, reqPerSec)      
                    }
                } else if rule != nil {
                    // Not blocked but exceeds threshold — block
                    duration := time.Duration(rule.Duration) * time.Second
                    program.BlockIP(ip, duration)

                    log.Printf("[%s] IP %s exceeds limit (%d req/s) — blocking!\n",
                        cfg.AgentID, ipStr, reqPerSec)
                }

                // Send stats to the server for monitoring
                rep.AddStat(models.ClientStats{
                    IP:        ipStr,
                    ReqPerSec: reqPerSec,
                    Blocked:   boolToInt(isBlocked),
                    Passed:    int(diff),
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

func boolToInt(b bool) int {
    if b {
        return 1
    }
    return 0
}