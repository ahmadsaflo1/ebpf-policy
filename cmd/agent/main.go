package main

import (
    "log"
    "os"
    "os/signal"
    "syscall"
    "github.com/ahmadsaflo1/ebpf-policy/internal/agent/config"
    "github.com/ahmadsaflo1/ebpf-policy/internal/agent/reporter"
    "github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
    "github.com/ahmadsaflo1/ebpf-policy/internal/models"   
)

func main() {
    log.Println("Starting Policy Agent ...")

    cfg := config.Load()

    // Initialize NATS connection
    messaging.Init()
    defer messaging.Close()

    // initialize rule store
    store := config.NewRuleStore()

    rules, err := config.FetchRules(cfg.ServerURL)
    if err != nil {
        log.Println("Warning: Failed to fetch all rules: ", err)
    } else {
        for _, rule := range rules {
            store.Upsert(rule)
        }
    }

    // Start listening for policy updates
    listener := config.NewListener(
        func(rule models.PolicyRule) {
            store.Upsert(rule)
        },
        func(ruleID int) {
            store.Delete(ruleID)
        },
    )

    if err := listener.Start(); err != nil {
        log.Fatal("Failed to start policy listener: ", err)
    }

    // Start metrics reporter
    rep := reporter.New(cfg.AgentID)
    rep.Start()

    log.Println("Agent running — waiting for rule updates...")

    // Wait for termination signal to gracefully shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Shutting down agent...")
}