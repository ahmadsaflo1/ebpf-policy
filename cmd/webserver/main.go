package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"

	"github.com/ahmadsaflo1/ebpf-policy/internal/agent"
	"github.com/ahmadsaflo1/ebpf-policy/internal/config"
	"github.com/ahmadsaflo1/ebpf-policy/web"
)

var (
	// Build name and version are set using ld-flags
	BuildName    string
	BuildVersion string
)

func main() {

	if BuildName == "" {
		BuildName = os.Args[0]
	}
	if BuildVersion == "" {
		BuildVersion = "dev"
	}

	var (
		optConfig    string
		optLoglevel  string
		optLogFormat string
	)
	flag.StringVar(&optConfig, "c", "", "config file")
	flag.StringVar(&optLoglevel, "l", "info", "log level")
	flag.StringVar(&optLogFormat, "f", "text", "log format")
	flag.Parse()

	setupLogger(os.Stdout, optLoglevel, optLogFormat)

	slog.Info("starting", "name", BuildName, "version", BuildVersion, "level", optLoglevel, "format", optLogFormat, "config", optConfig)

	conf, err := config.New(optConfig)
	if err != nil {
		slog.Error("configuration", "error", err)
		os.Exit(0)
	}

	// dump config settings in debug mode
	if optLoglevel == "debug" {
		slog.Debug("config", slog.Any("settings", *conf))
	}

	// catch process SIGINT
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)

	// we use context with cancel to broadcast termination
	ctx, terminate := context.WithCancel(context.Background())

	srv, err := web.Start(ctx, conf)
	if err != nil {
		slog.Error("server", "error", err)
		os.Exit(1)
	}

	if conf.Agent.Interface != "" {
		if err := agent.Start(ctx, conf); err != nil {
			slog.Error("agent", "error", err)
			os.Exit(1)
		}
	} else {
		slog.Info("agent disabled — set [agent] interface in config to enable")
	}

	<-sigint
	slog.Info("terminating")
	srv.Close()
	terminate()
}

func setupLogger(output io.Writer, level, format string) {
	// setup logger
	logOptions := &slog.HandlerOptions{}

	switch level {
	case "debug":
		logOptions.AddSource = true
		logOptions.Level = slog.LevelDebug
	case "info":
		logOptions.Level = slog.LevelInfo
	case "warn":
		logOptions.Level = slog.LevelWarn
	case "error":
		logOptions.Level = slog.LevelError
	default:
		logOptions.Level = slog.LevelInfo
	}

	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}

	var logger *slog.Logger
	if format == "json" {
		logger = slog.New(slog.NewJSONHandler(output, logOptions)).With(slog.String("host", host))
	} else {
		logger = slog.New(slog.NewTextHandler(output, logOptions)).With(slog.String("host", host))
	}
	slog.SetDefault(logger)
}
