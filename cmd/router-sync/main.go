package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourname/crowdsec-asus-sync/pkg/config"
	"github.com/yourname/crowdsec-asus-sync/pkg/crowdsec"
	"github.com/yourname/crowdsec-asus-sync/pkg/health"
	"github.com/yourname/crowdsec-asus-sync/pkg/router"
	"github.com/yourname/crowdsec-asus-sync/pkg/syncer"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	logger := newLogger()
	defer logger.Sync()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	state := health.NewState()

	// Health endpoint
	healthAddr := getenv("HEALTH_ADDR", ":8081")
	go func() {
		if err := health.Serve(healthAddr, state, logger); err != nil {
			logger.Error("health server error", zap.Error(err))
		}
	}()

	// Load config (same YAML as custom-bouncer)
	cfgPath := getenv("BOUNCER_CONFIG", "/crowdsec-custom-bouncer.yaml")
	bcfg, err := config.Load(cfgPath)
	if err != nil {
		logger.Fatal("failed to load config", zap.Error(err), zap.String("path", cfgPath))
	}

	lapiURL, apiKey, insecure := config.ResolveLAPIParams(bcfg, logger)

	csClient := crowdsec.NewClient(lapiURL, apiKey, insecure, logger)

	sshRouter, err := router.NewSSHRouterFromEnv(logger)
	if err != nil {
		logger.Fatal("failed to init SSH router", zap.Error(err))
	}

	intervalStr := getenv("SYNC_INTERVAL", "5m")
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		logger.Fatal("invalid SYNC_INTERVAL", zap.Error(err), zap.String("value", intervalStr))
	}

	s := syncer.New(csClient, sshRouter, interval, state, logger)

	if err := s.Run(ctx); err != nil {
		logger.Fatal("syncer exited with error", zap.Error(err))
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newLogger() *zap.Logger {
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "timestamp"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.InfoLevel),
		Development:      false,
		Encoding:         "json",
		EncoderConfig:    encCfg,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	return logger
}
