package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wing/config"
	"wing/daemon"
)

func runDaemon(cfgPath string, cfg *config.Config, wgGoPath string, reuse bool) error {
	if err := config.PersistRuntimeIdentity(cfgPath, cfg); err != nil {
		return err
	}
	runtimeCfg := daemon.RuntimeConfig(cfg)
	initialCandidates := daemon.DiscoverCandidates(context.Background(), cfg, true)
	sess, err := startSession(runtimeCfg, wgGoPath, reuse, false)
	if err != nil {
		return err
	}
	defer sess.cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	state := daemon.NewState(cfgPath, sess.osIface, runtimeCfg, initialCandidates)

	fmt.Printf("daemon: up %s (os=%s, addr=%s)\n", runtimeCfg.Interface, sess.osIface, runtimeCfg.Address)
	_ = state.Publish(ctx, initialCandidates)
	_ = state.RefreshPeers(ctx)

	reconcileTicker := time.NewTicker(time.Second)
	defer reconcileTicker.Stop()
	publishTicker := time.NewTicker(time.Duration(runtimeCfg.Daemon.PublishInterval) * time.Second)
	defer publishTicker.Stop()
	fetchTicker := time.NewTicker(time.Duration(runtimeCfg.Daemon.FetchInterval) * time.Second)
	defer fetchTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-publishTicker.C:
			candidates := daemon.DiscoverCandidates(ctx, runtimeCfg, false)
			state.Candidates = candidates
			if err := state.Publish(ctx, candidates); err != nil {
				fmt.Fprintf(os.Stderr, "daemon publish: %v\n", err)
			}
		case <-fetchTicker.C:
			if err := state.RefreshPeers(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "daemon fetch: %v\n", err)
			}
		case <-reconcileTicker.C:
			if err := state.RetryPeers(); err != nil {
				fmt.Fprintf(os.Stderr, "daemon retry: %v\n", err)
			}
		}
	}
}
