package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"wing/config"
	"wing/rendezvous"
)

func handleRendezvousStatus(cfg *config.Config, query string) error {
	urls := config.EffectiveRendezvousURLs(cfg)
	if len(urls) == 0 {
		return errors.New("no rendezvous urls configured")
	}

	targetLabel, targetPub, err := resolveRendezvousTarget(cfg, query)
	if err != nil {
		return err
	}

	fmt.Printf("target: %s\n", targetLabel)
	fmt.Printf("wg_public_key: %s\n", targetPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var latest *rendezvous.Record
	var latestSource string
	for _, baseURL := range urls {
		record, err := rendezvous.Fetch(ctx, baseURL, targetPub)
		fmt.Printf("server: %s\n", baseURL)
		if err != nil {
			fmt.Printf("  error: %v\n", err)
			continue
		}
		if record == nil {
			fmt.Printf("  record: (none)\n")
			continue
		}
		printRendezvousRecord(record)
		if latest == nil || record.Sequence > latest.Sequence {
			latest = record
			latestSource = baseURL
		}
	}

	if latest == nil {
		fmt.Printf("winner: (none)\n")
		return nil
	}

	fmt.Printf("winner: %s\n", latestSource)
	printRendezvousRecord(latest)
	return nil
}

func resolveRendezvousTarget(cfg *config.Config, query string) (string, string, error) {
	query = strings.TrimSpace(query)
	if query == "" || query == "self" {
		if strings.TrimSpace(cfg.MyPublicKey) == "" {
			return "", "", errors.New("self my_public_key is empty")
		}
		return "self", cfg.MyPublicKey, nil
	}
	for _, peer := range cfg.Peers {
		if peer.Name == query || peer.PublicKey == query {
			label := peer.Name
			if label == "" {
				label = peer.PublicKey
			}
			return label, peer.PublicKey, nil
		}
	}
	if query == cfg.MyPublicKey {
		return "self", cfg.MyPublicKey, nil
	}
	return "", "", fmt.Errorf("peer %q not found in config", query)
}

func printRendezvousRecord(record *rendezvous.Record) {
	if record == nil {
		return
	}
	fmt.Printf("  sequence: %d\n", record.Sequence)
	fmt.Printf("  observed_at: %s\n", record.ObservedAt)
	fmt.Printf("  expires_at: %s\n", record.ExpiresAt)
	fmt.Printf("  control_public_key: %s\n", record.ControlPublicKey)
	fmt.Printf("  candidates:\n")
	for _, candidate := range record.Candidates {
		source := candidate.Source
		if source == "" {
			source = "-"
		}
		fmt.Printf("    - %s %s (%s)\n", candidate.Type, candidate.Address, source)
	}
}

func printRendezvousStatusHint() {
	fmt.Fprintf(os.Stderr, "hint: use -rendezvous-status self or -rendezvous-status <peer-name-or-public-key>\n")
}
