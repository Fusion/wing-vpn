package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"wing/config"
	"wing/rendezvous"
)

type rendezvousLookupResult struct {
	Server string             `json:"server"`
	Error  string             `json:"error,omitempty"`
	Record *rendezvous.Record `json:"record,omitempty"`
}

type rendezvousWinner struct {
	Server string             `json:"server"`
	Record *rendezvous.Record `json:"record,omitempty"`
}

type rendezvousStatusResult struct {
	Target      string                  `json:"target"`
	WGPublicKey string                  `json:"wg_public_key"`
	Servers     []rendezvousLookupResult `json:"servers"`
	Winner      *rendezvousWinner       `json:"winner,omitempty"`
}

type rendezvousServerListing struct {
	Server  string              `json:"server"`
	Error   string              `json:"error,omitempty"`
	Records []rendezvous.Record `json:"records,omitempty"`
}

type mergedRendezvousRecord struct {
	WGPublicKey string            `json:"wg_public_key"`
	Winner      string            `json:"winner"`
	Record      rendezvous.Record `json:"record"`
}

type rendezvousListResult struct {
	Target        string                   `json:"target"`
	Servers       []rendezvousServerListing `json:"servers"`
	MergedRecords []mergedRendezvousRecord `json:"merged_records,omitempty"`
}

func HandleRendezvousStatus(cfg *config.Config, query string, jsonOutput bool) error {
	urls := config.EffectiveRendezvousURLs(cfg)
	if len(urls) == 0 {
		return errors.New("no rendezvous urls configured")
	}
	query = strings.TrimSpace(query)
	if query == "all" || query == "*" {
		return handleRendezvousListStatus(urls, jsonOutput)
	}

	targetLabel, targetPub, err := resolveRendezvousTarget(cfg, query)
	if err != nil {
		return err
	}

	if !jsonOutput {
		fmt.Printf("target: %s\n", targetLabel)
		fmt.Printf("wg_public_key: %s\n", targetPub)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := rendezvousStatusResult{
		Target:      targetLabel,
		WGPublicKey: targetPub,
		Servers:     make([]rendezvousLookupResult, 0, len(urls)),
	}
	var latest *rendezvous.Record
	var latestSource string
	for _, baseURL := range urls {
		record, err := rendezvous.Fetch(ctx, baseURL, targetPub)
		entry := rendezvousLookupResult{Server: baseURL}
		if err != nil {
			entry.Error = err.Error()
		} else {
			entry.Record = record
		}
		result.Servers = append(result.Servers, entry)
		if jsonOutput {
			if err != nil || record == nil {
				continue
			}
			if latest == nil || record.Sequence > latest.Sequence {
				latest = record
				latestSource = baseURL
			}
			continue
		}
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

	if latest != nil {
		result.Winner = &rendezvousWinner{
			Server: latestSource,
			Record: latest,
		}
	}

	if jsonOutput {
		return writeJSON(result)
	}

	if latest == nil {
		fmt.Printf("winner: (none)\n")
		return nil
	}

	fmt.Printf("winner: %s\n", latestSource)
	printRendezvousRecord(latest)
	return nil
}

func handleRendezvousListStatus(urls []string, jsonOutput bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type serverListing struct {
		baseURL string
		records []rendezvous.Record
		err     error
	}

	listings := make([]serverListing, 0, len(urls))
	merged := make(map[string]rendezvous.Record)
	winners := make(map[string]string)
	result := rendezvousListResult{
		Target:  "all",
		Servers: make([]rendezvousServerListing, 0, len(urls)),
	}

	if !jsonOutput {
		fmt.Printf("target: all\n")
	}
	for _, baseURL := range urls {
		records, err := rendezvous.FetchAll(ctx, baseURL)
		listings = append(listings, serverListing{baseURL: baseURL, records: records, err: err})
		entry := rendezvousServerListing{Server: baseURL}
		if err != nil {
			entry.Error = err.Error()
		} else {
			entry.Records = append([]rendezvous.Record(nil), records...)
		}
		result.Servers = append(result.Servers, entry)
		if err != nil {
			continue
		}
		for _, record := range records {
			current, ok := merged[record.WGPublicKey]
			if !ok || record.Sequence > current.Sequence {
				merged[record.WGPublicKey] = record
				winners[record.WGPublicKey] = baseURL
			}
		}
	}

	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		record := merged[key]
		result.MergedRecords = append(result.MergedRecords, mergedRendezvousRecord{
			WGPublicKey: key,
			Winner:      winners[key],
			Record:      record,
		})
	}

	if jsonOutput {
		return writeJSON(result)
	}

	for _, listing := range listings {
		fmt.Printf("server: %s\n", listing.baseURL)
		if listing.err != nil {
			fmt.Printf("  error: %v\n", listing.err)
			continue
		}
		if len(listing.records) == 0 {
			fmt.Printf("  records: (none)\n")
			continue
		}
		fmt.Printf("  records: %d\n", len(listing.records))
		for _, record := range listing.records {
			fmt.Printf("  - wg_public_key: %s\n", record.WGPublicKey)
			printRendezvousRecordWithIndent(&record, "    ")
		}
	}

	if len(merged) == 0 {
		fmt.Printf("merged_records: (none)\n")
		return nil
	}

	// The merged view is newest-by-sequence across servers, not a claim that
	// every server agreed on the same record contents.
	fmt.Printf("merged_records: %d\n", len(keys))
	for _, key := range keys {
		record := merged[key]
		fmt.Printf("- wg_public_key: %s\n", key)
		fmt.Printf("  winner: %s\n", winners[key])
		printRendezvousRecordWithIndent(&record, "  ")
	}
	return nil
}

func resolveRendezvousTarget(cfg *config.Config, query string) (string, string, error) {
	query = strings.TrimSpace(query)
	if query == "" || query == "self" {
		if strings.TrimSpace(cfg.PublicKey) == "" {
			return "", "", errors.New("self public_key is empty")
		}
		return "self", cfg.PublicKey, nil
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
	if query == cfg.PublicKey {
		return "self", cfg.PublicKey, nil
	}
	return "", "", fmt.Errorf("peer %q not found in config", query)
}

func printRendezvousRecord(record *rendezvous.Record) {
	printRendezvousRecordWithIndent(record, "  ")
}

func printRendezvousRecordWithIndent(record *rendezvous.Record, indent string) {
	if record == nil {
		return
	}
	if strings.TrimSpace(record.Name) != "" {
		fmt.Printf("%sname: %s\n", indent, record.Name)
	}
	fmt.Printf("%ssequence: %d\n", indent, record.Sequence)
	fmt.Printf("%sobserved_at: %s\n", indent, record.ObservedAt)
	fmt.Printf("%sexpires_at: %s\n", indent, record.ExpiresAt)
	if strings.TrimSpace(record.Endpoint) != "" {
		fmt.Printf("%sendpoint: %s\n", indent, record.Endpoint)
	}
	if len(record.AllowedIPs) > 0 {
		fmt.Printf("%sallowed_ips: %s\n", indent, strings.Join(record.AllowedIPs, ", "))
	}
	fmt.Printf("%scontrol_public_key: %s\n", indent, record.ControlPublicKey)
	if record.RootPublicKey != "" {
		fmt.Printf("%sroot_public_key: %s\n", indent, record.RootPublicKey)
	}
	if record.IdentitySignature != "" {
		fmt.Printf("%sidentity_signature: %s\n", indent, record.IdentitySignature)
	}
	fmt.Printf("%scandidates:\n", indent)
	for _, candidate := range record.Candidates {
		source := candidate.Source
		if source == "" {
			source = "-"
		}
		fmt.Printf("%s  - %s %s (%s)\n", indent, candidate.Type, candidate.Address, source)
	}
}

func PrintRendezvousStatusHint() {
	fmt.Fprintf(os.Stderr, "hint: use -rendezvous-status self, -rendezvous-status all, or -rendezvous-status <peer-name-or-public-key>\n")
}

func writeJSON(value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}
