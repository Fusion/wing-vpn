package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
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

type graphNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

type graphEdge struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Highlight bool   `json:"highlight"`
}

type graphPage struct {
	Title string      `json:"title"`
	Nodes []graphNode `json:"nodes"`
	Edges []graphEdge `json:"edges"`
}

func HandleRendezvousStatus(cfg *config.Config, query string, jsonOutput bool, graphPath string) error {
	if jsonOutput && strings.TrimSpace(graphPath) != "" {
		return errors.New("choose only one output format: --json or --graph")
	}
	textOutput := !jsonOutput && strings.TrimSpace(graphPath) == ""
	urls := config.EffectiveRendezvousURLs(cfg)
	if len(urls) == 0 {
		return errors.New("no rendezvous urls configured")
	}
	query = strings.TrimSpace(query)
	if query == "all" || query == "*" {
		return handleRendezvousListStatus(urls, jsonOutput, graphPath)
	}

	targetLabel, targetPub, err := resolveRendezvousTarget(cfg, query)
	if err != nil {
		return err
	}

	if textOutput {
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
		if !textOutput {
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
	if strings.TrimSpace(graphPath) != "" {
		return writeGraphFile(graphPath, graphPageFromStatus(result))
	}

	if latest == nil {
		fmt.Printf("winner: (none)\n")
		return nil
	}

	fmt.Printf("winner: %s\n", latestSource)
	printRendezvousRecord(latest)
	return nil
}

func handleRendezvousListStatus(urls []string, jsonOutput bool, graphPath string) error {
	textOutput := !jsonOutput && strings.TrimSpace(graphPath) == ""
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

	if textOutput {
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
	if strings.TrimSpace(graphPath) != "" {
		return writeGraphFile(graphPath, graphPageFromList(result))
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

func writeGraphFile(path string, page graphPage) error {
	htmlDoc, err := renderGraphHTML(page)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(htmlDoc), 0o644); err != nil {
		return err
	}
	fmt.Printf("graph: %s\n", path)
	return nil
}

func graphPageFromStatus(result rendezvousStatusResult) graphPage {
	page := graphPage{
		Title: fmt.Sprintf("wing-vpn rendezvous status: %s", result.Target),
	}
	peerLabel := result.Target
	peerDetail := fmt.Sprintf("wg_public_key: %s", result.WGPublicKey)
	if result.Winner != nil && result.Winner.Record != nil {
		peerLabel = peerLabelForRecord(result.Winner.Record, result.Target)
		peerDetail = recordDetail(result.Winner.Record)
	}
	page.Nodes = append(page.Nodes, graphNode{
		ID:     "peer:" + result.WGPublicKey,
		Label:  peerLabel,
		Kind:   "peer",
		Detail: peerDetail,
	})
	for _, server := range result.Servers {
		page.Nodes = append(page.Nodes, graphNode{
			ID:     "server:" + server.Server,
			Label:  server.Server,
			Kind:   "server",
			Detail: serverDetail(server),
		})
		if server.Record == nil {
			continue
		}
		page.Edges = append(page.Edges, graphEdge{
			From:      "server:" + server.Server,
			To:        "peer:" + result.WGPublicKey,
			Highlight: result.Winner != nil && result.Winner.Server == server.Server,
		})
	}
	return page
}

func graphPageFromList(result rendezvousListResult) graphPage {
	page := graphPage{
		Title: "wing-vpn rendezvous status: all peers",
	}
	for _, server := range result.Servers {
		page.Nodes = append(page.Nodes, graphNode{
			ID:     "server:" + server.Server,
			Label:  server.Server,
			Kind:   "server",
			Detail: listServerDetail(server),
		})
	}
	for _, merged := range result.MergedRecords {
		page.Nodes = append(page.Nodes, graphNode{
			ID:     "peer:" + merged.WGPublicKey,
			Label:  peerLabelForRecord(&merged.Record, merged.WGPublicKey),
			Kind:   "peer",
			Detail: recordDetail(&merged.Record),
		})
	}
	for _, server := range result.Servers {
		for _, record := range server.Records {
			page.Edges = append(page.Edges, graphEdge{
				From:      "server:" + server.Server,
				To:        "peer:" + record.WGPublicKey,
				Highlight: winnerForRecord(result.MergedRecords, record.WGPublicKey) == server.Server,
			})
		}
	}
	return page
}

func winnerForRecord(records []mergedRendezvousRecord, wgPublicKey string) string {
	for _, record := range records {
		if record.WGPublicKey == wgPublicKey {
			return record.Winner
		}
	}
	return ""
}

func peerLabelForRecord(record *rendezvous.Record, fallback string) string {
	if record == nil {
		return fallback
	}
	if strings.TrimSpace(record.Name) != "" {
		return record.Name
	}
	if strings.TrimSpace(record.WGPublicKey) != "" {
		return record.WGPublicKey
	}
	return fallback
}

func recordDetail(record *rendezvous.Record) string {
	if record == nil {
		return ""
	}
	lines := []string{
		fmt.Sprintf("wg_public_key: %s", record.WGPublicKey),
		fmt.Sprintf("sequence: %d", record.Sequence),
		fmt.Sprintf("observed_at: %s", record.ObservedAt),
		fmt.Sprintf("expires_at: %s", record.ExpiresAt),
		fmt.Sprintf("control_public_key: %s", record.ControlPublicKey),
	}
	if strings.TrimSpace(record.Endpoint) != "" {
		lines = append(lines, fmt.Sprintf("endpoint: %s", record.Endpoint))
	}
	if len(record.AllowedIPs) > 0 {
		lines = append(lines, fmt.Sprintf("allowed_ips: %s", strings.Join(record.AllowedIPs, ", ")))
	}
	if strings.TrimSpace(record.RootPublicKey) != "" {
		lines = append(lines, fmt.Sprintf("root_public_key: %s", record.RootPublicKey))
	}
	if len(record.Candidates) > 0 {
		lines = append(lines, "candidates:")
		for _, candidate := range record.Candidates {
			source := candidate.Source
			if source == "" {
				source = "-"
			}
			lines = append(lines, fmt.Sprintf("  - %s %s (%s)", candidate.Type, candidate.Address, source))
		}
	}
	return strings.Join(lines, "\n")
}

func serverDetail(server rendezvousLookupResult) string {
	if server.Error != "" {
		return "error: " + server.Error
	}
	if server.Record == nil {
		return "record: (none)"
	}
	return "record available"
}

func listServerDetail(server rendezvousServerListing) string {
	if server.Error != "" {
		return "error: " + server.Error
	}
	return fmt.Sprintf("records: %d", len(server.Records))
}

func renderGraphHTML(page graphPage) (string, error) {
	graphJSON, err := json.Marshal(page)
	if err != nil {
		return "", err
	}
	title := html.EscapeString(page.Title)
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>%s</title>
  <style>
    :root {
      --bg: #f4f6f8;
      --panel: #ffffff;
      --text: #0f1720;
      --muted: #5a6b7a;
      --server: #d7ebff;
      --peer: #e3f6df;
      --edge: #b7c2cc;
      --edge-win: #ff7a18;
      --border: #d7dde3;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif; background: linear-gradient(180deg, #eef3f6 0%%, #f8fafb 100%%); color: var(--text); }
    header { padding: 20px 24px 8px; }
    h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .sub { margin-top: 6px; color: var(--muted); font-size: 14px; }
    .layout { display: grid; grid-template-columns: minmax(720px, 1fr) 320px; gap: 18px; padding: 8px 24px 24px; }
    .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 16px; box-shadow: 0 8px 24px rgba(15, 23, 32, 0.06); }
    .graph-wrap { position: relative; min-height: 640px; overflow: auto; padding: 12px; }
    #graph { position: relative; min-height: 600px; }
    #edges { position: absolute; inset: 0; width: 100%%; height: 100%%; pointer-events: none; }
    .node { position: absolute; width: 180px; min-height: 64px; border-radius: 16px; border: 1px solid var(--border); padding: 12px 14px; box-shadow: 0 8px 18px rgba(15, 23, 32, 0.08); cursor: pointer; }
    .node.server { background: var(--server); }
    .node.peer { background: var(--peer); }
    .node h2 { margin: 0; font-size: 15px; line-height: 1.3; word-break: break-word; }
    .node p { margin: 6px 0 0; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
    .info { padding: 18px 18px 20px; }
    .info h2 { margin: 0 0 10px; font-size: 17px; }
    .info pre { margin: 0; white-space: pre-wrap; word-break: break-word; font-family: "SFMono-Regular", Menlo, Monaco, monospace; font-size: 12px; line-height: 1.45; color: var(--muted); }
    .legend { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; font-size: 13px; color: var(--muted); }
    .chip { display: inline-flex; align-items: center; gap: 8px; padding: 6px 10px; border-radius: 999px; border: 1px solid var(--border); background: #fafcfd; }
    .dot { width: 10px; height: 10px; border-radius: 999px; display: inline-block; }
    @media (max-width: 1100px) { .layout { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <h1>%s</h1>
    <div class="sub">Servers sit near the center and peers orbit around them. Orange edges mark the merged winning record.</div>
  </header>
  <div class="layout">
    <section class="panel graph-wrap">
      <div id="graph">
        <svg id="edges"></svg>
      </div>
    </section>
    <aside class="panel info">
      <h2>Details</h2>
      <pre id="detail">Select a node to inspect its record details.</pre>
      <div class="legend">
        <span class="chip"><span class="dot" style="background: var(--server)"></span>Rendezvous server</span>
        <span class="chip"><span class="dot" style="background: var(--peer)"></span>Peer</span>
        <span class="chip"><span class="dot" style="background: var(--edge-win)"></span>Winning record edge</span>
      </div>
    </aside>
  </div>
  <script>
    const page = %s;
    const graph = document.getElementById("graph");
    const edgesSvg = document.getElementById("edges");
    const detail = document.getElementById("detail");
    const servers = page.nodes.filter(node => node.kind === "server");
    const peers = page.nodes.filter(node => node.kind === "peer");
    const nodePositions = new Map();
    const serverRadius = Math.max(0, 48 + Math.max(0, servers.length - 1) * 28);
    const peerRadius = Math.max(220, 180 + peers.length * 22);
    const width = Math.max(760, peerRadius * 2 + 360);
    const height = Math.max(760, peerRadius * 2 + 220);
    const centerX = width / 2;
    const centerY = height / 2;
    graph.style.width = width + "px";
    graph.style.height = height + "px";
    edgesSvg.setAttribute("viewBox", "0 0 " + width + " " + height);
    function createNode(node, x, y) {
      const el = document.createElement("button");
      el.type = "button";
      el.className = "node " + node.kind;
      el.style.left = x + "px";
      el.style.top = y + "px";
      el.innerHTML = "<h2>" + escapeHtml(node.label) + "</h2><p>" + escapeHtml(node.kind) + "</p>";
      el.addEventListener("click", () => {
        detail.textContent = node.detail || node.label;
      });
      graph.appendChild(el);
      nodePositions.set(node.id, { x: x + 90, y: y + 32 });
    }
    function polarToCanvas(radius, angle, nodeWidth, nodeHeight) {
      return {
        x: centerX + Math.cos(angle) * radius - nodeWidth / 2,
        y: centerY + Math.sin(angle) * radius - nodeHeight / 2
      };
    }
    servers.forEach((node, index) => {
      const angle = ((Math.PI * 2) / Math.max(1, servers.length)) * index - Math.PI / 2;
      const pos = polarToCanvas(serverRadius, angle, 180, 64);
      createNode(node, pos.x, pos.y);
    });
    peers.forEach((node, index) => {
      const angle = ((Math.PI * 2) / Math.max(1, peers.length)) * index - Math.PI / 2;
      const pos = polarToCanvas(peerRadius, angle, 180, 64);
      createNode(node, pos.x, pos.y);
    });
    page.edges.forEach(edge => {
      const from = nodePositions.get(edge.from);
      const to = nodePositions.get(edge.to);
      if (!from || !to) return;
      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", from.x);
      line.setAttribute("y1", from.y);
      line.setAttribute("x2", to.x);
      line.setAttribute("y2", to.y);
      line.setAttribute("stroke", edge.highlight ? "var(--edge-win)" : "var(--edge)");
      line.setAttribute("stroke-width", edge.highlight ? "3" : "2");
      line.setAttribute("stroke-linecap", "round");
      edgesSvg.appendChild(line);
    });
    function escapeHtml(value) {
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
    }
  </script>
</body>
</html>`, title, title, string(graphJSON)), nil
}
