package rendezvous

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"wing/config"
)

const fetchLatestWindow = 1200 * time.Millisecond

type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]Record
}

type HandlerOptions struct {
	TrustedRootPublicKeys []string
	Debug                 bool
	Logf                  func(format string, args ...any)
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record)}
}

func (s *MemoryStore) Put(record Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.WGPublicKey] = record
}

func (s *MemoryStore) Get(wgPublicKey string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[wgPublicKey]
	return record, ok
}

func (s *MemoryStore) List() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		out = append(out, record)
	}
	slices.SortFunc(out, func(a, b Record) int {
		return strings.Compare(a.WGPublicKey, b.WGPublicKey)
	})
	return out
}

func NewHandler(store *MemoryStore) http.Handler {
	handler, err := NewHandlerWithOptions(store, HandlerOptions{})
	if err != nil {
		panic(err)
	}
	return handler
}

func NewHandlerWithOptions(store *MemoryStore, opts HandlerOptions) (http.Handler, error) {
	if store == nil {
		store = NewMemoryStore()
	}
	trustedRoots, err := normalizeTrustedRoots(opts.TrustedRootPublicKeys)
	if err != nil {
		return nil, err
	}
	logf := opts.Logf
	if logf == nil {
		logf = log.Printf
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			debugLogf(opts.Debug, logf, "rendezvous request rejected remote=%s method=%s reason=method_not_allowed", r.RemoteAddr, r.Method)
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		records := store.List()
		valid := make([]Record, 0, len(records))
		for _, record := range records {
			if err := record.Verify(); err != nil {
				debugLogf(opts.Debug, logf, "rendezvous query list skipping invalid wg=%s err=%v", record.WGPublicKey, err)
				continue
			}
			valid = append(valid, record)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(valid)
		debugLogf(opts.Debug, logf, "rendezvous query list remote=%s count=%d", r.RemoteAddr, len(valid))
	})
	mux.HandleFunc("/v1/records/", func(w http.ResponseWriter, r *http.Request) {
		wgPublicKey, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/v1/records/"))
		if err != nil {
			debugLogf(opts.Debug, logf, "rendezvous path decode rejected remote=%s path=%q err=%v", r.RemoteAddr, r.URL.Path, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if wgPublicKey == "" {
			debugLogf(opts.Debug, logf, "rendezvous request rejected remote=%s method=%s reason=missing_record_key", r.RemoteAddr, r.Method)
			http.Error(w, "missing record key", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var record Record
			if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
				debugLogf(opts.Debug, logf, "rendezvous register rejected remote=%s wg=%s err=%v", r.RemoteAddr, wgPublicKey, err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if record.WGPublicKey != wgPublicKey {
				debugLogf(opts.Debug, logf, "rendezvous register rejected remote=%s wg=%s reason=path_mismatch payload_wg=%s", r.RemoteAddr, wgPublicKey, record.WGPublicKey)
				http.Error(w, "wg_public_key path mismatch", http.StatusBadRequest)
				return
			}
			existing, hasExisting := store.Get(wgPublicKey)
			statusCode, err := validateStoredRecord(record, trustedRoots, hasExisting, existing)
			if err != nil {
				debugLogf(opts.Debug, logf, "rendezvous register rejected remote=%s wg=%s status=%d err=%v record=%s", r.RemoteAddr, wgPublicKey, statusCode, err, recordSummary(record))
				http.Error(w, err.Error(), statusCode)
				return
			}
			store.Put(record)
			debugLogf(opts.Debug, logf, "rendezvous register accepted remote=%s wg=%s record=%s", r.RemoteAddr, wgPublicKey, recordSummary(record))
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			record, ok := store.Get(wgPublicKey)
			if !ok {
				debugLogf(opts.Debug, logf, "rendezvous query miss remote=%s wg=%s", r.RemoteAddr, wgPublicKey)
				http.NotFound(w, r)
				return
			}
			if err := record.Verify(); err != nil {
				debugLogf(opts.Debug, logf, "rendezvous query invalid remote=%s wg=%s err=%v", r.RemoteAddr, wgPublicKey, err)
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(record)
			debugLogf(opts.Debug, logf, "rendezvous query hit remote=%s wg=%s record=%s", r.RemoteAddr, wgPublicKey, recordSummary(record))
		default:
			debugLogf(opts.Debug, logf, "rendezvous request rejected remote=%s method=%s wg=%s reason=method_not_allowed", r.RemoteAddr, r.Method, wgPublicKey)
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return mux, nil
}

func Serve(ctx context.Context, listen string, trustedRootPublicKeys []string, debug bool) error {
	if strings.TrimSpace(listen) == "" {
		listen = ":8787"
	}
	if len(trustedRootPublicKeys) == 0 {
		return errors.New("at least one trusted root public key is required")
	}
	handler, err := NewHandlerWithOptions(nil, HandlerOptions{
		TrustedRootPublicKeys: trustedRootPublicKeys,
		Debug:                 debug,
	})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:    listen,
		Handler: handler,
	}
	errc := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()
	return <-errc
}

func normalizeTrustedRoots(values []string) (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if err := config.ValidateControlPublicKey(value); err != nil {
			return nil, fmt.Errorf("invalid trusted root public key: %v", err)
		}
		out[value] = struct{}{}
	}
	return out, nil
}

func validateStoredRecord(record Record, trustedRoots map[string]struct{}, hasExisting bool, existing Record) (int, error) {
	if err := record.Verify(); err != nil {
		return http.StatusBadRequest, err
	}
	if len(trustedRoots) > 0 {
		if strings.TrimSpace(record.RootPublicKey) == "" || strings.TrimSpace(record.IdentitySignature) == "" {
			return http.StatusForbidden, errors.New("root-issued identity is required")
		}
		if _, ok := trustedRoots[strings.TrimSpace(record.RootPublicKey)]; !ok {
			return http.StatusForbidden, errors.New("record root_public_key is not trusted")
		}
	}
	if hasExisting && !sameIdentityBinding(existing, record) {
		return http.StatusConflict, errors.New("existing record is bound to a different identity")
	}
	return 0, nil
}

func sameIdentityBinding(a, b Record) bool {
	return strings.TrimSpace(a.WGPublicKey) == strings.TrimSpace(b.WGPublicKey) &&
		strings.TrimSpace(a.ControlPublicKey) == strings.TrimSpace(b.ControlPublicKey) &&
		strings.TrimSpace(a.RootPublicKey) == strings.TrimSpace(b.RootPublicKey) &&
		strings.TrimSpace(a.IdentitySignature) == strings.TrimSpace(b.IdentitySignature)
}

func debugLogf(enabled bool, logf func(format string, args ...any), format string, args ...any) {
	if !enabled || logf == nil {
		return
	}
	logf(format, args...)
}

func recordSummary(record Record) string {
	best := BestEndpoint(&record)
	if best == "" {
		best = "-"
	}
	root := strings.TrimSpace(record.RootPublicKey)
	if root == "" {
		root = "-"
	}
	return fmt.Sprintf("seq=%d candidates=%d best=%s control=%s root=%s expires_at=%s",
		record.Sequence,
		len(record.Candidates),
		best,
		shortKey(record.ControlPublicKey),
		shortKey(root),
		record.ExpiresAt,
	)
}

func shortKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return value
	}
	if len(value) <= 16 {
		return value
	}
	return value[:8] + "..." + value[len(value)-8:]
}

func Publish(ctx context.Context, baseURL string, record *Record) error {
	if record == nil {
		return errors.New("record is nil")
	}
	if err := record.Verify(); err != nil {
		return err
	}
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, recordURL(baseURL, record.WGPublicKey), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("rendezvous publish returned %s", resp.Status)
	}
	return nil
}

func PublishAll(ctx context.Context, baseURLs []string, record *Record) error {
	if record == nil {
		return errors.New("record is nil")
	}
	if len(baseURLs) == 0 {
		return nil
	}
	var errs []string
	successes := 0
	for _, baseURL := range baseURLs {
		if err := Publish(ctx, baseURL, record); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", baseURL, err))
			continue
		}
		successes++
	}
	if successes > 0 {
		return nil
	}
	return fmt.Errorf("rendezvous publish failed: %s", strings.Join(errs, "; "))
}

func Fetch(ctx context.Context, baseURL, wgPublicKey string) (*Record, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, recordURL(baseURL, wgPublicKey), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rendezvous fetch returned %s", resp.Status)
	}
	var record Record
	if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
		return nil, err
	}
	if err := record.Verify(); err != nil {
		return nil, err
	}
	return &record, nil
}

func FetchAll(ctx context.Context, baseURL string) ([]Record, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, recordsURL(baseURL), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rendezvous list returned %s", resp.Status)
	}
	var records []Record
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, err
	}
	for i := range records {
		if err := records[i].Verify(); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(records, func(a, b Record) int {
		return strings.Compare(a.WGPublicKey, b.WGPublicKey)
	})
	return records, nil
}

func FetchLatest(ctx context.Context, baseURLs []string, wgPublicKey string) (*Record, error) {
	if len(baseURLs) == 0 {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	fetchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type fetchResult struct {
		baseURL string
		record  *Record
		err     error
	}

	results := make(chan fetchResult, len(baseURLs))
	for _, baseURL := range baseURLs {
		baseURL := baseURL
		go func() {
			record, err := Fetch(fetchCtx, baseURL, wgPublicKey)
			results <- fetchResult{baseURL: baseURL, record: record, err: err}
		}()
	}

	timer := time.NewTimer(fetchWindow(ctx))
	defer timer.Stop()

	var latest *Record
	var errs []string
	successfulLookup := false
	received := 0

collect:
	for received < len(baseURLs) {
		select {
		case result := <-results:
			received++
			if result.err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", result.baseURL, result.err))
				continue
			}
			successfulLookup = true
			if result.record == nil {
				continue
			}
			if latest == nil || result.record.Sequence > latest.Sequence {
				latest = result.record
			}
		case <-timer.C:
			cancel()
			break collect
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		}
	}
	if latest != nil {
		return latest, nil
	}
	if successfulLookup {
		return nil, nil
	}
	return nil, fmt.Errorf("rendezvous fetch failed: %s", strings.Join(errs, "; "))
}

func recordURL(baseURL, wgPublicKey string) string {
	base := strings.TrimRight(baseURL, "/")
	return base + "/v1/records/" + url.PathEscape(wgPublicKey)
}

func recordsURL(baseURL string) string {
	return strings.TrimRight(baseURL, "/") + "/v1/records"
}

func fetchWindow(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return time.Millisecond
		}
		if remaining < fetchLatestWindow {
			return remaining
		}
	}
	return fetchLatestWindow
}
