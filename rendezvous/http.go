package rendezvous

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const fetchLatestWindow = 1200 * time.Millisecond

type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]Record
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

func NewHandler(store *MemoryStore) http.Handler {
	if store == nil {
		store = NewMemoryStore()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/records/", func(w http.ResponseWriter, r *http.Request) {
		wgPublicKey, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/v1/records/"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if wgPublicKey == "" {
			http.Error(w, "missing record key", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var record Record
			if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if record.WGPublicKey != wgPublicKey {
				http.Error(w, "wg_public_key path mismatch", http.StatusBadRequest)
				return
			}
			if err := record.Verify(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			store.Put(record)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			record, ok := store.Get(wgPublicKey)
			if !ok {
				http.NotFound(w, r)
				return
			}
			if err := record.Verify(); err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(record)
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return mux
}

func Serve(ctx context.Context, listen string) error {
	if strings.TrimSpace(listen) == "" {
		listen = ":8787"
	}
	srv := &http.Server{
		Addr:    listen,
		Handler: NewHandler(nil),
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
