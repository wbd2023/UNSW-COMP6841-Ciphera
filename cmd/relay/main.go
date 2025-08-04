package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"ciphera/internal/domain"
)

// In-memory relay.
type state struct {
	mu      sync.Mutex
	bundles map[string]domain.PrekeyBundle
	queues  map[string][]domain.Envelope
}

func newState() *state {
	return &state{
		bundles: make(map[string]domain.PrekeyBundle),
		queues:  make(map[string][]domain.Envelope),
	}
}

func main() {
	s := newState()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", s.handleRegister) // POST
	mux.HandleFunc("/prekey/", s.handleGetPrekey) // GET  /prekey/{username}
	mux.HandleFunc("/msg/", s.handleMsg)          // POST /msg/{to}, GET /msg/{user}, POST /msg/{user}/ack

	addr := "127.0.0.1:8080"
	log.Printf("relay listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, logMiddleware(mux)))
}

func (s *state) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var b domain.PrekeyBundle
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if b.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.bundles[b.Username] = b
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *state) handleGetPrekey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimPrefix(r.URL.Path, "/prekey/")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	b, ok := s.bundles[username]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, b)
}

func (s *state) handleMsg(w http.ResponseWriter, r *http.Request) {
	// POST /msg/{to}
	// GET  /msg/{user}?limit=N
	// POST /msg/{user}/ack   { "count": N }
	path := strings.TrimPrefix(r.URL.Path, "/msg/")
	if path == "" {
		http.Error(w, "user required", http.StatusBadRequest)
		return
	}

	// Ack
	if strings.HasSuffix(path, "/ack") && r.Method == http.MethodPost {
		user := strings.TrimSuffix(path, "/ack")
		var body struct {
			Count int `json:"count"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Count < 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		q := s.queues[user]
		if body.Count > len(q) {
			body.Count = len(q)
		}
		s.queues[user] = q[body.Count:]
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch r.Method {
	case http.MethodPost:
		to := path
		var env domain.Envelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if env.Timestamp == 0 {
			env.Timestamp = time.Now().Unix()
		}
		if env.To == "" {
			env.To = to
		}
		// Keep Prekey if present.
		s.mu.Lock()
		s.queues[to] = append(s.queues[to], env)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case http.MethodGet:
		user := path
		limit, _ := parseLimit(r.URL.Query().Get("limit"))
		s.mu.Lock()
		defer s.mu.Unlock()
		q := s.queues[user]
		if limit == 0 || limit > len(q) {
			limit = len(q)
		}
		out := make([]domain.Envelope, limit)
		copy(out, q[:limit])
		writeJSON(w, out)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func parseLimit(v string) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, errors.New("bad limit")
	}
	return n, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		http.Error(w, fmt.Sprintf("encode error: %v", err), http.StatusInternalServerError)
	}
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
