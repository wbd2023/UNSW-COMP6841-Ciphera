package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"ciphera/internal/domain"
)

// --- Flags ---

var (
	port          int  // listen port
	enableLogging bool // logging toggle
)

// --- Constants ---

// Networking and server limits.
const (
	defaultPort    = 8080
	minPort        = 0
	maxPort        = 65535
	readHeaderTO   = 5 * time.Second
	readTO         = 10 * time.Second
	writeTO        = 10 * time.Second
	idleTO         = 60 * time.Second
	maxRequestBody = 1 << 20 // 1 MiB cap for incoming JSON bodies
)

// Relay policy limits.
const (
	maxPerUserQueue = 1000             // cap messages kept per user
	maxCipherBytes  = 64 << 10         // 64 KiB max cipher payload
	maxOneTimeKeys  = 500              // max one-time prekeys in a bundle
	maxFutureSkew   = 10 * time.Minute // reject timestamps too far in the future
)

// Context key for request ID.
type ctxKey string

const ctxKeyReqID ctxKey = "reqid"

// --- Types & Constructors ---

// state holds registered prekey bundles and per-user message queues.
type state struct {
	mu      sync.RWMutex
	bundles map[domain.Username]domain.PreKeyBundle
	queues  map[domain.Username][]domain.Envelope
}

// newState initialises an empty relay state.
func newState() *state {
	return &state{
		bundles: make(map[domain.Username]domain.PreKeyBundle),
		queues:  make(map[domain.Username][]domain.Envelope),
	}
}

// loggingResponseWriter captures status code and byte count for access logs.
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

// --- Middleware ---

// withRecover wraps a handler to convert panics into 500 responses.
func withRecover(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeErr(w, http.StatusInternalServerError, "internal error")
				if enableLogging {
					slog.Error("panic", "err", rec)
				}
			}
		}()
		h(w, r)
	}
}

// withReqID ensures each request has an ID for tracing.
func withReqID(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = genReqID()
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), ctxKeyReqID, id)
		h(w, r.WithContext(ctx))
	}
}

// withLogging logs method, path, remote, status, bytes, duration and request ID.
func withLogging(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !enableLogging {
			h(w, r)
			return
		}
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w}
		h(lrw, r)
		reqID := requestIDFromCtx(r.Context())
		slog.Info("access",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", clientIP(r),
			"status", lrw.status,
			"bytes", lrw.bytes,
			"dur", time.Since(start),
			"reqid", reqID,
		)
	}
}

// chain composes middlewares in order.
func chain(h http.HandlerFunc, mws ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// --- Utilities ---

// WriteHeader records the status code then forwards to the underlying writer.
func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}

// Write records the bytes written and defaults status to 200 if unset.
func (lrw *loggingResponseWriter) Write(p []byte) (int, error) {
	if lrw.status == 0 {
		lrw.status = http.StatusOK
	}
	n, err := lrw.ResponseWriter.Write(p)
	lrw.bytes += n
	return n, err
}

// isZero32 checks whether a 32-byte slice is all zeros in constant time.
func isZero32(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	var zero [32]byte
	return subtle.ConstantTimeCompare(b, zero[:]) == 1
}

// writeJSON encodes v as JSON with no HTML escaping.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// Best effort error path.
		http.Error(w, fmt.Sprintf("encode error: %v", err), http.StatusInternalServerError)
	}
}

// writeErr writes a JSON error object with a given status code.
func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// parseLimit parses the optional "limit" query parameter.
func parseLimit(v string) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid limit")
	}
	return n, nil
}

// clientIP extracts the client IP from headers or RemoteAddr.
func clientIP(r *http.Request) string {
	// Respect common proxy headers. This is best-effort.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First hop is the client.
		if i := indexByte(xff, ','); i >= 0 {
			return trimSpace(xff[:i])
		}
		return trimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// requestIDFromCtx returns the request ID if present.
func requestIDFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyReqID).(string); ok {
		return v
	}
	return ""
}

// genReqID creates a simple 128-bit random hex ID.
func genReqID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to timestamp based if rand fails.
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// Small helpers without extra imports.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
func trimSpace(s string) string {
	// Minimal trim to avoid extra import.
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// --- Handlers ---

// handleRegister stores an incoming PrekeyBundle (POST /register).
func (s *state) handleRegister(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var bundle domain.PreKeyBundle
	if err := dec.Decode(&bundle); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if bundle.Username == "" {
		writeErr(w, http.StatusBadRequest, "username required")
		return
	}
	if bundle.Canary == "" {
		writeErr(w, http.StatusBadRequest, "canary required")
		return
	}
	if bundle.ServerURL == "" {
		writeErr(w, http.StatusBadRequest, "server url required")
		return
	}
	if len(bundle.OneTimePreKeys) > maxOneTimeKeys {
		writeErr(w, http.StatusRequestEntityTooLarge, "too many one-time keys")
		return
	}

	s.mu.Lock()
	s.bundles[bundle.Username] = bundle
	s.mu.Unlock()

	if enableLogging {
		slog.Info("register",
			"user", bundle.Username.String(),
			"identity_key_set", !isZero32(bundle.IdentityKey[:]),
			"signing_key_set", !isZero32(bundle.SigningKey[:]),
			"spk_id", bundle.SignedPreKeyID,
			"one_time_count", len(bundle.OneTimePreKeys),
			"reqid", requestIDFromCtx(r.Context()),
		)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGet returns a stored PrekeyBundle (GET /prekey/{username}).
func (s *state) handleGet(w http.ResponseWriter, r *http.Request) {
	usernameValue := domain.Username(r.PathValue("username"))
	if usernameValue == "" {
		writeErr(w, http.StatusBadRequest, "username required")
		return
	}

	s.mu.RLock()
	bundle, ok := s.bundles[usernameValue]
	s.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	if enableLogging {
		slog.Info(
			"prekey_fetch",
			"user", usernameValue.String(),
			"spk_id", bundle.SignedPreKeyID,
			"one_time_count", len(bundle.OneTimePreKeys),
			"reqid", requestIDFromCtx(r.Context()),
		)
	}
	writeJSON(w, bundle)
}

// handleAccountCanary returns the stored canary (GET /account/{user}/canary).
func (s *state) handleAccountCanary(w http.ResponseWriter, r *http.Request) {
	usernameValue := domain.Username(r.PathValue("user"))
	if usernameValue == "" {
		writeErr(w, http.StatusBadRequest, "username required")
		return
	}

	s.mu.RLock()
	bundle, ok := s.bundles[usernameValue]
	s.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	writeJSON(w, map[string]string{"canary": bundle.Canary})
}

// handleEnqueue enqueues a new Envelope (POST /msg/{user}).
func (s *state) handleEnqueue(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	usernameValue := domain.Username(r.PathValue("user"))

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var env domain.Envelope
	if err := dec.Decode(&env); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if env.To == "" {
		writeErr(w, http.StatusBadRequest, "recipient required")
		return
	}
	// Prevent route and payload mismatch.
	if usernameValue == "" || usernameValue != env.To {
		writeErr(w, http.StatusBadRequest, "recipient mismatch")
		return
	}
	// Basic payload caps and sanity checks.
	if len(env.Cipher) > maxCipherBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "cipher too large")
		return
	}
	if env.Timestamp == 0 {
		env.Timestamp = time.Now().Unix()
	} else {
		now := time.Now()
		ts := time.Unix(env.Timestamp, 0)
		if ts.After(now.Add(maxFutureSkew)) {
			writeErr(w, http.StatusBadRequest, "timestamp in future")
			return
		}
	}

	// Append with per-user queue cap, drop oldest if needed.
	s.mu.Lock()
	queue := append(s.queues[usernameValue], env)
	if len(queue) > maxPerUserQueue {
		queue = queue[len(queue)-maxPerUserQueue:]
	}
	s.queues[usernameValue] = queue
	queueLength := len(queue)
	s.mu.Unlock()

	if enableLogging {
		slog.Info("enqueue",
			"queue_user", usernameValue.String(),
			"from", env.From.String(),
			"to", env.To.String(),
			"cipher_bytes", len(env.Cipher),
			"has_prekey", env.PreKey != nil,
			"queue_len", queueLength,
			"reqid", requestIDFromCtx(r.Context()),
		)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleFetch fetches queued Envelopes (GET /msg/{user}?limit=N).
func (s *state) handleFetch(w http.ResponseWriter, r *http.Request) {
	usernameValue := domain.Username(r.PathValue("user"))

	limit, err := parseLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad limit")
		return
	}

	// Copy under lock to avoid races with concurrent enqueue/ack.
	s.mu.RLock()
	queue := s.queues[usernameValue]
	if limit == 0 || limit > len(queue) {
		limit = len(queue)
	}
	out := make([]domain.Envelope, limit)
	copy(out, queue[:limit])
	available := len(queue)
	s.mu.RUnlock()

	writeJSON(w, out)

	if enableLogging {
		slog.Info(
			"fetch",
			"user", usernameValue.String(),
			"limit", limit,
			"available", available,
			"reqid", requestIDFromCtx(r.Context()),
		)
	}
}

// handleAck acknowledges and drops N messages (POST /msg/{user}/ack).
func (s *state) handleAck(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	usernameValue := domain.Username(r.PathValue("user"))

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var ack struct {
		Count int `json:"count"`
	}
	if err := dec.Decode(&ack); err != nil || ack.Count < 0 {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}

	s.mu.Lock()
	if ack.Count > len(s.queues[usernameValue]) {
		ack.Count = len(s.queues[usernameValue])
	}
	s.queues[usernameValue] = s.queues[usernameValue][ack.Count:]
	remaining := len(s.queues[usernameValue])
	s.mu.Unlock()

	if enableLogging {
		slog.Info(
			"ack",
			"user", usernameValue.String(),
			"drop", ack.Count,
			"remaining", remaining,
			"reqid", requestIDFromCtx(r.Context()),
		)
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Main ---

// main starts the HTTP server and registers handlers.
func main() {
	pflag.IntVarP(&port, "port", "p", defaultPort, "port to listen on")
	pflag.BoolVar(&enableLogging, "log", false, "enable access logging")
	pflag.Parse()

	if port <= minPort || port > maxPort {
		port = defaultPort
	}

	logger := slog.New(
		slog.NewTextHandler(log.Writer(), &slog.HandlerOptions{Level: slog.LevelInfo}),
	)
	slog.SetDefault(logger)

	s := newState()
	mux := http.NewServeMux()

	// Register HTTP endpoints. Middlewares: recover -> reqid -> logging -> handler
	mux.HandleFunc(
		"POST /register",
		chain(s.handleRegister, withRecover, withReqID, withLogging),
	) // POST /register
	mux.HandleFunc(
		"GET /prekey/{username}",
		chain(s.handleGet, withRecover, withReqID, withLogging),
	) // GET  /prekey/{username}
	mux.HandleFunc(
		"GET /account/{user}/canary",
		chain(s.handleAccountCanary, withRecover, withReqID, withLogging),
	) // GET /account/{user}/canary
	mux.HandleFunc(
		"POST /msg/{user}",
		chain(s.handleEnqueue, withRecover, withReqID, withLogging),
	) // POST /msg/{user}
	mux.HandleFunc(
		"GET /msg/{user}",
		chain(s.handleFetch, withRecover, withReqID, withLogging),
	) // GET  /msg/{user}
	mux.HandleFunc(
		"POST /msg/{user}/ack",
		chain(s.handleAck, withRecover, withReqID, withLogging),
	) // POST /msg/{user}/ack

	// Simple health check for readiness/liveness probes.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTO,
		ReadTimeout:       readTO,
		WriteTimeout:      writeTO,
		IdleTimeout:       idleTO,
	}

	// Graceful shutdown.
	go func() {
		slog.Info("Relay listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Relay failed", "error", err)
		}
	}()

	// Wait for interrupt or terminate signal.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	slog.Info("Shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Graceful shutdown failed", "error", err)
	}
}
