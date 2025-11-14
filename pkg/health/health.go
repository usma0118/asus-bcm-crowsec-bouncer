package health

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

type State struct {
	mu        sync.RWMutex
	lastSync  time.Time
	lastError string
}

func NewState() *State {
	return &State{}
}

func (s *State) RecordSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSync = time.Now().UTC()
	s.lastError = ""
}

func (s *State) RecordError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSync = time.Now().UTC()
	if err != nil {
		s.lastError = err.Error()
	} else {
		s.lastError = "unknown error"
	}
}

func (s *State) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := "ok"
	if s.lastError != "" {
		status = "degraded"
	}

	resp := map[string]string{
		"status":    status,
		"lastSync":  s.lastSync.Format(time.RFC3339),
		"lastError": s.lastError,
	}

	code := http.StatusOK
	if status != "ok" {
		code = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(resp)
}

func Serve(addr string, state *State, log *zap.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/healthz", state)

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	log.Info("health server listening", zap.String("addr", addr))
	return srv.ListenAndServe()
}
