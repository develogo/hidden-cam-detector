package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"time"
)

func newServer(s *Scanner, loopback bool) http.Handler {
	static, _ := fs.Sub(webFiles, "web")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))

	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"subnet":       defaultSubnet(),
			"defaultPorts": defaultPorts,
			"timeoutMs":    700,
		})
	})

	mux.HandleFunc("POST /api/scan", func(w http.ResponseWriter, r *http.Request) {
		// Requiring JSON forces a CORS preflight, so an arbitrary website open in the browser cannot trigger scans.
		if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "use Content-Type: application/json"})
			return
		}
		var o Options
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&o); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		switch err := s.Start(o); {
		case errors.Is(err, errBusy):
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		case err != nil:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
		}
	})

	mux.HandleFunc("GET /api/devices", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.MarshalIndent(s.State(), "", "  ")
		w.Write(b)
	})

	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		changed, cancel := s.subscribe()
		defer cancel()
		for {
			// Always the full State: a reconnect or missed signal never leaves the screen inconsistent.
			b, _ := json.Marshal(s.State())
			fmt.Fprintf(w, "event: state\ndata: %s\n\n", b)
			fl.Flush()
			select { // at most one send every 250 ms; changes within that window are coalesced
			case <-r.Context().Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
			select {
			case <-r.Context().Done():
				return
			case <-changed:
			}
		}
	})

	if loopback {
		return hostGuard(mux)
	}
	return mux
}

// hostGuard blocks DNS rebinding: an external site pointing its domain at 127.0.0.1 cannot read the results.
func hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not allowed"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
