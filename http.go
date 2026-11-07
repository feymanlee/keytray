package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"keytray/internal/otp"
)

const defaultHTTPPort = 17304

// codeItem is one account's current code as served over HTTP.
type codeItem struct {
	Issuer       string `json:"issuer"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Code         string `json:"code"`
	RemainingSec uint32 `json:"remainingSec"`
	PeriodSec    uint32 `json:"periodSec,omitempty"`
	Counter      uint64 `json:"counter,omitempty"`
}

// codeSnapshot is what the HTTP server serves: the codes, or the fact
// that the vault is locked.
type codeSnapshot struct {
	Locked bool
	Items  []codeItem
}

// buildSnapshot computes the snapshot from accounts; pure and testable.
// The caller is responsible for running it on the main thread.
func buildSnapshot(accounts []otp.Account, now time.Time) codeSnapshot {
	items := make([]codeItem, 0, len(accounts))
	for _, a := range accounts {
		code, err := a.Code(now)
		if err != nil {
			continue
		}
		items = append(items, codeItem{
			Issuer:       a.Issuer,
			Name:         a.Name,
			Type:         string(a.Type),
			Code:         code,
			RemainingSec: a.SecondsRemaining(now),
			PeriodSec:    a.Period,
			Counter:      a.Counter,
		})
	}
	return codeSnapshot{Items: items}
}

// httpServer serves codes on 127.0.0.1 only, behind a random token.
type httpServer struct {
	port     int
	getToken func() string
	snapshot func() codeSnapshot // must hop to the main thread in production

	srv *http.Server
	ln  net.Listener
}

// newHTTPServer builds the server; callers Start it.
func newHTTPServer(port int, getToken func() string, snapshot func() codeSnapshot) *httpServer {
	return &httpServer{port: port, getToken: getToken, snapshot: snapshot}
}

// Start binds 127.0.0.1 and serves in the background.
func (h *httpServer) Start() error {
	if h.ln != nil {
		return nil // already running
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(h.port))
	if err != nil {
		return fmt.Errorf("监听失败:%w", err)
	}
	h.ln = ln
	h.srv = &http.Server{Handler: h}
	go func() { _ = h.srv.Serve(ln) }()
	return nil
}

// Stop shuts the server down; safe when not running.
func (h *httpServer) Stop() {
	if h.srv != nil {
		_ = h.srv.Close()
	}
	h.srv, h.ln = nil, nil
}

func (h *httpServer) Running() bool { return h.ln != nil }

// generateToken returns a fresh 256-bit hex token.
func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand unavailable: nothing sane to do
	}
	return hex.EncodeToString(b)
}

func (h *httpServer) authorized(r *http.Request) bool {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		tok = r.Header.Get("X-Keytray-Token")
	}
	want := h.getToken()
	return want != "" &&
		subtle.ConstantTimeCompare([]byte(tok), []byte(want)) == 1
}

func (h *httpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorized(r) {
		http.Error(w, "invalid or missing token (?token=…)", http.StatusUnauthorized)
		return
	}
	snap := h.snapshot()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if snap.Locked {
		w.WriteHeader(http.StatusLocked) // 423
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false, "locked": true, "error": "金库已锁定,解锁后再试",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":     true,
		"locked": false,
		"count":  len(snap.Items),
		"codes":  snap.Items,
	})
}

// ---- app wiring ----

// ensureHTTP starts the server if the settings ask for it (at launch and
// after every settings change that affects it).
func (a *app) ensureHTTP() {
	a.stopHTTP()
	if !a.state.settings.HTTPEnabled {
		return
	}
	if a.state.settings.HTTPToken == "" {
		a.state.settings.HTTPToken = generateToken()
		a.state.saveSettings()
	}
	h := newHTTPServer(a.state.settings.HTTPPort,
		func() string { return a.state.settings.HTTPToken },
		func() codeSnapshot {
			// Hop to the main thread: accounts live there. The import
			// window stays alive for the app's lifetime.
			done := make(chan codeSnapshot, 1)
			a.importUI.win.Update(func() {
				now := time.Now()
				s := a.state
				if s.encrypted && !s.unlocked {
					done <- codeSnapshot{Locked: true}
					return
				}
				done <- buildSnapshot(s.accounts, now)
			})
			return <-done
		})
	if err := h.Start(); err != nil {
		log.Printf("http: %v", err)
		return
	}
	a.httpSrv = h
}

func (a *app) stopHTTP() {
	if a.httpSrv != nil {
		a.httpSrv.Stop()
		a.httpSrv = nil
	}
}

// httpURL is the browser-ready URL of the codes endpoint.
func httpURL(port int, token string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/codes?token=%s", port, token)
}
