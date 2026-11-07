package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"keytray/internal/otp"
)

func TestBuildSnapshot(t *testing.T) {
	now := time.Unix(59, 0).UTC()
	github := githubAccount(t)
	bank := bankAccount(t)
	snap := buildSnapshot([]otp.Account{github, bank}, now)
	if snap.Locked || len(snap.Items) != 2 {
		t.Fatalf("snapshot: %+v", snap)
	}
	item := snap.Items[0]
	if item.Issuer != "GitHub" || item.Type != "TOTP" || item.RemainingSec != 1 || item.PeriodSec != 30 {
		t.Errorf("item0: %+v", item)
	}
	if item.Code == "" || len(item.Code) != 6 {
		t.Errorf("item0 code: %q", item.Code)
	}
	if snap.Items[1].Type != "HOTP" || snap.Items[1].Counter != 7 {
		t.Errorf("item1: %+v", snap.Items[1])
	}
}

func TestHTTPServerAuthAndServe(t *testing.T) {
	token := "tok-abc"
	snap := codeSnapshot{Items: []codeItem{{Issuer: "GitHub", Name: "feyman", Type: "TOTP", Code: "123456", RemainingSec: 9}}}
	h := newHTTPServer(0, func() string { return token }, func() codeSnapshot { return snap })
	// Serve against a synthetic listener through our handler.
	rec := func(target string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if code := rec("/codes", nil).Code; code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code := rec("/codes?token=wrong", nil).Code; code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", code)
	}
	if code := rec("/codes?token=tok-abc", nil).Code; code != http.StatusOK {
		t.Fatalf("query token: %d", code)
	}
	if code := rec("/codes", map[string]string{"X-Keytray-Token": "tok-abc"}).Code; code != http.StatusOK {
		t.Errorf("header token: %d", code)
	}
	if code := rec("/codes", map[string]string{"X-Keytray-Token": "tok-abc"}).Code; code != http.StatusOK {
		t.Errorf("header token again: %d", code)
	}
	if code := rec("/codes", map[string]string{"X-Keytray-Token": "tok-abc"}).Code; code != http.StatusOK {
		t.Errorf("constant-time path: %d", code)
	}
	if code := func() int {
		req := httptest.NewRequest(http.MethodPost, "/codes?token=tok-abc", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}(); code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", code)
	}

	var body struct {
		Ok    bool       `json:"ok"`
		Count int        `json:"count"`
		Codes []codeItem `json:"codes"`
	}
	w := rec("/codes?token=tok-abc", nil)
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !body.Ok || body.Count != 1 || len(body.Codes) != 1 || body.Codes[0].Code != "123456" {
		t.Errorf("body: %+v", body)
	}
}

func TestHTTPServerLocked(t *testing.T) {
	h := newHTTPServer(0, func() string { return "t" }, func() codeSnapshot { return codeSnapshot{Locked: true} })
	req := httptest.NewRequest(http.MethodGet, "/codes?token=t", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusLocked {
		t.Fatalf("locked status: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "locked") {
		t.Errorf("body: %s", w.Body.String())
	}
}

func TestSettingsHTTPDefaults(t *testing.T) {
	st := loadSettings(joinPath(t))
	if st.HTTPEnabled {
		t.Error("HTTP must default off")
	}
	if st.HTTPPort != defaultHTTPPort {
		t.Errorf("port default: %d", st.HTTPPort)
	}
	st.HTTPPort = 80 // clamped on normalize
	st.normalize()
	if st.HTTPPort != defaultHTTPPort {
		t.Errorf("clamped port: %d", st.HTTPPort)
	}
}

func joinPath(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/settings.json"
}

func TestGenerateToken(t *testing.T) {
	a, b := generateToken(), generateToken()
	if a == b || len(a) != 64 {
		t.Errorf("token gen: %q vs %q", a, b)
	}
}
