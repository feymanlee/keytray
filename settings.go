package main

import (
	"encoding/json"
	"os"

	"keytray/internal/vault"
)

// Settings are the app's non-secret preferences, stored as plain JSON next
// to the vault (settings.json). The vault stays the only encrypted file.
type Settings struct {
	Autostart       bool   `json:"autostart"`
	ClearClipboard  bool   `json:"clearClipboard"`
	ShowGroups      bool   `json:"showGroups"` // group by issuer, default on
	AutoUnlock      bool   `json:"autoUnlock"` // keychain auto-unlock, default off
	AutoLock        bool   `json:"autoLock"`
	AutoLockMinutes int    `json:"autoLockMinutes"`
	SummonShortcut  string `json:"summonShortcut"`  // open the panel
	CaptureShortcut string `json:"captureShortcut"` // screen-capture import

	HTTPEnabled bool   `json:"httpEnabled"` // codes over local HTTP, default off
	HTTPPort    int    `json:"httpPort"`
	HTTPToken   string `json:"httpToken,omitempty"` // random, regenerated on demand
}

const (
	defaultSummonShortcut   = "Alt+Space"
	fallbackSummonShortcut  = "Alt+Shift+Space"
	defaultCaptureShortcut  = "Alt+S"
	fallbackCaptureShortcut = "Alt+D"
)

// shortcut presets offered in the settings window.
var (
	summonPresets      = []string{defaultSummonShortcut, fallbackSummonShortcut, "CmdOrCtrl+Alt+Space", "F8"}
	capturePresets     = []string{defaultCaptureShortcut, fallbackCaptureShortcut, "CmdOrCtrl+Alt+S"}
	lockMinutesPresets = []string{"1", "5", "10", "15", "30", "60"}
	httpPortPresets    = []string{"17304", "18080", "28080"}
)

func defaultSettings() Settings {
	return Settings{
		Autostart:       true,
		ClearClipboard:  true,
		ShowGroups:      true,
		AutoLock:        false, // 默认不锁定(2026-11-06 需求修订)
		AutoLockMinutes: 5,
		SummonShortcut:  defaultSummonShortcut,
		CaptureShortcut: defaultCaptureShortcut,
		HTTPPort:        defaultHTTPPort,
	}
}

// normalize repairs invalid or missing values.
func (s *Settings) normalize() {
	if s.SummonShortcut == "" {
		s.SummonShortcut = defaultSummonShortcut
	}
	if s.CaptureShortcut == "" {
		s.CaptureShortcut = defaultCaptureShortcut
	}
	if s.HTTPPort < 1024 || s.HTTPPort > 65535 {
		s.HTTPPort = defaultHTTPPort
	}
	if s.AutoLockMinutes < 1 {
		s.AutoLockMinutes = 5 // unset/garbage → default
	} else if s.AutoLockMinutes > 60 {
		s.AutoLockMinutes = 60 // clamp to the 1–60 minute range
	}
}

// loadSettings reads settings over the defaults; a missing or unreadable
// file yields the defaults.
func loadSettings(path string) Settings {
	st := defaultSettings()
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &st) // bad JSON keeps the defaults
	}
	st.normalize()
	return st
}

// saveSettings atomically writes settings (0600).
func saveSettings(path string, st Settings) error {
	st.normalize()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return vault.SaveFile(path, data)
}
