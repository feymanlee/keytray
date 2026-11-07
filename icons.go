// Issuer icons for the account list. Icons are embedded SVGs under
// resources/icons/<keyword>.svg; an issuer whose lower-case name contains
// the keyword uses that icon. Everything else falls back to the
// framework's letter avatar, so adding a brand is dropping a file into
// resources/icons — no code changes.
package main

import (
	"embed"
	"io/fs"
	"sort"
	"strings"
	"sync"

	"github.com/egoist/mygo/ui"
)

//go:embed all:resources/icons
var iconFS embed.FS

var (
	iconsOnce   sync.Once
	parsedIcons map[string]*ui.SVG // keyword → parsed icon
)

// loadIcons reads and parses resources/icons/*.svg once. A malformed file
// is skipped: an icon must never take the app down.
func loadIcons() {
	parsedIcons = map[string]*ui.SVG{}
	entries, err := fs.ReadDir(iconFS, "resources/icons")
	if err != nil {
		return
	}
	// Longest keyword wins, so "tencent cloud" beats "tencent".
	sorted := append([]fs.DirEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i].Name()) > len(sorted[j].Name()) })
	for _, e := range sorted {
		name := e.Name()
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".svg") {
			continue
		}
		data, err := iconFS.ReadFile("resources/icons/" + name)
		if err != nil {
			continue
		}
		svg, err := ui.ParseSVG(data)
		if err != nil {
			continue
		}
		parsedIcons[strings.TrimSuffix(lower, ".svg")] = svg
	}
}

// iconForIssuer returns the parsed icon whose keyword appears in the
// issuer, or nil when there is none.
func iconForIssuer(issuer string) *ui.SVG {
	iconsOnce.Do(loadIcons)
	q := strings.ToLower(strings.TrimSpace(issuer))
	if q == "" {
		return nil
	}
	for keyword, svg := range parsedIcons {
		if strings.Contains(q, keyword) {
			return svg
		}
	}
	return nil
}
