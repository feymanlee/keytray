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

// manageIcons are the row-action icons (24×24 stroke style, colored by
// currentColor to follow the theme).
var (
	manageOnce sync.Once
	editIcon   *ui.SVG
	upIcon     *ui.SVG
	downIcon   *ui.SVG
	trashIcon  *ui.SVG
)

func mustSVG(src string) *ui.SVG {
	svg, err := ui.ParseSVG([]byte(src))
	if err != nil {
		return nil
	}
	return svg
}

func loadManageIcons() {
	stroke := func(body string) string {
		return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">` + body + `</svg>`
	}
	editIcon = mustSVG(stroke(`<path d="M17 3l4 4L8 20l-5 1 1-5z"/><path d="M15 5l4 4"/>`))
	upIcon = mustSVG(stroke(`<polyline points="6 15 12 9 18 15"/>`))
	downIcon = mustSVG(stroke(`<polyline points="6 9 12 15 18 9"/>`))
	trashIcon = mustSVG(stroke(`<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M6 6l1 14h10l1-14"/>`))
}

// actionButton is a small icon button with hover feedback.
func actionButton(c *ui.Context, svg *ui.SVG, tip string, fn func()) {
	b := ui.Row(c).Padding(4, 6).Radius(6).AlignItems(ui.Center)
	hovered := b.Hovered()
	t := c.Theme()
	bg := ui.Transparent
	if hovered {
		bg = t.SurfacePressed
	}
	b.Background(bg).OnClick(fn).Children(func() {
		ui.Icon(c, svg).FontSize(14).TextColor(t.Text)
	})
}
