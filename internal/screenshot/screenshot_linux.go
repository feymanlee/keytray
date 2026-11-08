//go:build linux

// Linux full-screen capture via whatever screenshot CLI the desktop
// environment provides: GNOME (gnome-screenshot), KDE (spectacle) or
// ImageMagick's import. Region selection is not available on Linux.
package screenshot

import (
	"bytes"
	"image/png"
	"os"
	"os/exec"
)

// CaptureScreen grabs the whole virtual screen and returns PNG bytes.
func CaptureScreen() ([]byte, int, int, error) {
	tmp, err := os.CreateTemp("", "keytray-full-*.png")
	if err != nil {
		return nil, 0, 0, err
	}
	path := tmp.Name()
	tmp.Close()
	defer os.Remove(path)

	// Ordered by prevalence; each tool captures all displays it sees.
	tries := [][]string{
		{"gnome-screenshot", "-f", path},
		{"spectacle", "-b", "-n", "-o", path}, // KDE: background, no notify
		{"import", "-window", "root", path},   // ImageMagick (X11)
	}
	var lastErr error
	for _, argv := range tries {
		if _, err := exec.LookPath(argv[0]); err != nil {
			lastErr = err
			continue
		}
		if err := exec.Command(argv[0], argv[1:]...).Run(); err == nil {
			if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
				w, h := 0, 0
				if cfg, err := png.DecodeConfig(bytes.NewReader(data)); err == nil {
					w, h = cfg.Width, cfg.Height
				}
				return data, w, h, nil
			}
		}
		lastErr = err
	}
	return nil, 0, 0, lastErr
}
