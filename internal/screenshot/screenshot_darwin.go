//go:build darwin

package screenshot

import (
	"bytes"
	"errors"
	"fmt"
	"image/png"
	"os"
	"os/exec"

	"github.com/ebitengine/purego"
)

// ErrPermission means macOS has not (yet) granted Screen Recording to
// this app build. Each rebuild changes the code signature, which
// invalidates the previous grant — re-approve and relaunch.
var ErrPermission = errors.New("screenshot: screen recording permission not granted")

// screenRecordingGranted asks CoreGraphics whether this process may
// capture the screen (no prompt).
func screenRecordingGranted() bool {
	lib, err := purego.Dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
	if err != nil {
		return true // can't check: let screencapture try anyway
	}
	var preflight func() bool
	purego.RegisterLibFunc(&preflight, lib, "CGPreflightScreenCaptureAccess")
	return preflight()
}

// CaptureRegion asks the user to pick a screen region with the system's
// interactive selector (screencapture -i), and returns it as PNG bytes.
// It blocks until the user finishes or cancels the selection.
//
// Requires the Screen Recording permission; without it macOS returns a
// desktop-image-only capture or an error.
func CaptureRegion() ([]byte, error) {
	if !screenRecordingGranted() {
		return nil, ErrPermission
	}
	tmp, err := os.CreateTemp("", "keytray-qr-*.png")
	if err != nil {
		return nil, err
	}
	path := tmp.Name()
	tmp.Close()
	defer os.Remove(path)

	// -i interactive region selection, -x no capture sound.
	cmd := exec.Command("screencapture", "-i", "-x", path)
	if err := cmd.Run(); err != nil {
		// Canceling (Esc, right-click) leaves no usable file.
		if info, statErr := os.Stat(path); statErr != nil || info.Size() == 0 {
			return nil, ErrCanceled
		}
		return nil, fmt.Errorf("screencapture: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrCanceled
	}
	return data, nil
}

// CaptureScreen grabs the whole primary display and returns PNG bytes.
// Used on Windows for the full-screen QR import; kept on macOS for the
// same fallback if the system selector ever proves unavailable.
func CaptureScreen() ([]byte, int, int, error) {
	tmp, err := os.CreateTemp("", "keytray-full-*.png")
	if err != nil {
		return nil, 0, 0, err
	}
	path := tmp.Name()
	tmp.Close()
	defer os.Remove(path)

	if err := exec.Command("screencapture", "-x", path).Run(); err != nil {
		return nil, 0, 0, fmt.Errorf("screencapture: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(data) == 0 {
		return nil, 0, 0, ErrCanceled
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return data, 0, 0, nil // still usable bytes
	}
	return data, cfg.Width, cfg.Height, nil
}
