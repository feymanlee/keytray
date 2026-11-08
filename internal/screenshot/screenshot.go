// Package screenshot captures a user-selected screen region. v1 ships the
// macOS backend (the system screencapture tool); other platforms return
// ErrUnsupported until their M-for-Windows backends land.
package screenshot

import "errors"

var (
	// ErrCanceled means the user dismissed the region selection (Esc).
	ErrCanceled = errors.New("screenshot: capture canceled")
	// ErrUnsupported means this platform has no capture backend (yet).
	ErrUnsupported = errors.New("screenshot: not supported on this platform")
	// ErrPermission means the OS has not granted screen capture.
	ErrPermission = errors.New("screenshot: screen recording permission not granted")
)
