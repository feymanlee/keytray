//go:build !darwin

package screenshot

// CaptureRegion is unavailable outside macOS in v1.
func CaptureRegion() ([]byte, error) { return nil, ErrUnsupported }
