// Package qrcode decodes QR codes from images, for importing otpauth://
// URIs captured from the screen.
package qrcode

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg" // accept JPEG screen captures too
	_ "image/png"

	"github.com/makiuchi-d/gozxing"
	gozxingmulti "github.com/makiuchi-d/gozxing/multi/qrcode"
	gozxingqr "github.com/makiuchi-d/gozxing/qrcode"
)

// ErrNoQR means the image was read but contains no decodable QR code.
var ErrNoQR = fmt.Errorf("qrcode: no QR code found in image")

// DecodeImage decodes the first QR code in img and returns its text.
func DecodeImage(img image.Image) (string, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", err
	}
	result, err := gozxingqr.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", ErrNoQR
	}
	return result.GetText(), nil
}

// DecodeBytes decodes the first QR code in an encoded image (PNG/JPEG).
func DecodeBytes(data []byte) (string, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("qrcode: decode image: %w", err)
	}
	return DecodeImage(img)
}

// DecodeAllBytes decodes every QR code in an encoded image (PNG/JPEG),
// de-duplicated in discovery order. Falls back to the single-code reader
// when the multi detector finds nothing.
func DecodeAllBytes(data []byte) ([]string, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("qrcode: decode image: %w", err)
	}
	return DecodeAll(img)
}

// DecodeAll decodes every QR code in img; see DecodeAllBytes.
func DecodeAll(img image.Image) ([]string, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return nil, err
	}
	results, err := gozxingmulti.NewQRCodeMultiReader().DecodeMultipleWithoutHint(bmp)
	if err == nil && len(results) > 0 {
		return dedupe(results), nil
	}
	// Multi detection is lossy on small/single codes: one more try with
	// the dedicated single reader before giving up.
	s, singleErr := DecodeImage(img)
	if singleErr != nil {
		return nil, ErrNoQR
	}
	return []string{s}, nil
}

func dedupe(results []*gozxing.Result) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range results {
		t := r.GetText()
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}
