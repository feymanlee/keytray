package qrcode

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"testing"

	qrencode "github.com/skip2/go-qrcode"
)

func TestDecodeRoundTrip(t *testing.T) {
	uri := "otpauth://totp/GitHub:feyman%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	pngBytes, err := qrencode.Encode(uri, qrencode.Medium, 256)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBytes(pngBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got != uri {
		t.Errorf("got %q, want %q", got, uri)
	}
}

func TestDecodeRejectsNonImage(t *testing.T) {
	if _, err := DecodeBytes([]byte("not an image")); err == nil {
		t.Error("expected error for non-image bytes")
	}
	if _, err := DecodeBytes(nil); err == nil {
		t.Error("expected error for empty bytes")
	}
}

func TestDecodeBlankImageHasNoQR(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for i := range img.Pix {
		img.Pix[i] = 0xFF // plain white
	}
	_ = color.White
	if _, err := DecodeImage(img); err != ErrNoQR {
		t.Errorf("got %v, want ErrNoQR", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBytes(buf.Bytes()); err != ErrNoQR {
		t.Errorf("bytes path: got %v, want ErrNoQR", err)
	}
}

// drawQR renders text as a decoded QR image of the given size.
func drawQR(t *testing.T, text string, size int) image.Image {
	t.Helper()
	pngBytes, err := qrencode.Encode(text, qrencode.Medium, size)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// paste composes src into dst at (x, y).
func paste(dst *image.RGBA, src image.Image, x, y int) {
	b := src.Bounds()
	draw.Draw(dst, image.Rect(x, y, x+b.Dx(), y+b.Dy()), src, b.Min, draw.Src)
}

func TestDecodeAllFindsBothCodes(t *testing.T) {
	u1 := "otpauth://totp/One:a?secret=JBSWY3DPEHPK3PXP"
	u2 := "otpauth://totp/Two:b?secret=JBSWY3DPEHPK3PXP"
	canvas := image.NewRGBA(image.Rect(0, 0, 560, 280))
	paste(canvas, drawQR(t, u1, 240), 10, 20)
	paste(canvas, drawQR(t, u2, 240), 300, 20)

	got, err := DecodeAll(canvas)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	if !set[u1] || !set[u2] {
		t.Errorf("decoded %v; want both %q and %q", got, u1, u2)
	}
}

func TestDecodeAllSingleFallsBack(t *testing.T) {
	uri := "otpauth://totp/GitHub:solo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	pngBytes, err := qrencode.Encode(uri, qrencode.Medium, 256)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAllBytes(pngBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != uri {
		t.Errorf("got %v, want [%s]", got, uri)
	}
}

func TestDecodeAllRejectsNonImage(t *testing.T) {
	if _, err := DecodeAllBytes([]byte("junk")); err == nil {
		t.Error("expected error")
	}
}
