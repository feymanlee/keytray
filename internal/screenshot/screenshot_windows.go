//go:build windows

// Windows screen capture via GDI (no cgo): BitBlt of the whole virtual
// screen into a DIB, converted to PNG. The region selection itself is a
// mygo overlay window in the app (see selection_windows.go) — the frozen
// image is shown there and the user drags a rectangle over it.
package screenshot

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/png"
	"syscall"
	"unsafe"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	gdi32            = syscall.NewLazyDLL("gdi32.dll")
	procGetDC        = user32.NewProc("GetDC")
	procReleaseDC    = user32.NewProc("ReleaseDC")
	procMetrics      = user32.NewProc("GetSystemMetrics")
	procCompatDC     = gdi32.NewProc("CreateCompatibleDC")
	procCompatBmp    = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject = gdi32.NewProc("SelectObject")
	procDeleteObject = gdi32.NewProc("DeleteObject")
	procDeleteDC     = gdi32.NewProc("DeleteDC")
	procBitBlt       = gdi32.NewProc("BitBlt")
	procGetDIBits    = gdi32.NewProc("GetDIBits")
	procGdiFlush     = gdi32.NewProc("GdiFlush")
)

const (
	smXVirtual  = 76
	smYVirtual  = 77
	smCxVirtual = 78
	smCyVirtual = 79

	srccopy    = 0x00CC0020
	captureBlt = 0x40000000
)

// call invokes a lazy proc and returns its first result, panicking with
// the system error only when the call itself could not be made.
func call(p *syscall.LazyProc, args ...uintptr) uintptr {
	r1, _, _ := p.Call(args...)
	return r1
}

// CaptureScreen grabs the whole virtual screen and returns PNG bytes plus
// its pixel size.
func CaptureScreen() (pngBytes []byte, w, h int, err error) {
	w = int(call(procMetrics, smCxVirtual))
	h = int(call(procMetrics, smCyVirtual))
	vx := int(call(procMetrics, smXVirtual))
	vy := int(call(procMetrics, smYVirtual))
	if w <= 0 || h <= 0 {
		return nil, 0, 0, errors.New("screenshot: bad virtual screen metrics")
	}

	srcDC := uintptr(call(procGetDC, 0))
	if srcDC == 0 {
		return nil, 0, 0, errors.New("screenshot: GetDC failed")
	}
	defer procReleaseDC.Call(0, srcDC)

	memDC := uintptr(call(procCompatDC, srcDC))
	if memDC == 0 {
		return nil, 0, 0, errors.New("screenshot: CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(memDC)

	hbmp := call(procCompatBmp, srcDC, uintptr(w), uintptr(h))
	if hbmp == 0 {
		return nil, 0, 0, errors.New("screenshot: CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(hbmp)

	prev := call(procSelectObject, memDC, hbmp)
	defer procSelectObject.Call(memDC, prev)

	// SRCCOPY|CAPTUREBLT also pulls layered windows into the shot.
	ret := call(procBitBlt, memDC, 0, 0, uintptr(w), uintptr(h),
		srcDC, uintptr(vx), uintptr(vy), uintptr(srccopy|captureBlt))
	if ret == 0 {
		return nil, 0, 0, errors.New("screenshot: BitBlt failed")
	}
	procGdiFlush.Call()

	pixels, err := dibPixels(memDC, hbmp, w, h)
	if err != nil {
		return nil, 0, 0, err
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i, y := 0, 0; y < h; y++ {
		row := pixels[y*w*4 : (y+1)*w*4]
		// DIB is BGRA top-down; image.RGBA wants RGBA.
		for x := 0; x < w; x++ {
			o := x * 4
			d := img.Pix[i : i+4]
			d[0] = row[o+2]
			d[1] = row[o+1]
			d[2] = row[o]
			d[3] = 0xFF
			i += 4
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, 0, 0, fmt.Errorf("screenshot: encode: %w", err)
	}
	return buf.Bytes(), w, h, nil
}

// dibPixels reads the bitmap's 32bpp top-down pixels.
func dibPixels(memDC, hbmp uintptr, w, h int) ([]byte, error) {
	const headerLen = 40
	info := make([]byte, headerLen)
	putU32 := func(off int, v uint32) {
		info[off], info[off+1], info[off+2], info[off+3] =
			byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	}
	putU32(0, headerLen)      // biSize
	putU32(4, uint32(w))      // biWidth
	putU32(8, uint32(-h))     // biHeight negative = top-down
	putU32(12, 1)             // biPlanes
	putU32(16, 32)            // biBitCount
	putU32(20, 0)             // BI_RGB
	putU32(24, uint32(w*h*4)) // biSizeImage

	pixels := make([]byte, w*h*4)
	if call(procGetDIBits, memDC, hbmp, 0, uintptr(h),
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&info[0])), 0) == 0 { // DIB_RGB_COLORS
		return nil, errors.New("screenshot: GetDIBits failed")
	}
	return pixels, nil
}
