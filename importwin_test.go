package main

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/egoist/mygo/ui"

	"keytray/internal/screenshot"
)

func TestCapturePermissionGuide(t *testing.T) {
	for _, dark := range []bool{false, true} {
		t.Run(fmt.Sprintf("dark=%v", dark), func(t *testing.T) {
			is := &importState{
				app:     &app{state: unlockedState(t)},
				text:    "existing draft",
				busy:    true,
				err:     "old error",
				summary: "old result",
			}
			is.finishCapture(nil, fmt.Errorf("capture: %w", screenshot.ErrPermission))
			if is.busy || is.err != "" || is.summary != "" || !is.needsScreenPermission {
				t.Fatalf("permission failure should show guidance instead of an error: %+v", is)
			}
			tt := ui.NewTesterWith(is.view, 480, 440, ui.TesterOptions{Dark: dark})
			if !tt.HasText("开启屏幕录制权限") {
				t.Fatal("permission guide is missing")
			}
			if err := tt.Click("打开系统设置"); err != nil {
				t.Fatal(err)
			}
			wantURLs := []string{"x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"}
			if !reflect.DeepEqual(tt.OpenedURLs(), wantURLs) {
				t.Fatalf("opened %v, want %v", tt.OpenedURLs(), wantURLs)
			}
			if err := tt.Click("返回链接导入"); err != nil {
				t.Fatal(err)
			}
			if _, ok := tt.Find("otpauth 链接"); !ok || is.text != "existing draft" {
				t.Fatal("returning from guidance should preserve the URI draft")
			}
			is.needsScreenPermission = true
			is.finishCapture([]string{"new URI"}, nil)
			tt.Frame()
			if is.needsScreenPermission || is.text != "existing draft\nnew URI\n" ||
				is.summary != selectionSummary(1) {
				t.Fatalf("successful retry did not restore import: %+v", is)
			}
		})
	}
}

func TestCaptureOtherResults(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"cancel", screenshot.ErrCanceled, ""},
		{"decode failure", errors.New("no QR codes found"), "识别失败:no QR codes found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := &importState{text: "draft", busy: true}
			is.finishCapture(nil, tc.err)
			if is.busy || is.needsScreenPermission || is.err != tc.want || is.text != "draft" {
				t.Fatalf("unexpected capture result: %+v", is)
			}
		})
	}
}
