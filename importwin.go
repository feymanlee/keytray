package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"keytray/internal/qrcode"
	"keytray/internal/screenshot"
)

// importState drives the import window: a textarea of otpauth:// URIs,
// which the screen-capture flow appends to for review before importing,
// plus one-shot import of an encrypted backup file.
type importState struct {
	app     *app
	text    string
	summary string
	err     string
	busy    bool // a capture is running

	backupPw string

	// pickOpen is injectable for tests; default is the system open dialog.
	pickOpen func(opts mygo.OpenDialogOptions) ([]string, error)

	win *mygo.Window
	ta  ui.Handle
}

// newImportState creates the hidden, reusable import window.
func newImportState(a *app) *importState {
	is := &importState{app: a}
	is.pickOpen = func(opts mygo.OpenDialogOptions) ([]string, error) {
		return mygo.Dialog.Open(opts)
	}
	is.win = mygo.NewWindow(mygo.WindowOptions{
		Title:   "导入账号",
		Width:   480,
		Height:  440,
		Hidden:  true,
		Content: ui.View(is.view),
	})
	// Hide instead of close: the capture goroutine keeps a handle to it.
	is.win.OnClose(func(e *mygo.CloseEvent) {
		e.PreventDefault()
		is.win.Hide()
	})
	return is
}

func (is *importState) view(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Padding(16).Gap(10).Children(func() {
		ui.Text(c, "导入账号").FontSize(16).Bold()
		ui.Text(c, "粘贴 otpauth:// 链接(每行一条),或截取屏幕上的二维码。").
			FontSize(12).TextColor(t.TextMuted)
		ui.TextArea(c.Key("uris"), &is.text).Bind(&is.ta).Grow(1).Label("otpauth 链接")

		ui.Divider(c)
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "加密备份").FontSize(12).TextColor(t.TextMuted)
			ui.TextInput(c.Key("backup-pw"), &is.backupPw).Password().Grow(1).
				Placeholder("备份密码").Label("备份密码 输入")
			ui.Button(c.Key("backup-file"), "选择备份文件…").Label("选择备份文件").
				OnClick(func() { is.importBackup() })
		})

		if is.err != "" {
			ui.Text(c, is.err).FontSize(12).TextColor(warnColor)
		}
		if is.summary != "" {
			ui.Text(c, is.summary).FontSize(12).TextColor(t.Accent)
		}

		ui.Row(c).Gap(8).Children(func() {
			ui.Button(c.Key("capture"), "截取屏幕二维码").Label("截取屏幕二维码").
				Disabled(is.busy).OnClick(func() { is.app.startCapture(is) })
			ui.Spacer(c)
			ui.Button(c.Key("close"), "关闭").Label("关闭").OnClick(func() { is.win.Hide() })
			ui.PrimaryButton(c.Key("import"), "导入").Label("导入").OnClick(func() { is.run() })
		})
	})
}

// run imports the textarea's URIs and reports the outcome inline.
func (is *importState) run() {
	is.err, is.summary = "", ""
	added, skipped, bad, err := is.app.state.ImportURIs(is.text)
	if err != nil {
		is.err = "保存失败:" + err.Error()
		return
	}
	is.summary = fmt.Sprintf("已添加 %d 条,跳过重复 %d 条,无法识别 %d 条", added, skipped, bad)
	if added > 0 {
		is.text = ""
	}
	// The panel may be open behind this window; refresh its rows.
	if p := is.app.panel; p != nil {
		p.Update(func() {})
	}
}

// importBackup decrypts a backup file with the backup password and merges
// its accounts, skipping duplicates, through the same path as URI import.
func (is *importState) importBackup() {
	is.err, is.summary = "", ""
	paths, err := is.pickOpen(mygo.OpenDialogOptions{
		Title:   "选择备份文件",
		Message: "导入此前导出的加密备份",
		Filters: []mygo.FileFilter{{Name: "keytray 备份", Extensions: []string{"kt"}}},
	})
	if err != nil {
		is.err = "选择文件失败:" + err.Error()
		return
	}
	if len(paths) == 0 {
		return // canceled
	}
	accounts, err := readBackupFile(paths[0], is.backupPw)
	if err != nil {
		is.err = err.Error()
		return
	}
	var lines []string
	for _, a := range accounts {
		if uri, err := a.URI(); err == nil {
			lines = append(lines, uri)
		}
	}
	added, skipped, _, err := is.app.state.ImportURIs(strings.Join(lines, "\n"))
	if err != nil {
		is.err = "保存失败:" + err.Error()
		return
	}
	is.summary = fmt.Sprintf("备份导入:已添加 %d 条,跳过重复 %d 条", added, skipped)
	if p := is.app.panel; p != nil {
		p.Update(func() {})
	}
}

// startCapture closes the flyout (it would cover the screen), runs the
// interactive region capture on a goroutine, decodes the QR and appends
// the URI to the textarea for review. Only the first QR in the selection
// is decoded in v1.
func (a *app) startCapture(is *importState) {
	if is.busy {
		return
	}
	if a.panel != nil {
		a.panel.Close()
	}
	is.busy = true
	is.win.Show()

	if runtime.GOOS == "windows" {
		// Windows v1.1 MVP: no interactive region selection yet — capture
		// the whole virtual screen and decode every QR on it. (The macOS
		// path uses the system's region selector below.)
		go func() {
			pngBytes, _, _, err := screenshot.CaptureScreen()
			var uris []string
			if err == nil {
				uris, err = qrcode.DecodeAllBytes(pngBytes)
			}
			is.win.Update(func() {
				is.busy = false
				switch {
				case err != nil:
					is.err = "识别失败:" + err.Error()
				default:
					is.err = ""
					if is.text != "" && !strings.HasSuffix(is.text, "\n") {
						is.text += "\n"
					}
					is.text += strings.Join(uris, "\n") + "\n"
					is.summary = selectionSummary(len(uris))
				}
				is.win.Show()
			})
		}()
		return
	}

	go func() {
		var uris []string
		png, err := screenshot.CaptureRegion()
		if err == nil {
			// Decode every QR in the selection; GA exports and batch
			// migration codes are the common multi-code case.
			uris, err = qrcode.DecodeAllBytes(png)
		}
		is.win.Update(func() {
			is.busy = false
			switch {
			case errors.Is(err, screenshot.ErrCanceled):
				// User dismissed the selection; nothing to report.
			case err != nil:
				is.err = "识别失败:" + err.Error()
			default:
				is.err = ""
				if is.text != "" && !strings.HasSuffix(is.text, "\n") {
					is.text += "\n"
				}
				is.text += strings.Join(uris, "\n") + "\n"
				if len(uris) == 1 {
					is.summary = "已识别 1 个二维码,确认后点「导入」"
				} else {
					is.summary = fmt.Sprintf("已识别 %d 个二维码,确认后点「导入」", len(uris))
				}
			}
			is.win.Show()
		})
	}()
}

// appendURIs appends URIs to the review textarea, one per line.
func appendURIs(is *importState, uris []string) {
	for _, u := range uris {
		if is.text != "" && !strings.HasSuffix(is.text, "\n") {
			is.text += "\n"
		}
		is.text += u + "\n"
	}
}

// selectionSummary describes how many codes a capture produced.
func selectionSummary(n int) string {
	if n == 1 {
		return "已识别 1 个二维码,确认后点「导入」"
	}
	return fmt.Sprintf("已识别 %d 个二维码,确认后点「导入」", n)
}
