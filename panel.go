package main

import (
	"errors"
	"fmt"
	"log"
	"reflect"
	"runtime"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"keytray/internal/otp"
)

const (
	panelWidth, panelHeight = 360, 480
)

// warnColor marks codes about to expire (<5s).
var warnColor = ui.RGB(214, 69, 65)

// digitKeys are the ⇧⌘0..⇧⌘9 quick-copy shortcuts for rows 0..9.
var digitKeys = [10]ui.Key{
	ui.Key0, ui.Key1, ui.Key2, ui.Key3, ui.Key4,
	ui.Key5, ui.Key6, ui.Key7, ui.Key8, ui.Key9,
}

// app holds the tray, the open flyout and the panel state. All of it is
// read and changed on the main thread; the tick goroutine only reaches the
// state through Window.Update.
type app struct {
	state *panelState

	tray     *mygo.Tray
	panel    *mygo.Window // the open flyout, or nil
	importUI *importState // the hidden, reusable import window

	search ui.Handle // the search input
	pw     ui.Handle // the password input of whichever view is shown
	list   ui.ListState

	// windows is false under the ui.Tester, where real windows cannot be
	// created; open* record into lastAction instead.
	windows    bool
	lastAction string

	// the global shortcuts actually registered (may differ from settings
	// when the preferred one is taken).
	shortcutSummon  string
	shortcutCapture string

	httpSrv *httpServer // local codes API, nil when disabled
}

func (a *app) view(c *ui.Context) {
	// The panel is a plain flyout (no system popover): it draws its own
	// background with the app's own, smaller corner radius.
	c.Root().Background(c.Theme().Surface).Radius(8)
	switch {
	case a.state.encrypted && !a.state.unlocked:
		a.lockView(c)
	default:
		a.mainView(c)
	}
}

func (a *app) lockView(c *ui.Context) {
	s := a.state
	t := c.Theme()
	c.OnShortcut(ui.Cmd, ui.KeyQ, mygo.App.Quit)
	ui.Column(c).Fill().Padding(24).Gap(12).Children(func() {
		ui.Text(c, "🔒 Keytray").FontSize(18).Bold()
		ui.Text(c, "输入主密码解锁").FontSize(12).TextColor(t.TextMuted)
		if ui.TextInput(c.Key("pw"), &s.unlockPw).Bind(&a.pw).
			Password().Placeholder("主密码").Label("主密码").Submitted() {
			a.tryUnlock(c)
		}
		if s.err != "" {
			ui.Text(c, s.err).FontSize(12).TextColor(warnColor)
		}
		ui.PrimaryButton(c.Key("unlock"), "解锁").Label("解锁").
			OnClick(func() { a.tryUnlock(c) })
	})
}

func (a *app) tryUnlock(c *ui.Context) {
	if err := a.state.unlock(); err != nil {
		a.state.err = unlockErrorText(err)
		return
	}
	a.state.err = ""
	a.search.Focus(c)
}

func (a *app) mainView(c *ui.Context) {
	s := a.state
	t := c.Theme()

	if s.query != "" && c.Shortcut(0, ui.KeyEscape) {
		s.query = ""
		s.filter()
	}
	c.OnShortcut(ui.Cmd, ui.KeyQ, mygo.App.Quit)
	for _, key := range digitKeys {
		ord := digitOrdinal(key)
		c.OnShortcut(ui.Shift|ui.Cmd, key, func() { s.copyOrd(ord) })
	}
	// A 添加 / I 导入 / S 截图 / D 管理, as in the reference app's menu.
	c.OnShortcut(0, ui.KeyA, func() { a.openForm(otp.Account{}) })
	c.OnShortcut(0, ui.KeyI, func() { a.openImport() })
	c.OnShortcut(0, ui.KeyS, func() { a.openImportWithCapture() })
	c.OnShortcut(0, ui.KeyD, func() { s.toggleManage() })

	ui.Column(c).Fill().Children(func() {
		ui.Row(c).Padding(7, 12).Gap(8).AlignItems(ui.Center).Children(func() {
			if ui.TextInput(c.Key("search"), &s.query).Bind(&a.search).Grow(1).
				FontSize(13).Placeholder("搜索账号").Label("搜索账号").Changed() {
				s.filter()
			}
		})
		insetDivider(c)

		a.list.Key = func(i int) any { return fmt.Sprintf("%d/%s", i, rowLabel(s.rows[i])) }
		a.list.Label = func(i int) string { return rowLabel(s.rows[i]) }
		// Sticky group headers in the grouped view.
		a.list.Header = func(i int) bool { return s.rows[i].header }
		// Drag reorder only when rows map 1:1 to vault order: flat full
		// view (grouping off). Search, manage mode and grouped views
		// disable it.
		flat := !s.manageMode && s.query == "" && !s.settings.ShowGroups
		if flat {
			a.list.Reorder = func(rows []int, to int) {
				reordered := applyReorder(s.accounts, rows, to)
				if reflect.DeepEqual(reordered, s.accounts) {
					return
				}
				s.accounts = reordered
				s.reportErr(s.save())
				s.filter()
			}
		} else {
			a.list.Reorder = nil
		}
		ui.List(c, &a.list, len(s.rows), func(i int) { a.row(c, i) }).
			Grow(1).Padding(3, 8).Children(func() {
			if len(s.filtered) == 0 {
				msg := "没有匹配的账号"
				if len(s.accounts) == 0 {
					msg = "暂无账号"
				}
				ui.Text(c, msg).FontSize(13).TextColor(t.TextMuted).Padding(10)
			}
		})

		ui.Row(c).Padding(3, 12).Gap(8).AlignItems(ui.Center).Children(func() {
			if rem, ok := centralCountdown(s.filtered, s.now); ok {
				ui.Textf(c, "过期时间:%d 秒", rem).FontSize(11).
					TextColor(t.TextMuted).Grow(1)
			} else {
				ui.Spacer(c)
			}
			if s.copyHintVisible(s.now) {
				ui.Text(c, "已复制 "+s.copiedLabel).FontSize(11).TextColor(t.Accent)
			} else {
				ui.Text(c, "点击复制 · esc 关闭").FontSize(10).TextColor(t.TextMuted)
			}
		})
		insetDivider(c)

		// 认证管理 menu section.
		ui.Row(c).Padding(4, 10).Gap(6).AlignItems(ui.Center).Children(func() {
			if s.manageMode {
				ui.PrimaryButton(c.Key("manage-done"), "完成管理").Label("完成管理").
					OnClick(func() { s.toggleManage() })
			} else {
				ui.Button(c.Key("add"), "添加").Label("添加").
					OnClick(func() { a.openForm(otp.Account{}) })
				ui.Button(c.Key("import"), "导入").Label("导入").
					OnClick(func() { a.openImport() })
				ui.Button(c.Key("export"), "导出").Label("导出").
					OnClick(func() { a.openExport() })
				ui.Button(c.Key("manage"), "管理").Label("管理").
					OnClick(func() { s.toggleManage() })
				ui.Button(c.Key("settings"), "设置").Label("设置").
					OnClick(func() { a.openSettings() })
				if s.encrypted {
					ui.Button(c.Key("lock"), "锁定").Label("锁定").OnClick(func() {
						a.state.lock()
					})
				}
			}
			ui.Spacer(c)
			if s.err != "" {
				ui.Text(c, s.err).FontSize(11).TextColor(warnColor)
			}
		})
		insetDivider(c)

	})
	_ = t
}

func (a *app) row(c *ui.Context, i int) {
	s := a.state
	t := c.Theme()
	r := s.rows[i]
	if r.header {
		ui.Row(c.Key(fmt.Sprintf("hdr-%d", i))).
			Padding(8, 10, 3).AlignItems(ui.Center).Children(func() {
			ui.Text(c, r.text).FontSize(11).TextColor(t.TextMuted)
		})
		return
	}
	acc := s.filtered[r.accIdx]

	if s.manageMode {
		a.manageRow(c, i, acc)
		return
	}

	code, err := acc.Code(s.now)
	if err != nil {
		code = "——————"
	}
	remaining := acc.SecondsRemaining(s.now)
	expiring := acc.Type == otp.TOTP && remaining <= 5

	codeColor := t.Text
	if expiring {
		codeColor = warnColor
	}

	// Hover paints our own rounded highlight over the framework's row
	// surface; there is no keyboard selection anymore — click (or ⇧⌘N)
	// copies. Height pins the row to the reference menu's ~28px height.
	row := ui.Row(c.Key(fmt.Sprintf("row-%d", i))).
		Height(28).Padding(0, 10).Gap(8).AlignItems(ui.Center).Radius(6)
	hovered := row.Hovered()
	row.Background(hoverBG(t, hovered)).
		OnClick(func() { s.copy(r.accIdx) }).Children(func() {
		if svg := iconForIssuer(acc.Issuer); svg != nil {
			ui.Icon(c, svg).FontSize(15).TextColor(t.Text)
		} else {
			label := acc.Issuer
			if label == "" {
				label = acc.Name
			}
			ui.Avatar(c, label, nil).Size(18, 18)
		}
		ui.Text(c, accountLabel(acc)).Grow(1).SingleLine().FontSize(13)
		ui.Text(c, otp.FormatCode(code)).FontFeatures("tnum").FontSize(13).TextColor(codeColor)
		if acc.Type == otp.TOTP && acc.Period != otp.DefaultPeriod {
			ui.Textf(c, "%d 秒", remaining).FontSize(11).TextColor(t.TextMuted)
		}
		if r.ord >= 0 && r.ord < len(digitKeys) {
			ui.Textf(c, "⇧⌘%d", r.ord).FontSize(10).TextColor(t.TextMuted)
		}
	})
}

// hoverBG is the row background while hovered: SurfacePressed, one step
// deeper than the framework's hover gray, still theme-aware. Transparent
// otherwise.
func hoverBG(t *ui.Theme, hovered bool) ui.Color {
	if hovered {
		return t.SurfacePressed
	}
	return ui.Transparent
}

// insetDivider draws a hairline that stops short of the panel edges,
// like native menu separators.
func insetDivider(c *ui.Context) {
	ui.Divider(c).Padding(0, 12)
}

// manageRow shows edit/move/delete actions for one account. Mutations go
// through the state, which persists each change to the vault.
func (a *app) manageRow(c *ui.Context, i int, acc otp.Account) {
	t := c.Theme()
	ui.Row(c.Key(fmt.Sprintf("mrow-%d", i))).
		Padding(6, 10).Gap(6).AlignItems(ui.Center).Radius(8).Children(func() {
		ui.Text(c, accountLabel(acc)).Grow(1).SingleLine()
		ui.Text(c, string(acc.Type)).FontSize(10).TextColor(t.TextMuted)
		ui.Button(c.Key(fmt.Sprintf("edit-%d", i)), "✎").Label("编辑").
			OnClick(func() { a.openForm(acc) })
		ui.Button(c.Key(fmt.Sprintf("up-%d", i)), "↑").Label("上移").
			OnClick(func() { a.state.reportErr(a.state.MoveAccount(acc, -1)) })
		ui.Button(c.Key(fmt.Sprintf("down-%d", i)), "↓").Label("下移").
			OnClick(func() { a.state.reportErr(a.state.MoveAccount(acc, 1)) })
		ui.Button(c.Key(fmt.Sprintf("del-%d", i)), "🗑").Label("删除").
			OnClick(func() { a.state.reportErr(a.state.RemoveAccount(acc)) })
	})
}

// toggle opens the flyout next to the tray icon, or closes it.
func (a *app) toggle() {
	if a.panel != nil {
		a.panel.Close()
		return
	}
	a.state.now = time.Now()
	a.state.err = ""
	a.state.touch()
	a.state.hideAt = time.Time{} // a fresh open cancels any pending auto-hide
	a.panel = mygo.NewFlyout(mygo.FlyoutOptions{
		Tray:      a.tray,
		Placement: mygo.PlacementBottom,
		Gap:       4,
		Width:     panelWidth,
		Height:    panelHeight,
		Focusable: true,
		Shadow:    true, // on macOS the shadow follows our rounded content
		Content:   ui.View(a.view),
	})

	// Refresh codes and the countdown every second while the panel is open.
	done := make(chan struct{})
	go a.tickLoop(a.panel, done)
	a.panel.OnClosed(func() {
		a.panel = nil
		close(done)
		s := a.state // forget what was typed; keep the lock state itself
		s.query, s.unlockPw, s.err = "", "", ""
		s.filter()
	})

	if a.state.encrypted && !a.state.unlocked {
		a.pw.Focus()
	} else {
		a.search.Focus()
	}
}

func (a *app) tickLoop(p *mygo.Window, done chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// The open panel counts as activity for the auto-lock timer.
			p.Update(func() {
				now := time.Now()
				a.state.now = now
				a.state.lastActive = now
				if a.state.autoHideDue(now) && a.panel != nil {
					a.panel.Close()
				}
			})
		case <-done:
			return
		}
	}
}

// openForm opens the add/edit window; under the Tester it only records.
func (a *app) openForm(acc otp.Account) {
	if !a.windows {
		a.lastAction = "form:" + accountLabel(acc)
		return
	}
	newFormWindow(a, acc)
}

// openImport shows the import window; under the Tester it only records.
func (a *app) openImport() {
	if !a.windows {
		a.lastAction = "import"
		return
	}
	a.importUI.win.Show()
}

// openImportWithCapture shows the import window and starts a screen
// capture; under the Tester it only records.
func (a *app) openImportWithCapture() {
	if !a.windows {
		a.lastAction = "capture"
		return
	}
	a.startCapture(a.importUI)
}

// openExport opens the export window; under the Tester it only records.
func (a *app) openExport() {
	if !a.windows {
		a.lastAction = "export"
		return
	}
	newExportWindow(a)
}

// openSettings opens the settings window; under the Tester it only records.
func (a *app) openSettings() {
	if !a.windows {
		a.lastAction = "settings"
		return
	}
	newSettingsWindow(a)
}

// openCrypt opens the enable/disable/change-password window; under the
// Tester it only records.
func (a *app) openCrypt(mode cryptMode) {
	if !a.windows {
		a.lastAction = fmt.Sprintf("crypt:%d", mode)
		return
	}
	newCryptWindow(a, mode)
}

// registerShortcuts registers the summon and capture global shortcuts from
// settings (with fallbacks when taken) and remembers what was registered.
// It returns an error only when a shortcut cannot be registered at all.
func (a *app) registerShortcuts() error {
	for _, sc := range shortcutCandidates(a.state.settings.SummonShortcut,
		defaultSummonShortcut, fallbackSummonShortcut) {
		if err := mygo.GlobalShortcut.Register(sc, a.toggle); err == nil {
			a.shortcutSummon = sc
			break
		}
	}
	for _, sc := range shortcutCandidates(a.state.settings.CaptureShortcut,
		defaultCaptureShortcut, fallbackCaptureShortcut) {
		if err := mygo.GlobalShortcut.Register(sc, a.openImportWithCapture); err == nil {
			a.shortcutCapture = sc
			break
		}
	}
	if a.shortcutSummon == "" {
		return errors.New("唤起面板快捷键注册失败")
	}
	if a.shortcutCapture == "" {
		return errors.New("截屏导入快捷键注册失败")
	}
	return nil
}

// reapplyHTTP restarts the local codes server after a settings change;
// under the Tester it only records.
func (a *app) reapplyHTTP() {
	if !a.windows {
		a.lastAction = "http"
		return
	}
	a.ensureHTTP()
}

// reapplyShortcuts swaps the global shortcuts after a settings change.
func (a *app) reapplyShortcuts() error {
	if !a.windows {
		a.lastAction = "shortcuts"
		return nil
	}
	if a.shortcutSummon != "" {
		mygo.GlobalShortcut.Unregister(a.shortcutSummon)
	}
	if a.shortcutCapture != "" {
		mygo.GlobalShortcut.Unregister(a.shortcutCapture)
	}
	a.shortcutSummon, a.shortcutCapture = "", ""
	return a.registerShortcuts()
}

func shortcutCandidates(preferred string, fallbacks ...string) []string {
	var out []string
	if preferred != "" {
		out = append(out, preferred)
	}
	for _, f := range fallbacks {
		if f != preferred {
			out = append(out, f)
		}
	}
	return out
}

// autoLockLoop runs for the app's lifetime: every second it checks the
// idle timer on the main thread (through the always-alive import window)
// and locks the vault when due.
func (a *app) autoLockLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a.importUI.win.Update(func() {
			if a.state.autoLockDue(time.Now()) {
				a.state.lock()
			}
		})
	}
}

func (a *app) ready() {
	a.windows = true
	trayIcon := iconPNG
	template := false
	if runtime.GOOS == "darwin" {
		// macOS menu-bar icons are template images: AppKit tints the
		// black glyph correctly for light and dark menu bars.
		trayIcon = trayTemplatePNG
		template = true
	}
	var err error
	a.tray, err = mygo.NewTray(mygo.TrayOptions{
		Icon:           trayIcon,
		IconIsTemplate: template,
		ToolTip:        "Keytray",
	})
	if err != nil {
		panic("tray: " + err.Error())
	}
	menu := mygo.NewMenu([]*mygo.MenuItem{
		{Label: "打开 Keytray", Click: func(*mygo.MenuItem, *mygo.Window) { a.toggle() }},
		mygo.Separator(),
		{Role: mygo.RoleQuit},
	})
	if runtime.GOOS == "linux" {
		// AppIndicator only shows menus and tells nothing of clicks.
		a.tray.SetMenu(menu)
	} else {
		a.tray.OnClick(a.toggle)
		a.tray.OnRightClick(func() {
			if a.panel != nil {
				a.panel.Close()
			}
			a.tray.SetMenu(menu)
			defer a.tray.SetMenu(nil)
			a.tray.PopUpMenu()
		})
	}
	mygo.App.OnWillQuit(func(*mygo.QuitEvent) {
		a.stopHTTP()
		a.tray.Destroy()
	})

	a.importUI = newImportState(a)
	go a.autoLockLoop()
	a.ensureHTTP()

	if err := a.registerShortcuts(); err != nil {
		log.Printf("global shortcut: %v", err)
	}
	if a.state.settings.Autostart {
		// Dev builds without an app bundle may refuse; the setting stays
		// on and applies again from the packaged app.
		if err := mygo.App.SetOpenAtLogin(true); err != nil {
			log.Printf("open at login: %v", err)
		}
	}
}

// rowLabel is the list row's accessible label.
func rowLabel(r listRow) string {
	if r.header {
		return "分组 " + r.text
	}
	return "row"
}

// digitOrdinal maps a digit key to its account ordinal (0-9).
func digitOrdinal(k ui.Key) int {
	for i, d := range digitKeys {
		if d == k {
			return i
		}
	}
	return -1
}

// copyOrd copies the ord-th visible account (headers not counted).
func (s *panelState) copyOrd(ord int) {
	for _, r := range s.rows {
		if !r.header && r.ord == ord {
			s.copy(r.accIdx)
			return
		}
	}
}
