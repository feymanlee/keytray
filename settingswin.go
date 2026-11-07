package main

import (
	"strconv"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

// settingsState drives the settings window. Toggles apply immediately and
// persist to settings.json.
type settingsState struct {
	app *app

	lockMinutes string // Select works on strings; parsed into settings
	httpPort    string

	// setAutostart is injectable for tests.
	setAutostart func(bool) error
	err          string
	win          *mygo.Window
}

func newSettingsWindow(a *app) {
	ss := &settingsState{app: a}
	ss.lockMinutes = strconv.Itoa(a.state.settings.AutoLockMinutes)
	ss.httpPort = strconv.Itoa(a.state.settings.HTTPPort)
	ss.setAutostart = func(on bool) error { return mygo.App.SetOpenAtLogin(on) }
	ss.win = mygo.NewWindow(mygo.WindowOptions{
		Title:   "设置",
		Width:   420,
		Height:  520,
		Content: ui.View(ss.view),
	})
}

func (ss *settingsState) view(c *ui.Context) {
	s := ss.app.state
	// The window title bar closes the window; errors surface in a footer.
	ui.Column(c).Fill().Children(func() {
		ui.Scroll(c).Grow(1).Padding(20).Gap(14).Children(func() {
			ss.sections(c, s)
		})
		if ss.err != "" {
			ui.Divider(c)
			ui.Row(c).Padding(12, 20).Children(func() {
				ui.Text(c, ss.err).FontSize(12).TextColor(warnColor).Grow(1)
			})
		}
	})
}

func (ss *settingsState) sections(c *ui.Context, s *panelState) {
	st := &s.settings
	t := c.Theme()

	ui.Text(c, "设置").FontSize(16).Bold()

	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Grow(1).Children(func() {
			ui.Text(c, "开机自启")
			ui.Text(c, "登录后自动在菜单栏运行").FontSize(11).TextColor(t.TextMuted)
		})
		if ui.Switch(c.Key("autostart"), &st.Autostart).Label("开机自启 开关").Changed() {
			if err := ss.setAutostart(st.Autostart); err != nil {
				ss.err = "开机自启设置失败:" + err.Error()
			}
			s.saveSettings()
		}
	})

	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Grow(1).Children(func() {
			ui.Text(c, "复制后清空剪贴板")
			ui.Text(c, "复制验证码 30 秒后自动清除").FontSize(11).TextColor(t.TextMuted)
		})
		if ui.Switch(c.Key("clearclip"), &st.ClearClipboard).Label("清空剪贴板 开关").Changed() {
			s.saveSettings()
		}
	})

	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Grow(1).Children(func() {
			ui.Text(c, "自动锁定")
			ui.Text(c, "无操作一段时间后锁定金库(默认关闭)").FontSize(11).TextColor(t.TextMuted)
		})
		if ui.Switch(c.Key("autolock"), &st.AutoLock).Label("自动锁定 开关").Changed() {
			s.touch() // a fresh change resets the idle timer
			s.saveSettings()
		}
	})
	if st.AutoLock {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "锁定时长").Grow(1)
			if ui.Select(c.Key("lockmin"), &ss.lockMinutes, lockMinutesPresets).
				Label("锁定时长 选择").Width(120).Changed() {
				if n, err := strconv.Atoi(ss.lockMinutes); err == nil {
					st.AutoLockMinutes = n
					s.saveSettings()
				}
			}
		})
	}

	ui.Divider(c)
	ui.Text(c, "本地加密").FontSize(12).TextColor(t.TextMuted)
	if s.encrypted {
		ui.Text(c, "已开启 — 数据加密存储,启动后需主密码解锁").
			FontSize(11).TextColor(t.TextMuted)
	} else {
		ui.Text(c, "未开启 — 账号密钥以明文存储于本机").
			FontSize(11).TextColor(warnColor)
	}
	ui.Row(c).Gap(8).Children(func() {
		if s.encrypted {
			ui.Button(c.Key("crypt-off"), "关闭加密…").Label("关闭加密").
				OnClick(func() { ss.app.openCrypt(cryptDisable) })
			ui.Button(c.Key("crypt-change"), "修改主密码…").Label("修改主密码").
				OnClick(func() { ss.app.openCrypt(cryptChange) })
		} else {
			ui.Button(c.Key("crypt-on"), "开启本地加密…").Label("开启本地加密").
				OnClick(func() { ss.app.openCrypt(cryptEnable) })
		}
	})
	if s.encrypted {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Column(c).Grow(1).Children(func() {
				ui.Text(c, "启动时自动解锁")
				ui.Text(c, "主密码存入系统钥匙串,启动免输(TouchID 场景默认关)").FontSize(11).TextColor(t.TextMuted)
			})
			if ui.Switch(c.Key("autounlock"), &st.AutoUnlock).Label("自动解锁 开关").Changed() {
				if err := s.SetAutoUnlock(st.AutoUnlock); err != nil {
					ss.err = err.Error()
					st.AutoUnlock = !st.AutoUnlock // revert on failure
				}
			}
		})
	}

	ui.Divider(c)
	ui.Text(c, "显示").FontSize(12).TextColor(t.TextMuted)
	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Grow(1).Children(func() {
			ui.Text(c, "按服务分组")
			ui.Text(c, "同服务账号聚合显示;关闭后恢复拖拽排序").FontSize(11).TextColor(t.TextMuted)
		})
		if ui.Switch(c.Key("groups"), &st.ShowGroups).Label("按服务分组 开关").Changed() {
			s.saveSettings()
		}
	})
	ui.Divider(c)
	ui.Text(c, "HTTP 接口").FontSize(12).TextColor(t.TextMuted)
	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Grow(1).Children(func() {
			ui.Text(c, "本地取码接口")
			ui.Text(c, "仅监听 127.0.0.1;金库锁定时不提供验证码(默认关)").FontSize(11).TextColor(t.TextMuted)
		})
		if ui.Switch(c.Key("http"), &st.HTTPEnabled).Label("HTTP 接口 开关").Changed() {
			if st.HTTPEnabled && st.HTTPToken == "" {
				st.HTTPToken = generateToken()
			}
			s.saveSettings()
			ss.app.reapplyHTTP()
		}
	})
	if st.HTTPEnabled {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "端口").Grow(1)
			if ui.Select(c.Key("httpport"), &ss.httpPort, httpPortPresets).
				Label("HTTP 端口 选择").Width(120).Changed() {
				if n, err := strconv.Atoi(ss.httpPort); err == nil && n != st.HTTPPort {
					st.HTTPPort = n
					s.saveSettings()
					ss.app.reapplyHTTP()
				}
			}
		})
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "令牌").Grow(1).SingleLine().FontSize(11).TextColor(t.TextMuted)
			ui.Button(c.Key("token-copy"), "复制链接").Label("复制链接").
				OnClick(func() { mygo.Clipboard.WriteText(httpURL(st.HTTPPort, st.HTTPToken)) })
			ui.Button(c.Key("token-reset"), "重置令牌").Label("重置令牌").
				OnClick(func() {
					st.HTTPToken = generateToken()
					s.saveSettings()
				})
		})
		ui.Text(c, httpURL(st.HTTPPort, st.HTTPToken)).FontSize(10).TextColor(t.TextMuted).SingleLine()
	}
	ui.Divider(c)
	ui.Text(c, "全局快捷键").FontSize(12).TextColor(t.TextMuted)
	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "唤起面板").Grow(1)
		if ui.Select(c.Key("summon"), &st.SummonShortcut, summonPresets).
			Label("唤起面板快捷键 选择").Width(180).Changed() {
			ss.applyShortcuts()
		}
	})
	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "截屏导入").Grow(1)
		if ui.Select(c.Key("capture"), &st.CaptureShortcut, capturePresets).
			Label("截屏导入快捷键 选择").Width(180).Changed() {
			ss.applyShortcuts()
		}
	})
	ui.Text(c, "若首选快捷键被其他应用占用,自动改用备选").FontSize(11).TextColor(t.TextMuted)
}

func (ss *settingsState) applyShortcuts() {
	if err := ss.app.reapplyShortcuts(); err != nil {
		ss.err = err.Error()
		return
	}
	ss.err = ""
	ss.app.state.saveSettings()
}
