package main

import (
	"errors"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

// cryptMode selects which master-password operation the window performs.
type cryptMode int

const (
	cryptEnable  cryptMode = iota // set a master password, encrypt the vault
	cryptDisable                  // verify the master password, go plaintext
	cryptChange                   // old password verified, new one twice
)

type cryptState struct {
	app    *app
	mode   cryptMode
	pw     string // enable: new password; disable: current; change: old
	pw2    string // enable/change: repeat
	pw3    string // change: repeat of the new password
	err    string
	notice string
	win    *mygo.Window
}

func newCryptWindow(a *app, mode cryptMode) {
	cs := &cryptState{app: a, mode: mode}
	title := "开启本地加密"
	if mode == cryptDisable {
		title = "关闭本地加密"
	} else if mode == cryptChange {
		title = "修改主密码"
	}
	cs.win = mygo.NewWindow(mygo.WindowOptions{
		Title:   title,
		Width:   420,
		Height:  400,
		Content: ui.View(cs.view),
	})
}

func (cs *cryptState) view(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Padding(20).Gap(10).Children(func() {
		switch cs.mode {
		case cryptEnable:
			ui.Text(c, "开启本地加密").FontSize(16).Bold()
			ui.Text(c, "设置主密码后,账号数据将以 AES-256 加密存储,每次启动需解锁。").
				FontSize(12).TextColor(t.TextMuted)
			formField(c, "主密码", &cs.pw, "至少 8 位")
			if ui.TextInput(c.Key("pw2"), &cs.pw2).Password().
				Placeholder("再输入一次").Label("确认主密码 输入").Submitted() {
				cs.submit()
			}
			if h := passwordHint(cs.pw, cs.pw2); h != "" {
				ui.Text(c, h).FontSize(12).TextColor(t.TextMuted)
			}
			ui.Text(c, "⚠️ 密码丢失无法找回,请定期导出加密备份").
				FontSize(11).TextColor(t.TextMuted)
		case cryptDisable:
			ui.Text(c, "关闭本地加密").FontSize(16).Bold()
			ui.Text(c, "⚠️ 关闭后账号密钥将以明文存储于本机,任何能读取该文件的程序都能看到。").
				FontSize(12).TextColor(warnColor)
			formField(c, "主密码", &cs.pw, "输入主密码确认")
		default:
			ui.Text(c, "修改主密码").FontSize(16).Bold()
			formField(c, "当前主密码", &cs.pw, "输入当前主密码")
			formField(c, "新主密码", &cs.pw2, "至少 8 位")
			if ui.TextInput(c.Key("pw3"), &cs.pw3).Password().
				Placeholder("再输入一次").Label("确认新主密码 输入").Submitted() {
				cs.submit()
			}
			if h := passwordHint(cs.pw2, cs.pw3); h != "" {
				ui.Text(c, h).FontSize(12).TextColor(t.TextMuted)
			}
		}

		if cs.err != "" {
			ui.Text(c, cs.err).FontSize(12).TextColor(warnColor)
		}
		ui.Row(c).Gap(8).Children(func() {
			ui.PrimaryButton(c.Key("apply"), "确认").Label("确认").OnClick(func() { cs.submit() })
			ui.Button(c.Key("close"), "取消").Label("取消").OnClick(func() { cs.win.Close() })
		})
	})
}

func (cs *cryptState) submit() {
	s := cs.app.state
	cs.err = ""
	var err error
	switch cs.mode {
	case cryptEnable:
		err = s.EnableEncryption(cs.pw, cs.pw2)
	case cryptDisable:
		err = s.DisableEncryption(cs.pw)
	default:
		if cs.pw2 != cs.pw3 {
			err = errors.New("两次输入的新主密码不一致")
		} else {
			err = s.ChangeMasterPassword(cs.pw, cs.pw2)
		}
	}
	if err != nil {
		cs.err = err.Error()
		return
	}
	if cs.win != nil {
		cs.win.Close()
	}
}
