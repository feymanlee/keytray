package main

import (
	"strconv"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"keytray/internal/otp"
)

var (
	formTypes  = []otp.Type{otp.TOTP, otp.HOTP}
	formAlgs   = []string{"SHA1", "SHA256", "SHA512"}
	formDigits = []int{6, 8}
)

// formState drives the add/edit account window. A zero orig (Type == "")
// means a new account.
type formState struct {
	app  *app
	orig otp.Account // the account being edited, if any

	typeIdx  int // index into formTypes
	issuer   string
	name     string
	secret   string // base32, as typed
	algIdx   int    // index into formAlgs
	digitIdx int    // index into formDigits
	period   string // TOTP, seconds
	counter  string // HOTP
	err      string

	win *mygo.Window
}

func newFormWindow(a *app, acc otp.Account) {
	fs := &formState{app: a}
	if acc.Type != "" {
		fs.prefill(acc)
	} else {
		fs.period = strconv.Itoa(otp.DefaultPeriod)
	}
	title := "添加账号"
	if fs.editing() {
		title = "编辑账号"
	}
	fs.win = mygo.NewWindow(mygo.WindowOptions{
		Title:   title,
		Width:   400,
		Height:  520,
		Content: ui.View(fs.view),
	})
	fs.win.OnClosed(func() { a.onChildClosed("form") })
}

// prefill fills the form from an existing account for editing.
func (fs *formState) prefill(acc otp.Account) {
	fs.orig = acc
	for i, t := range formTypes {
		if t == acc.Type {
			fs.typeIdx = i
		}
	}
	for i, alg := range formAlgs {
		if alg == acc.Algorithm {
			fs.algIdx = i
		}
	}
	for i, d := range formDigits {
		if d == acc.Digits {
			fs.digitIdx = i
		}
	}
	fs.issuer = acc.Issuer
	fs.name = acc.Name
	fs.secret = otp.EncodeSecret(acc.Secret)
	fs.period = strconv.FormatUint(uint64(acc.Period), 10)
	fs.counter = strconv.FormatUint(acc.Counter, 10)
}

func (fs *formState) editing() bool { return fs.orig.Type != "" }

func (fs *formState) view(c *ui.Context) {
	s := fs
	t := c.Theme()
	// Fields scroll when the window is short; the action row stays visible.
	ui.Column(c).Fill().Children(func() {
		ui.Scroll(c).Grow(1).Padding(20).Gap(10).Children(func() {
			if s.editing() {
				ui.Text(c, "编辑账号").FontSize(16).Bold()
			} else {
				ui.Text(c, "添加账号").FontSize(16).Bold()
			}

			ui.Text(c, "类型").FontSize(12).TextColor(t.TextMuted)
			ui.Segmented(c.Key("type"), &s.typeIdx, "TOTP", "HOTP")
			formField(c, "服务名", &s.issuer, "GitHub(可选)")
			formField(c, "账号名", &s.name, "user@example.com")
			formField(c, "密钥(Base32)", &s.secret, "JBSWY3DPEHPK3PXP")
			ui.Text(c, "算法").FontSize(12).TextColor(t.TextMuted)
			ui.Segmented(c.Key("alg"), &s.algIdx, formAlgs...)
			ui.Text(c, "位数").FontSize(12).TextColor(t.TextMuted)
			ui.Segmented(c.Key("digits"), &s.digitIdx, "6 位", "8 位")
			if formTypes[s.typeIdx] == otp.TOTP {
				formField(c, "周期(秒)", &s.period, "30")
			} else {
				formField(c, "计数器", &s.counter, "0")
			}

			if s.err != "" {
				ui.Text(c, s.err).FontSize(12).TextColor(warnColor)
			}
		})
		ui.Divider(c)
		ui.Row(c).Padding(12, 20).Gap(8).Children(func() {
			ui.Spacer(c)
			ui.Button(c.Key("cancel"), "取消").Label("取消").Padding(3, 10).FontSize(13).OnClick(func() {
				if s.win != nil {
					s.win.Close()
				}
			})
			ui.PrimaryButton(c.Key("save"), "保存").Label("保存").Padding(3, 10).FontSize(13).OnClick(func() { s.submit() })
		})
	})
}

// formField shows a labeled input. The input's accessible label differs
// from the visible text so UI tests can target the input unambiguously.
func formField(c *ui.Context, label string, value *string, placeholder string) {
	ui.Text(c, label).FontSize(12).TextColor(c.Theme().TextMuted)
	ui.TextInput(c.Key(label), value).Placeholder(placeholder).Label(label + " 输入")
}

// submit validates the fields and writes the account to the vault.
func (fs *formState) submit() {
	s := fs
	s.err = ""
	secret, err := otp.DecodeSecret(strings.TrimSpace(s.secret))
	if err != nil {
		s.err = "密钥不是有效的 Base32"
		return
	}
	name := strings.TrimSpace(s.name)
	if name == "" {
		s.err = "账号名不能为空"
		return
	}
	acc := otp.Account{
		Type:      formTypes[s.typeIdx],
		Issuer:    strings.TrimSpace(s.issuer),
		Name:      name,
		Secret:    secret,
		Algorithm: formAlgs[s.algIdx],
		Digits:    formDigits[s.digitIdx],
	}
	if acc.Type == otp.TOTP {
		p, err := strconv.Atoi(strings.TrimSpace(s.period))
		if err != nil || p <= 0 {
			s.err = "周期需为正整数秒"
			return
		}
		acc.Period = uint32(p)
	} else {
		ct, err := strconv.ParseUint(strings.TrimSpace(s.counter), 10, 64)
		if err != nil {
			s.err = "计数器需为非负整数"
			return
		}
		acc.Counter = ct
	}
	acc.Normalize()
	if err := acc.Valid(); err != nil {
		s.err = err.Error()
		return
	}

	if s.editing() {
		err = s.app.state.UpdateAccount(s.orig, acc)
	} else {
		err = s.app.state.AddAccount(acc)
	}
	if err != nil {
		s.err = "保存失败:" + err.Error()
		return
	}
	if s.win != nil {
		s.win.Close()
	}
}
