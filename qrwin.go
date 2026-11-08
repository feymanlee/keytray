package main

import (
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	qrcode "github.com/skip2/go-qrcode"

	"keytray/internal/otp"
)

// qrState is the persistent "account QR" window: scan it with a phone to
// migrate one account, or copy the URI from the same screen.
type qrState struct {
	app    *app
	acc    otp.Account
	uri    string
	bmp    *ui.Bitmap
	err    string
	copied bool
	win    *mygo.Window
}

func newQRState(a *app) *qrState {
	qs := &qrState{app: a}
	qs.win = mygo.NewWindow(mygo.WindowOptions{
		Title:         "账号二维码",
		Width:         320,
		Height:        484,
		Hidden:        true,
		DisableResize: true,
		Content:       ui.View(qs.view),
	})
	qs.win.OnClose(func(e *mygo.CloseEvent) {
		e.PreventDefault()
		qs.win.Hide()
	})
	return qs
}

func (qs *qrState) view(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Padding(20).Gap(12).AlignItems(ui.Center).Children(func() {
		ui.Text(c, accountLabel(qs.acc)).FontSize(14).MaxWidth(280).TextAlign(ui.Center)

		switch {
		case qs.err != "":
			ui.Text(c, qs.err).FontSize(12).TextColor(warnColor)
		case qs.bmp != nil:
			ui.Image(c, qs.bmp).Size(240, 240).Radius(8).Background(ui.RGB(255, 255, 255))
		default:
			ui.Spacer(c)
			ui.Spacer(c)
		}

		// URI 是无断点的长串,自动排版会横向溢出:按固定宽度分块展示。
		ui.Text(c, chunkURI(qs.uri, 40)).FontSize(9).TextColor(t.TextMuted)
		ui.Row(c).Gap(8).Children(func() {
			ui.Button(c.Key("copy-uri"), "复制链接").Label("复制链接").Padding(3, 10).FontSize(13).
				OnClick(func() {
					mygo.Clipboard.WriteText(qs.uri)
					qs.copied = true
					qs.win.Update(func() {})
					time.AfterFunc(2*time.Second, func() {
						qs.win.Update(func() { qs.copied = false })
					})
				})
			ui.Button(c.Key("close"), "关闭").Label("关闭").Padding(3, 10).FontSize(13).
				OnClick(func() { qs.win.Hide() })
		})
		// 固定高度的提示槽:出现/消失都不推挤按钮。
		ui.Row(c).Height(18).AlignItems(ui.Center).Children(func() {
			if qs.copied {
				ui.Text(c, "已复制 ✓").FontSize(12).TextColor(t.Accent)
			}
		})
	})
}

// showQR renders the account's otpauth URI as a QR code and shows it.
// Called on the main thread (context menu callback).
func (a *app) showQR(acc otp.Account) {
	if !a.windows {
		a.lastAction = "qr"
		return
	}
	qs := a.qrUI
	qs.acc = acc
	qs.uri, _ = acc.URI()
	qs.err, qs.bmp = "", nil

	png, err := qrcode.Encode(qs.uri, qrcode.Medium, 480)
	if err == nil {
		qs.bmp, err = ui.DecodeBitmap(png)
	}
	if err != nil {
		qs.err = "二维码生成失败:" + err.Error()
	}
	qs.win.Update(func() {})
	qs.win.Show()
}

// chunkURI breaks a URI into fixed-width chunks (one per line) so it
// wraps predictably inside the window. Display only; the clipboard and
// QR payload always carry the original URI.
func chunkURI(s string, width int) string {
	if width <= 0 || len(s) <= width {
		return s
	}
	var b []byte
	for i := 0; i < len(s); i += width {
		if i > 0 {
			b = append(b, '\n')
		}
		end := i + width
		if end > len(s) {
			end = len(s)
		}
		b = append(b, s[i:end]...)
	}
	return string(b)
}
