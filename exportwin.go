package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"keytray/internal/otp"
	"keytray/internal/vault"
)

// exportState drives the export window: an encrypted backup (the vault
// re-encrypted under a backup password) or a plaintext CSV guarded by the
// master password.
type exportState struct {
	app *app

	mode      int // 0 加密备份, 1 明文 CSV
	backupPw  string
	backupPw2 string
	confirmPw string // plaintext mode: master password confirmation
	err       string
	notice    string

	// pickSave is injectable for tests; default is the system save dialog.
	pickSave func(opts mygo.SaveDialogOptions) (string, error)
	win      *mygo.Window
}

func newExportWindow(a *app) {
	es := &exportState{app: a}
	es.pickSave = func(opts mygo.SaveDialogOptions) (string, error) {
		return mygo.Dialog.Save(opts)
	}
	es.win = mygo.NewWindow(mygo.WindowOptions{
		Title:   "导出账号",
		Width:   420,
		Height:  420,
		Content: ui.View(es.view),
	})
}

func (es *exportState) view(c *ui.Context) {
	s := es.app.state
	t := c.Theme()
	ui.Column(c).Fill().Padding(20).Gap(10).Children(func() {
		ui.Text(c, "导出账号").FontSize(16).Bold()
		ui.Segmented(c.Key("mode"), &es.mode, "加密备份", "明文 CSV")

		if es.mode == 0 {
			ui.Text(c, "备份文件用独立的备份密码加密,可在另一台机器导入。").
				FontSize(12).TextColor(t.TextMuted)
			formField(c, "备份密码", &es.backupPw, "至少 8 位")
			if ui.TextInput(c.Key("pw2"), &es.backupPw2).Password().
				Placeholder("再输入一次").Label("确认备份密码 输入").Submitted() {
				es.submit()
			}
		} else {
			ui.Text(c, "⚠️ 明文导出会把所有密钥以可读形式写入磁盘,任何能读到该文件的人都能生成你的验证码。").
				FontSize(12).TextColor(warnColor)
			if s.encrypted {
				formField(c, "主密码确认", &es.confirmPw, "输入主密码确认导出")
			}
		}

		if es.err != "" {
			ui.Text(c, es.err).FontSize(12).TextColor(warnColor)
		}
		if es.notice != "" {
			ui.Text(c, es.notice).FontSize(12).TextColor(t.Accent)
		}

		ui.Row(c).Gap(8).Children(func() {
			ui.PrimaryButton(c.Key("export"), "导出").Label("导出").OnClick(func() { es.submit() })
			ui.Button(c.Key("close"), "关闭").Label("关闭").OnClick(func() { es.win.Close() })
		})
	})
}

// submit validates and writes the export to a user-picked path.
func (es *exportState) submit() {
	s := es.app.state
	es.err, es.notice = "", ""

	var data []byte
	var opts mygo.SaveDialogOptions
	switch es.mode {
	case 0:
		if len(es.backupPw) < minMasterLen {
			es.err = fmt.Sprintf("备份密码至少需要 %d 个字符", minMasterLen)
			return
		}
		if es.backupPw != es.backupPw2 {
			es.err = "两次输入的备份密码不一致"
			return
		}
		var err error
		data, err = vault.SealVault(&vault.Vault{Version: vault.Version, Accounts: s.accounts},
			es.backupPw, vault.DefaultParams())
		if err != nil {
			es.err = "导出失败:" + err.Error()
			return
		}
		opts = mygo.SaveDialogOptions{
			Title:   "导出加密备份",
			Message: "备份文件包含所有账号的密钥",
			Filters: []mygo.FileFilter{{Name: "Keytray 备份", Extensions: []string{"kt"}}},
		}
	default:
		// The master-password confirmation exists only in encrypted mode;
		// a plaintext vault has no password to confirm.
		if s.encrypted && (es.confirmPw == "" || es.confirmPw != s.masterPw) {
			es.err = "主密码不正确"
			return
		}
		var err error
		data, err = exportCSV(s.accounts)
		if err != nil {
			es.err = "导出失败:" + err.Error()
			return
		}
		opts = mygo.SaveDialogOptions{
			Title:   "导出明文 CSV",
			Message: "明文 CSV 包含所有密钥,请妥善保管",
			Filters: []mygo.FileFilter{{Name: "CSV", Extensions: []string{"csv"}}},
		}
	}

	path, err := es.pickSave(opts)
	if err != nil {
		es.err = "选择保存位置失败:" + err.Error()
		return
	}
	if path == "" {
		return // canceled
	}
	if err := vault.SaveFile(path, data); err != nil { // atomic write, 0600
		es.err = "写入失败:" + err.Error()
		return
	}
	es.notice = "已导出到 " + path
}

// exportCSV renders accounts as CSV, one otpauth:// URI per row included.
func exportCSV(accounts []otp.Account) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{
		"issuer", "name", "type", "algorithm", "digits",
		"period", "counter", "secret", "otpauth_uri",
	}); err != nil {
		return nil, err
	}
	for _, a := range accounts {
		uri, err := a.URI()
		if err != nil {
			return nil, err
		}
		if err := w.Write([]string{
			a.Issuer, a.Name, string(a.Type), a.Algorithm,
			strconv.Itoa(a.Digits), strconv.Itoa(int(a.Period)),
			strconv.FormatUint(a.Counter, 10),
			otp.EncodeSecret(a.Secret), uri,
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// readBackupFile decrypts an exported backup with its backup password.
func readBackupFile(path, password string) ([]otp.Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := vault.OpenVault(data, password)
	if err != nil {
		if errors.Is(err, vault.ErrWrongPassword) {
			return nil, errors.New("备份密码错误")
		}
		return nil, err
	}
	return v.Accounts, nil
}
