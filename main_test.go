package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"keytray/internal/otp"
	"keytray/internal/vault"
)

const testPassword = "demo-password"

type clipRecorder struct{ writes []string }

// newStateAt returns a state over the given vault path, with a recorded
// clipboard instead of the real one.
func newStateAt(t *testing.T, path string) (*panelState, *clipRecorder) {
	t.Helper()
	s := newPanelState(path, filepath.Join(filepath.Dir(path), "settings.json"))
	rec := &clipRecorder{}
	s.writeClip = func(text string) { rec.writes = append(rec.writes, text) }
	s.scheduleClear = func(string) {}
	return s, rec
}

// newState returns a state with a fresh temp vault path (no vault yet).
func newState(t *testing.T) (*panelState, *clipRecorder) {
	t.Helper()
	return newStateAt(t, filepath.Join(t.TempDir(), "vault.kt"))
}

// newStateWithSeed seeds a vault first, then builds the state over it.
func newStateWithSeed(t *testing.T, accounts ...otp.Account) (*panelState, *clipRecorder) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.kt")
	seedVault(t, path, accounts...)
	return newStateAt(t, path)
}

func seedVault(t *testing.T, path string, accounts ...otp.Account) {
	t.Helper()
	v := vault.New()
	v.Accounts = accounts
	data, err := vault.SealVault(v, testPassword,
		vault.Params{Time: 1, MemoryKB: 64, Threads: 1, Salt: bytes.Repeat([]byte{0xCD}, 16)})
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.SaveFile(path, data); err != nil {
		t.Fatal(err)
	}
}

func githubAccount(t *testing.T) otp.Account {
	t.Helper()
	a, err := otp.ParseURI("otpauth://totp/GitHub:feyman?secret=JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func bankAccount(t *testing.T) otp.Account {
	t.Helper()
	a, err := otp.ParseURI("otpauth://hotp/OldBank:bob?secret=JBSWY3DPEHPK3PXP&counter=7")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// 首次运行:无金库文件 → 直接可用(明文模式),第一次保存落明文 JSON。
func TestFirstRunPlainFlow(t *testing.T) {
	s, _ := newState(t)
	if s.exists || s.encrypted || !s.unlocked || len(s.accounts) != 0 {
		t.Fatalf("first-run state: exists=%v encrypted=%v unlocked=%v", s.exists, s.encrypted, s.unlocked)
	}
	if err := s.AddAccount(githubAccount(t)); err != nil {
		t.Fatal(err)
	}
	if !s.exists || s.encrypted {
		t.Fatalf("after first save: exists=%v encrypted=%v", s.exists, s.encrypted)
	}
	if vault.IsEncrypted(mustLoad(t, s.vaultPath)) {
		t.Error("plain-mode save must not produce an encrypted file")
	}

	// A fresh state over the same file loads without any password.
	s2 := newPanelState(s.vaultPath, s.settingsPath)
	if !s2.unlocked || !s2.exists || s2.encrypted || len(s2.accounts) != 1 {
		t.Fatalf("reopen plain: unlocked=%v encrypted=%v accounts=%d", s2.unlocked, s2.encrypted, len(s2.accounts))
	}
}

func TestEncryptionLifecycle(t *testing.T) {
	s, _ := newState(t)
	if err := s.AddAccount(githubAccount(t)); err != nil {
		t.Fatal(err)
	}

	// Enable: validation then success.
	if err := s.EnableEncryption("short", "short"); err == nil || !strings.Contains(err.Error(), "8") {
		t.Errorf("short password: got %v", err)
	}
	if err := s.EnableEncryption(testPassword, "mismatch-xxx"); err == nil || !strings.Contains(err.Error(), "不一致") {
		t.Errorf("mismatch: got %v", err)
	}
	if err := s.EnableEncryption(testPassword, testPassword); err != nil {
		t.Fatal(err)
	}
	if !s.encrypted || s.masterPw != testPassword {
		t.Fatalf("after enable: encrypted=%v", s.encrypted)
	}
	if !vault.IsEncrypted(mustLoad(t, s.vaultPath)) {
		t.Error("enable must rewrite the file encrypted")
	}

	// Lock/unlock now applies.
	s.lock()
	if s.unlocked {
		t.Error("encrypted vault should lock")
	}
	s.unlockPw = "wrong"
	if err := s.unlock(); !errors.Is(err, vault.ErrWrongPassword) {
		t.Errorf("wrong password: %v", err)
	}
	s.unlockPw = testPassword
	if err := s.unlock(); err != nil {
		t.Fatal(err)
	}

	// Change master password.
	if err := s.ChangeMasterPassword("wrong", "new-password-1"); err == nil {
		t.Error("wrong old password must fail")
	}
	if err := s.ChangeMasterPassword(testPassword, "short"); err == nil {
		t.Error("short new password must fail")
	}
	if err := s.ChangeMasterPassword(testPassword, "new-password-1"); err != nil {
		t.Fatal(err)
	}
	s.lock()
	s.unlockPw = testPassword
	if err := s.unlock(); !errors.Is(err, vault.ErrWrongPassword) {
		t.Error("old password should stop working after change")
	}
	s.unlockPw = "new-password-1"
	if err := s.unlock(); err != nil {
		t.Fatal(err)
	}

	// Disable: wrong password rejected, right one reverts to plaintext.
	if err := s.DisableEncryption("wrong"); err == nil {
		t.Error("wrong password must fail")
	}
	if err := s.DisableEncryption("new-password-1"); err != nil {
		t.Fatal(err)
	}
	if s.encrypted || s.masterPw != "" {
		t.Fatalf("after disable: encrypted=%v", s.encrypted)
	}
	if vault.IsEncrypted(mustLoad(t, s.vaultPath)) {
		t.Error("disable must rewrite the file as plaintext")
	}
	s.lock() // no-op in plain mode
	if !s.unlocked {
		t.Error("plain vault cannot lock")
	}
}

func mustLoad(t *testing.T, path string) []byte {
	t.Helper()
	b, err := vault.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnlockWrongThenRight(t *testing.T) {
	s, _ := newStateWithSeed(t, githubAccount(t))
	s.unlockPw = "totally-wrong"
	if err := s.unlock(); !errors.Is(err, vault.ErrWrongPassword) {
		t.Errorf("wrong password: got %v", err)
	}
	if s.unlocked {
		t.Error("unlocked with a wrong password")
	}
	s.unlockPw = testPassword
	if err := s.unlock(); err != nil {
		t.Fatal(err)
	}
	if !s.unlocked || len(s.accounts) != 1 || s.accounts[0].Name != "feyman" {
		t.Errorf("state after unlock: %+v", s.accounts)
	}
}

func TestFilterAndCopy(t *testing.T) {
	s, rec := newStateWithSeed(t, githubAccount(t), bankAccount(t))
	s.unlockPw = testPassword
	if err := s.unlock(); err != nil {
		t.Fatal(err)
	}

	s.query = "git"
	s.filter()
	if len(s.filtered) != 1 || s.filtered[0].Issuer != "GitHub" {
		t.Errorf("filter 'git': %+v", s.filtered)
	}
	s.query = "OLD" // case-insensitive
	s.filter()
	if len(s.filtered) != 1 || s.filtered[0].Issuer != "OldBank" {
		t.Errorf("filter 'OLD': %+v", s.filtered)
	}
	s.query = ""
	s.filter()
	if len(s.filtered) != 2 {
		t.Errorf("filter '': %+v", s.filtered)
	}

	want, err := githubAccount(t).Code(s.now)
	if err != nil {
		t.Fatal(err)
	}
	s.copy(0)
	if len(rec.writes) != 1 || rec.writes[0] != want {
		t.Errorf("clipboard writes = %v, want [%s]", rec.writes, want)
	}
	if s.copiedLabel != "GitHub:feyman" {
		t.Errorf("copiedLabel = %q", s.copiedLabel)
	}
	s.copy(99) // out of range: no panic, no write
	if len(rec.writes) != 1 {
		t.Errorf("out-of-range copy wrote %v", rec.writes)
	}

	s.lock()
	if s.unlocked || s.accounts != nil || len(s.filtered) != 0 || s.query != "" {
		t.Errorf("state after lock: unlocked=%v accounts=%v", s.unlocked, s.accounts)
	}
}

func TestCopyHintExpiry(t *testing.T) {
	s, _ := newStateWithSeed(t, githubAccount(t))
	if s.copyHintVisible(s.now.Add(copiedHintFor + time.Second)) {
		t.Error("hint should expire")
	}
	s.copy(0) // seeded state has no accounts, but copy guards bounds
	if s.copyHintVisible(time.Now()) {
		t.Error("no hint without a successful copy")
	}
}

func TestCentralCountdown(t *testing.T) {
	now := time.Unix(59, 0).UTC()
	acc := githubAccount(t)
	if rem, ok := centralCountdown([]otp.Account{acc, bankAccount(t)}, now); !ok || rem != 1 {
		t.Errorf("centralCountdown = %d, %v; want 1, true", rem, ok)
	}
	if _, ok := centralCountdown([]otp.Account{bankAccount(t)}, now); ok {
		t.Error("HOTP-only list has no shared countdown")
	}
}

// --- view-level tests: the view runs without a window; click and type as a
// user would. ---

// 首次打开:没有设置主密码的环节,直接是空账号面板 + 未加密标识。
func TestViewFirstRunPlain(t *testing.T) {
	s, _ := newState(t)
	a := &app{state: s}
	tt := ui.NewTester(a.view, panelWidth, panelHeight)

	if !tt.HasText("暂无账号") {
		t.Fatalf("first-run texts: %q", tt.Texts())
	}
	if tt.HasText("解锁") || tt.HasText("创建金库") || tt.HasText("锁定") {
		t.Errorf("password UI leaked into first run: %q", tt.Texts())
	}
}

func TestViewCryptWindows(t *testing.T) {
	s, _ := newState(t)
	a := &app{state: s}

	// Enable via the crypt window's view.
	cs := &cryptState{app: a, mode: cryptEnable}
	tt := ui.NewTester(cs.view, 420, 400)
	if !tt.HasText("无法找回") {
		t.Fatalf("enable view: %q", tt.Texts())
	}
	tt.Click("主密码 输入")
	tt.Type("short")
	if !tt.HasText("至少 8 位") {
		t.Errorf("weak hint missing: %q", tt.Texts())
	}
	tt.Click("确认")
	if !tt.HasText("至少需要") {
		t.Errorf("short error missing: %q", tt.Texts())
	}

	cs.pw = testPassword // as if retyped
	tt.Click("确认主密码 输入")
	tt.Type(testPassword)
	tt.Click("确认")
	if cs.err != "" || !s.encrypted {
		t.Fatalf("enable failed: err=%q encrypted=%v", cs.err, s.encrypted)
	}

	// Disable with the wrong password shows the error.
	ds := &cryptState{app: a, mode: cryptDisable}
	tt2 := ui.NewTester(ds.view, 420, 400)
	if !tt2.HasText("明文存储") {
		t.Fatalf("disable view: %q", tt2.Texts())
	}
	tt2.Click("主密码 输入")
	tt2.Type("wrong-password")
	tt2.Click("确认")
	if !tt2.HasText("主密码不正确") || s.masterPw == "" {
		t.Errorf("wrong disable pw: %q", tt2.Texts())
	}
	ds.pw = ""
	tt2.Click("主密码 输入")
	tt2.Type(testPassword)
	tt2.Click("确认")
	if ds.err != "" || s.encrypted {
		t.Fatalf("disable failed: err=%q encrypted=%v", ds.err, s.encrypted)
	}
}

func TestViewUnlockSearchCopyLock(t *testing.T) {
	s, rec := newStateWithSeed(t, githubAccount(t), bankAccount(t))
	a := &app{state: s}
	tt := ui.NewTester(a.view, panelWidth, panelHeight)

	if !tt.HasText("解锁") {
		t.Fatalf("lock view texts: %q", tt.Texts())
	}
	tt.Click("主密码")
	tt.Type("wrong-password")
	tt.Click("解锁")
	if !tt.HasText("密码错误") || s.unlocked {
		t.Fatalf("wrong password not reported: %q", tt.Texts())
	}

	s.unlockPw = "" // as if selected and retyped
	tt.Click("主密码")
	tt.Type(testPassword)
	tt.Click("解锁")
	if !s.unlocked {
		t.Fatalf("unlock failed: err=%q", s.err)
	}
	if !tt.HasText("GitHub:feyman") || !tt.HasText("OldBank:bob") {
		t.Errorf("accounts missing: %q", tt.Texts())
	}

	tt.Click("搜索账号")
	tt.Type("git")
	if tt.HasText("OldBank:bob") {
		t.Errorf("search did not filter: %q", tt.Texts())
	}

	want, err := githubAccount(t).Code(s.now)
	if err != nil {
		t.Fatal(err)
	}
	tt.Click("GitHub:feyman")
	if len(rec.writes) != 1 || rec.writes[0] != want {
		t.Errorf("row click wrote %v, want [%s]", rec.writes, want)
	}
	if !tt.HasText("已复制 GitHub:feyman") {
		t.Errorf("copy hint missing: %q", tt.Texts())
	}

	tt.Click("锁定")
	if s.unlocked || !tt.HasText("解锁") {
		t.Errorf("lock button did not lock: %q", tt.Texts())
	}
}

// --- M3: mutations, import, form, manage mode ---

func unlockedState(t *testing.T) *panelState {
	t.Helper()
	s, _ := newStateWithSeed(t, githubAccount(t))
	s.unlockPw = testPassword
	if err := s.unlock(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMutationsPersist(t *testing.T) {
	s := unlockedState(t)
	bank := bankAccount(t)

	if err := s.AddAccount(bank); err != nil {
		t.Fatal(err)
	}
	if err := s.MoveAccount(bank, -1); err != nil {
		t.Fatal(err)
	}
	renamed := githubAccount(t)
	renamed.Name = "feyman2"
	if err := s.UpdateAccount(githubAccount(t), renamed); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveAccount(bank); err != nil {
		t.Fatal(err)
	}
	if len(s.accounts) != 1 || s.accounts[0].Name != "feyman2" {
		t.Fatalf("in-memory state: %+v", s.accounts)
	}

	// Everything above must be on disk: reopen with a fresh state.
	s2 := newPanelState(s.vaultPath, filepath.Join(filepath.Dir(s.vaultPath), "settings.json"))
	s2.unlockPw = testPassword
	if err := s2.unlock(); err != nil {
		t.Fatal(err)
	}
	if len(s2.accounts) != 1 || s2.accounts[0].Name != "feyman2" || s2.accounts[0].Issuer != "GitHub" {
		t.Fatalf("persisted state: %+v", s2.accounts)
	}
}

func TestImportURIsDedupe(t *testing.T) {
	s := unlockedState(t)
	githubURI := "otpauth://totp/GitHub:feyman?secret=JBSWY3DPEHPK3PXP"
	bankURI := "otpauth://hotp/OldBank:bob?secret=JBSWY3DPEHPK3PXP&counter=7"

	text := githubURI + "\n" + bankURI + "\nhttps://not-otpauth\n\n" + bankURI
	added, skipped, bad, err := s.ImportURIs(text)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || skipped != 2 || bad != 1 {
		t.Errorf("added=%d skipped=%d bad=%d; want 1/2/1", added, skipped, bad)
	}
	if len(s.accounts) != 2 {
		t.Fatalf("accounts: %+v", s.accounts)
	}

	s.lock()
	if _, _, _, err := s.ImportURIs(bankURI); err == nil {
		t.Error("import while locked must fail")
	}
}

func TestViewFormSubmitAndPrefill(t *testing.T) {
	s := unlockedState(t)
	a := &app{state: s}

	fs := &formState{app: a, period: "30"}
	tt := ui.NewTester(fs.view, 400, 520)
	tt.Click("服务名 输入")
	tt.Type("Tencent Cloud")
	tt.Click("账号名 输入")
	tt.Type("100053131378")
	tt.Click("密钥(Base32) 输入")
	tt.Type("JBSWY3DPEHPK3PXP")
	tt.Click("保存")
	if fs.err != "" {
		t.Fatalf("submit error: %q", fs.err)
	}
	if len(s.accounts) != 2 {
		t.Fatalf("accounts after add: %+v", s.accounts)
	}
	got := s.accounts[1]
	if got.Issuer != "Tencent Cloud" || got.Name != "100053131378" || got.Digits != 6 {
		t.Errorf("added account: %+v", got)
	}

	// Bad secret surfaces an inline error and adds nothing.
	fs2 := &formState{app: a, period: "30"}
	tt2 := ui.NewTester(fs2.view, 400, 520)
	tt2.Click("账号名 输入")
	tt2.Type("x")
	tt2.Click("密钥(Base32) 输入")
	tt2.Type("!!!")
	tt2.Click("保存")
	if fs2.err == "" || len(s.accounts) != 2 {
		t.Errorf("bad secret: err=%q accounts=%d", fs2.err, len(s.accounts))
	}

	// Editing prefills from the existing account.
	fs3 := &formState{app: a}
	fs3.prefill(s.accounts[0])
	if fs3.issuer != "GitHub" || fs3.name != "feyman" || fs3.secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("prefill: %+v", fs3)
	}
}

func TestViewImportRun(t *testing.T) {
	s := unlockedState(t)
	a := &app{state: s}
	is := &importState{app: a}
	tt := ui.NewTester(is.view, 480, 380)

	bankURI := "otpauth://hotp/OldBank:bob?secret=JBSWY3DPEHPK3PXP&counter=7"
	is.text = bankURI
	tt.Click("导入")
	if !tt.HasText("已添加 1") || !tt.HasText("跳过重复 0") {
		t.Fatalf("summary: %q", tt.Texts())
	}
	if is.text != "" {
		t.Error("textarea should clear after a successful import")
	}

	is.text = bankURI // same URI again
	tt.Click("导入")
	if !tt.HasText("跳过重复 1") {
		t.Fatalf("dup summary: %q", tt.Texts())
	}
	if len(s.accounts) != 2 {
		t.Errorf("accounts: %+v", s.accounts)
	}
}

func TestViewManageModeAndTypingSafety(t *testing.T) {
	s := unlockedState(t)
	s.AddAccount(bankAccount(t))
	a := &app{state: s}
	tt := ui.NewTester(a.view, panelWidth, panelHeight)

	tt.Click("管理")
	if !s.manageMode || !tt.HasText("完成管理") || !tt.HasText("✎") {
		t.Fatalf("manage mode not shown: %q", tt.Texts())
	}

	// Typing into the search box must not fire the A/I/S/D shortcuts.
	tt.Click("搜索账号")
	tt.Type("ai")
	if a.lastAction != "" {
		t.Errorf("shortcut fired while typing: %q", a.lastAction)
	}
	if s.query != "ai" {
		t.Errorf("query = %q, want \"ai\"", s.query)
	}

	tt.Click("完成管理")
	if s.manageMode {
		t.Error("manage mode should be off")
	}
}

// --- M4: settings, auto-lock, export/import backup ---

func TestSettingsDefaultsPersistAndClamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	st := loadSettings(path) // missing file
	if !st.Autostart || !st.ClearClipboard || st.AutoLock {
		t.Errorf("defaults: %+v", st)
	}
	if st.AutoLockMinutes != 5 || st.SummonShortcut != "Alt+Space" || st.CaptureShortcut != "Alt+S" {
		t.Errorf("defaults: %+v", st)
	}

	st.AutoLock = true
	st.AutoLockMinutes = 99 // clamped on save
	if err := saveSettings(path, st); err != nil {
		t.Fatal(err)
	}
	got := loadSettings(path)
	if !got.AutoLock || got.AutoLockMinutes != 60 {
		t.Errorf("persisted: %+v", got)
	}

	// Bad JSON keeps the defaults.
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := loadSettings(path); !d.Autostart || d.AutoLock {
		t.Errorf("bad json: %+v", d)
	}
}

func TestAutoLockDue(t *testing.T) {
	s := unlockedState(t)
	now := time.Now()
	s.settings.AutoLock = false
	if s.autoLockDue(now) {
		t.Error("auto-lock off must never be due")
	}

	s.settings.AutoLock = true
	s.settings.AutoLockMinutes = 5
	s.lastActive = now.Add(-6 * time.Minute)
	if !s.autoLockDue(now) {
		t.Error("6min idle with 5min lock should be due")
	}
	s.touch()
	if s.autoLockDue(now) {
		t.Error("fresh activity should not be due")
	}
	s.lock()
	s.lastActive = now.Add(-time.Hour)
	if s.autoLockDue(now) {
		t.Error("locked state is never due")
	}
}

func TestExportEncryptedBackupAndCSV(t *testing.T) {
	s := unlockedState(t)
	a := &app{state: s}

	// Encrypted backup with an independent password.
	backupPath := filepath.Join(t.TempDir(), "backup.kt")
	es := &exportState{app: a}
	es.pickSave = func(mygo.SaveDialogOptions) (string, error) { return backupPath, nil }
	es.backupPw, es.backupPw2 = "backup-password", "backup-password"
	es.submit()
	if es.err != "" {
		t.Fatalf("export err: %q", es.err)
	}
	accounts, err := readBackupFile(backupPath, "backup-password")
	if err != nil || len(accounts) != 1 || accounts[0].Name != "feyman" {
		t.Fatalf("readBackup: %v %+v", err, accounts)
	}
	if _, err := readBackupFile(backupPath, "wrong"); err == nil {
		t.Error("wrong backup password must fail")
	}

	// Backup password validation.
	es2 := &exportState{app: a}
	es2.pickSave = es.pickSave
	es2.submit()
	if es2.err == "" {
		t.Error("empty backup password must be rejected")
	}

	// Plaintext CSV requires the master password.
	csvPath := filepath.Join(t.TempDir(), "export.csv")
	es3 := &exportState{app: a, mode: 1}
	es3.pickSave = func(mygo.SaveDialogOptions) (string, error) { return csvPath, nil }
	es3.confirmPw = "not-the-master"
	es3.submit()
	if es3.err == "" || fileExists(csvPath) {
		t.Errorf("wrong master password: err=%q exists=%v", es3.err, fileExists(csvPath))
	}
	es3.confirmPw = testPassword
	es3.submit()
	if es3.err != "" {
		t.Fatalf("csv export err: %q", es3.err)
	}

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("csv rows: %d", len(rows))
	}
	acc, err := otp.ParseURI(rows[1][8])
	if err != nil || acc.Issuer != "GitHub" || acc.Name != "feyman" {
		t.Errorf("csv uri column: %v %+v", err, acc)
	}
}

func TestImportBackupFile(t *testing.T) {
	s := unlockedState(t)
	a := &app{state: s}

	// An exported backup holding a different account.
	other := &vault.Vault{Version: vault.Version, Accounts: []otp.Account{bankAccount(t)}}
	backupPath := filepath.Join(t.TempDir(), "backup.kt")
	data, err := vault.SealVault(other, "backup-password", fastVaultParams(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.SaveFile(backupPath, data); err != nil {
		t.Fatal(err)
	}

	is := &importState{app: a}
	is.pickOpen = func(mygo.OpenDialogOptions) ([]string, error) { return []string{backupPath}, nil }
	is.backupPw = "backup-password"
	is.importBackup()
	if is.err != "" {
		t.Fatalf("importBackup err: %q", is.err)
	}
	if len(s.accounts) != 2 {
		t.Fatalf("accounts after backup import: %+v", s.accounts)
	}

	// Importing the same backup again skips everything.
	is.importBackup()
	if !strings.Contains(is.summary, "跳过重复 1") {
		t.Errorf("second import summary: %q", is.summary)
	}

	is.backupPw = "wrong"
	is.importBackup()
	if is.err != "备份密码错误" {
		t.Errorf("wrong backup pw: %q", is.err)
	}
}

func fastVaultParams(t *testing.T) vault.Params {
	t.Helper()
	return vault.Params{Time: 1, MemoryKB: 64, Threads: 1, Salt: bytes.Repeat([]byte{0x5A}, 16)}
}

func TestViewSettingsWindow(t *testing.T) {
	s := unlockedState(t)
	a := &app{state: s}
	var autostartCalls []bool
	ss := &settingsState{app: a, lockMinutes: "5"}
	ss.setAutostart = func(on bool) error { autostartCalls = append(autostartCalls, on); return nil }

	tt := ui.NewTester(ss.view, 420, 460)
	tt.Click("开机自启 开关") // default on -> off
	if s.settings.Autostart {
		t.Error("switch did not turn autostart off")
	}
	if len(autostartCalls) != 1 || autostartCalls[0] {
		t.Errorf("autostart calls: %v", autostartCalls)
	}
	// The change persisted.
	persisted := loadSettings(s.settingsPath)
	if persisted.Autostart {
		t.Error("settings not persisted")
	}

	tt.Click("自动锁定 开关")
	if !s.settings.AutoLock {
		t.Error("auto-lock switch did not turn on")
	}
	if !tt.HasText("锁定时长") {
		t.Errorf("lock duration missing: %q", tt.Texts())
	}

	tt.Click("唤起面板快捷键 选择") // open the select's menu? Select interaction is native; just assert state save via applyShortcuts
	a.lastAction = ""
	ss.applyShortcuts()
	if a.lastAction != "shortcuts" {
		t.Errorf("applyShortcuts under tester: %q", a.lastAction)
	}
	if loadSettings(s.settingsPath).SummonShortcut != s.settings.SummonShortcut {
		t.Error("shortcut setting not persisted")
	}
}

func TestViewSettingsEncryptionSection(t *testing.T) {
	// Plain vault: offers enable, no disable/change.
	s, _ := newState(t)
	a := &app{state: s}
	ss := &settingsState{app: a, lockMinutes: "5"}
	ss.setAutostart = func(bool) error { return nil }
	tt := ui.NewTester(ss.view, 420, 460)
	if !tt.HasText("未开启") || !tt.HasText("明文存储") {
		t.Fatalf("plain settings: %q", tt.Texts())
	}
	a.lastAction = ""
	tt.Click("开启本地加密")
	if a.lastAction != "crypt:0" {
		t.Errorf("openCrypt not routed: %q", a.lastAction)
	}

	// Encrypted vault: offers disable and change.
	s2 := unlockedState(t)
	a2 := &app{state: s2}
	ss2 := &settingsState{app: a2, lockMinutes: "5"}
	ss2.setAutostart = func(bool) error { return nil }
	tt2 := ui.NewTester(ss2.view, 420, 460)
	if !tt2.HasText("已开启") || tt2.HasText("开启本地加密") {
		t.Fatalf("encrypted settings: %q", tt2.Texts())
	}
	a2.lastAction = ""
	tt2.Click("修改主密码")
	if a2.lastAction != "crypt:2" {
		t.Errorf("change-pw not routed: %q", a2.lastAction)
	}
}

func TestExportCSVPlainMode(t *testing.T) {
	// A plaintext vault has no master password to confirm.
	s, _ := newState(t)
	if err := s.AddAccount(githubAccount(t)); err != nil {
		t.Fatal(err)
	}
	a := &app{state: s}
	csvPath := filepath.Join(t.TempDir(), "export.csv")
	es := &exportState{app: a, mode: 1}
	es.pickSave = func(mygo.SaveDialogOptions) (string, error) { return csvPath, nil }
	es.submit() // confirmPw empty; plain mode must not require it
	if es.err != "" {
		t.Fatalf("plain CSV export err: %q", es.err)
	}
	if !fileExists(csvPath) {
		t.Fatal("csv not written")
	}
}

// GA 导出链接:一条 migration URI 携带多个账号,重复项跨次导入跳过。
func TestImportGoogleMigration(t *testing.T) {
	s := unlockedState(t)

	accounts := []otp.Account{
		{Type: otp.TOTP, Issuer: "GitHub", Name: "feyman", Secret: []byte("ga-export-key-1")},
		{Type: otp.HOTP, Issuer: "OldBank", Name: "bob", Secret: []byte("ga-export-key-2"), Counter: 3},
	}
	uri, err := otp.MigrationURI(accounts)
	if err != nil {
		t.Fatal(err)
	}
	added, skipped, bad, err := s.ImportURIs(uri)
	if err != nil || added != 2 || skipped != 0 || bad != 0 {
		t.Fatalf("first import: added=%d skipped=%d bad=%d err=%v", added, skipped, bad, err)
	}
	if len(s.accounts) != 3 { // seed GitHub:feyman + 2 new
		t.Fatalf("accounts: %+v", s.accounts)
	}

	// Same URI again: everything dedupes.
	added, skipped, _, err = s.ImportURIs(uri)
	if err != nil || added != 0 || skipped != 2 {
		t.Fatalf("second import: added=%d skipped=%d err=%v", added, skipped, err)
	}

	// Mixed text: migration URI + plain otpauth + garbage line.
	mixed := uri + "\n" + "otpauth://totp/Mixed:one?secret=JBSWY3DPEHPK3PXP\nhttps://nope"
	added, skipped, bad, err = s.ImportURIs(mixed)
	if err != nil || added != 1 || skipped != 2 || bad != 1 {
		t.Fatalf("mixed import: added=%d skipped=%d bad=%d err=%v", added, skipped, bad, err)
	}
}

// --- v1.1: 钥匙串自动解锁 ---

// fakeSecrets is an in-memory credential store.
type fakeSecrets struct {
	store map[string][]byte
}

func newFakeSecrets() *fakeSecrets { return &fakeSecrets{store: map[string][]byte{}} }

func (f *fakeSecrets) read() ([]byte, error) {
	v, ok := f.store[secretKey]
	if !ok {
		return nil, errors.New("not found") // stand-in for ErrSecretNotFound
	}
	return bytes.Clone(v), nil
}
func (f *fakeSecrets) write(v []byte) error {
	f.store[secretKey] = bytes.Clone(v)
	return nil
}
func (f *fakeSecrets) drop() error {
	delete(f.store, secretKey)
	return nil
}

// stateWithSecrets builds a panelState over path with the fake store.
func stateWithSecrets(path, settingsPath string, f *fakeSecrets) *panelState {
	return newPanelStateWith(path, settingsPath, f.read, f.write, f.drop)
}

func TestAutoUnlockLifecycle(t *testing.T) {
	sec := newFakeSecrets()

	// Encrypted vault, unlocked once by hand.
	s := unlockedState(t)
	s.readSecret, s.writeSecret, s.dropSecret = sec.read, sec.write, sec.drop

	// Off by default; enabling stores the password.
	if s.settings.AutoUnlock {
		t.Fatal("auto unlock must default off")
	}
	if err := s.SetAutoUnlock(true); err != nil {
		t.Fatal(err)
	}
	if !s.settings.AutoUnlock || string(sec.store[secretKey]) != testPassword {
		t.Fatalf("enable: setting=%v secret=%q", s.settings.AutoUnlock, sec.store[secretKey])
	}

	// A fresh state over the same files auto-unlocks.
	s2 := stateWithSecrets(s.vaultPath, s.settingsPath, sec)
	if !s2.unlocked || len(s2.accounts) != 1 || s2.masterPw != testPassword {
		t.Fatalf("auto unlock on fresh state: unlocked=%v accounts=%d", s2.unlocked, len(s2.accounts))
	}

	// Disabling deletes the stored secret and the setting.
	if err := s2.SetAutoUnlock(false); err != nil {
		t.Fatal(err)
	}
	if _, exists := sec.store[secretKey]; exists {
		t.Error("secret not deleted on disable")
	}
	if s2.settings.AutoUnlock {
		t.Error("setting not cleared on disable")
	}
	s3 := stateWithSecrets(s.vaultPath, s.settingsPath, sec)
	if s3.unlocked {
		t.Error("fresh state must stay locked after disable")
	}
}

func TestAutoUnlockGuards(t *testing.T) {
	sec := newFakeSecrets()

	// Plaintext vault: refused.
	plain, _ := newState(t)
	plain.readSecret, plain.writeSecret, plain.dropSecret = sec.read, sec.write, sec.drop
	if err := plain.SetAutoUnlock(true); err == nil {
		t.Error("auto unlock on a plain vault must be refused")
	}

	// Locked encrypted vault: refused until unlocked.
	s, _ := newStateWithSeed(t, githubAccount(t))
	s.readSecret, s.writeSecret, s.dropSecret = sec.read, sec.write, sec.drop
	if err := s.SetAutoUnlock(true); err == nil {
		t.Error("auto unlock while locked must be refused")
	}
	s.unlockPw = testPassword
	if err := s.unlock(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAutoUnlock(true); err != nil {
		t.Fatal(err)
	}

	// Master password change keeps auto unlock working.
	newPw := "changed-password-9"
	if err := s.ChangeMasterPassword(testPassword, newPw); err != nil {
		t.Fatal(err)
	}
	if string(sec.store[secretKey]) != newPw {
		t.Fatalf("stored secret not refreshed: %q", sec.store[secretKey])
	}
	s4 := stateWithSecrets(s.vaultPath, s.settingsPath, sec)
	if !s4.unlocked || s4.masterPw != newPw {
		t.Error("auto unlock must follow the new master password")
	}

	// Disabling encryption removes the secret and the setting.
	if err := s.DisableEncryption(newPw); err != nil {
		t.Fatal(err)
	}
	if _, exists := sec.store[secretKey]; exists || s.settings.AutoUnlock {
		t.Error("disable encryption must clear secret and setting")
	}
}

func TestAutoUnlockStaleSecretDropped(t *testing.T) {
	sec := newFakeSecrets()
	s := unlockedState(t)
	s.readSecret, s.writeSecret, s.dropSecret = sec.read, sec.write, sec.drop
	if err := s.SetAutoUnlock(true); err != nil {
		t.Fatal(err)
	}

	// Simulate the vault password changing without the secret following
	// (e.g. edited by an older build): the stored one goes stale.
	sec.store[secretKey] = []byte("outdated")
	s5 := stateWithSecrets(s.vaultPath, s.settingsPath, sec)
	if s5.unlocked {
		t.Fatal("stale secret must not unlock")
	}
	if _, exists := sec.store[secretKey]; exists {
		t.Error("stale secret not dropped")
	}
	if s5.settings.AutoUnlock {
		t.Error("stale setting not cleared")
	}
}

// --- v1.1: 拖拽排序 ---

func TestApplyReorder(t *testing.T) {
	accounts := []otp.Account{bankAccount(t), githubAccount(t), bankAccount(t)} // [0,1,2]

	label := func(as []otp.Account) []string {
		out := make([]string, len(as))
		for i, a := range as {
			out[i] = a.Name
		}
		return out
	}
	names := label(accounts) // ["bob", "feyman", "bob"]

	// 单行 0 移到 2(尾部)。
	got := applyReorder(accounts, []int{0}, 2)
	if !reflect.DeepEqual(label(got), []string{names[1], names[2], names[0]}) {
		t.Errorf("move head to tail: %v", label(got))
	}

	// 尾行 2 移到 0(头部)。
	got = applyReorder(accounts, []int{2}, 0)
	if !reflect.DeepEqual(label(got), []string{names[2], names[0], names[1]}) {
		t.Errorf("move tail to head: %v", label(got))
	}

	// 下移一格:落点是最末插入位 to=3。
	got = applyReorder(accounts, []int{1}, 3)
	if !reflect.DeepEqual(label(got), []string{names[0], names[2], names[1]}) {
		t.Errorf("swap adjacent down: %v", label(got))
	}
	// to=2 表示插回原位之前,等于没动。
	got = applyReorder(accounts, []int{1}, 2)
	if !reflect.DeepEqual(label(got), []string{names[0], names[1], names[2]}) {
		t.Errorf("insert before original row2: %v", label(got))
	}

	// 空拖拽与越界:原样返回,不损坏。
	if got := applyReorder(accounts, nil, 1); !reflect.DeepEqual(label(got), names) {
		t.Errorf("empty rows: %v", label(got))
	}
	if got := applyReorder(accounts, []int{9}, 0); !reflect.DeepEqual(label(got), names) {
		t.Errorf("out of range must refuse: %v", label(got))
	}
}

func TestIssuerIcons(t *testing.T) {
	loadIcons()
	if iconForIssuer("Microsoft Azure") == nil {
		t.Error("microsoft icon should match by keyword")
	}
	if iconForIssuer("GitHub") != nil {
		t.Error("no embedded github icon yet; fallback expected")
	}
	if iconForIssuer("   ") != nil {
		t.Error("blank issuer has no icon")
	}
}

// --- v1.1: 分组显示 ---

func TestBuildRows(t *testing.T) {
	a1 := githubAccount(t) // GitHub:feyman
	a2 := bankAccount(t)   // OldBank:bob
	a3, _ := otp.ParseURI("otpauth://totp/GitHub:two?secret=JBSWY3DPEHPK3PXP")
	a4, _ := otp.ParseURI("otpauth://totp/NoIssuer?secret=JBSWY3DPEHPK3PXP")

	// 分组:同 issuer 相邻聚合,无 issuer 归"未分组",ord 只数账号行。
	got := buildRows([]otp.Account{a1, a2, a3, a4}, true)
	var kinds []string
	var ords []int
	for _, r := range got {
		if r.header {
			kinds = append(kinds, r.text)
			ords = append(ords, -1)
		} else {
			kinds = append(kinds, fmt.Sprint(r.accIdx))
			ords = append(ords, r.ord)
		}
	}
	wantKinds := []string{"GitHub", "0", "OldBank", "1", "GitHub", "2", "未分组", "3"}
	if !reflect.DeepEqual(kinds, wantKinds) {
		t.Errorf("grouped rows: %v", kinds)
	}
	if !reflect.DeepEqual(ords, []int{-1, 0, -1, 1, -1, 2, -1, 3}) {
		t.Errorf("ordinals: %v", ords)
	}

	// 平面模式:无头行,ord 连续。
	got = buildRows([]otp.Account{a1, a2}, false)
	for i, r := range got {
		if r.header || r.accIdx != i || r.ord != i {
			t.Errorf("flat row %d: %+v", i, r)
		}
	}
}

func TestViewGroupedHeadersAndDigitCopy(t *testing.T) {
	s, rec := stateWithSecretsLocked(t)
	a := &app{state: s}
	tt := ui.NewTester(a.view, panelWidth, panelHeight)

	if !tt.HasText("分组 GitHub") || !tt.HasText("分组 OldBank") {
		t.Fatalf("group headers missing: %q", tt.Texts())
	}
	// ⇧⌘ 复制走账号序数(头行不占号)。
	tt.Key(ui.Shift|ui.Cmd, ui.Key1) // ord 1 = OldBank(bob)
	if len(rec.writes) != 1 {
		t.Fatalf("digit copy wrote %v", rec.writes)
	}
}

func stateWithSecretsLocked(t *testing.T) (*panelState, *clipRecorder) {
	t.Helper()
	s, rec := newStateWithSeed(t, githubAccount(t), bankAccount(t))
	s.unlockPw = testPassword
	if err := s.unlock(); err != nil {
		t.Fatal(err)
	}
	return s, rec
}
