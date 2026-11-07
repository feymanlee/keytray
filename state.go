package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/egoist/mygo"

	"keytray/internal/otp"
	"keytray/internal/vault"
)

const (
	// minMasterLen is the minimum master password length (enforced).
	minMasterLen = 8
	// clipboardClearIn is how long a copied code may stay on the clipboard.
	clipboardClearIn = 30 * time.Second
	// copiedHintFor is how long the panel shows "已复制" after a copy.
	copiedHintFor = 3 * time.Second
	// secretKey stores the master password for auto-unlock in the
	// system credential store (mygo.Secrets).
	secretKey = "master-password"
)

// panelState is everything the flyout panel shows. It lives on the main
// thread (view, tray and shortcut callbacks); clipboard side effects are
// injectable so tests can observe them without an app runtime.
type panelState struct {
	vaultPath string
	exists    bool // a vault file is present

	// encrypted mirrors the vault file's format. Local encryption is
	// optional (default off): a plaintext vault opens without a password.
	encrypted bool
	unlocked  bool
	accounts  []otp.Account // display order, the vault's order
	filtered  []otp.Account // accounts matching query
	rows      []listRow     // panel rows: grouped or flat
	hideAt    time.Time     // auto-hide the panel after this instant (copy)

	query string
	err   string
	now   time.Time // the tick codes are generated at

	// masterPw re-encrypts the vault on change; it lives only in memory
	// while an encrypted vault is unlocked and is dropped by lock.
	masterPw   string
	manageMode bool

	unlockPw string

	copiedLabel string
	copiedAt    time.Time

	settings     Settings
	settingsPath string
	lastActive   time.Time // auto-lock reference point

	writeClip     func(string)
	scheduleClear func(string)

	// keychain access, injectable for tests. readSecret yields
	// mygo.ErrSecretNotFound (or any error) when nothing is stored.
	readSecret  func() ([]byte, error)
	writeSecret func([]byte) error
	dropSecret  func() error
}

func newPanelState(vaultPath, settingsPath string) *panelState {
	return newPanelStateWith(vaultPath, settingsPath,
		func() ([]byte, error) { return mygo.Secrets.Get(secretKey) },
		func(v []byte) error { return mygo.Secrets.Set(secretKey, v) },
		func() error { return mygo.Secrets.Delete(secretKey) })
}

// newPanelStateWith is the testable constructor: the credential-store
// access is injected (production passes mygo.Secrets wrappers).
func newPanelStateWith(vaultPath, settingsPath string,
	readSecret func() ([]byte, error), writeSecret func([]byte) error, dropSecret func() error,
) *panelState {
	s := &panelState{
		vaultPath:    vaultPath,
		settingsPath: settingsPath,
		now:          time.Now(),
		lastActive:   time.Now(),
		exists:       fileExists(vaultPath),
		settings:     loadSettings(settingsPath),
		readSecret:   readSecret,
		writeSecret:  writeSecret,
		dropSecret:   dropSecret,
	}
	s.writeClip = func(text string) { mygo.Clipboard.WriteText(text) }
	s.scheduleClear = func(code string) {
		if !s.settings.ClearClipboard {
			return
		}
		go func() {
			time.Sleep(clipboardClearIn)
			// Only clear what we put there; never clobber a later copy.
			if mygo.Clipboard.ReadText() == code {
				mygo.Clipboard.WriteText("")
			}
		}()
	}
	s.loadVault()
	s.filter()
	return s
}

// loadVault reads the vault file at startup. A plaintext vault (or a
// missing file — first run) is usable at once; an encrypted one stays
// locked until unlock.
func (s *panelState) loadVault() {
	data, err := os.ReadFile(s.vaultPath)
	if err != nil {
		s.unlocked = true // first run: an empty plain vault, created on first save
		return
	}
	if vault.IsEncrypted(data) {
		s.encrypted = true
		s.tryAutoUnlock(data)
		return // auto-unlock may have opened it; otherwise locked
	}
	v, err := vault.Unmarshal(data)
	if err != nil {
		s.err = "金库文件无法读取:" + err.Error()
		return
	}
	s.unlocked = true
	s.accounts = v.Accounts
}

// saveSettings persists the settings; failures surface in the panel.
func (s *panelState) saveSettings() {
	if err := saveSettings(s.settingsPath, s.settings); err != nil {
		s.err = "保存设置失败:" + err.Error()
	}
}

// touch marks activity for the auto-lock idle timer.
func (s *panelState) touch() { s.lastActive = time.Now() }

// autoHideDue reports whether the panel should auto-close after a copy.
func (s *panelState) autoHideDue(now time.Time) bool {
	return s.unlocked && s.settings.HideAfterCopy && !s.hideAt.IsZero() && now.After(s.hideAt)
}

// autoLockDue reports whether the unlocked vault should lock now. Only an
// encrypted vault can lock.
func (s *panelState) autoLockDue(now time.Time) bool {
	return s.encrypted && s.unlocked && s.settings.AutoLock &&
		now.Sub(s.lastActive) >= time.Duration(s.settings.AutoLockMinutes)*time.Minute
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// filter recomputes the visible accounts from query and derives the
// panel rows: grouped by issuer in the full view (setting on), flat in
// search results and manage mode.
func (s *panelState) filter() {
	q := strings.ToLower(strings.TrimSpace(s.query))
	s.filtered = s.filtered[:0]
	for _, a := range s.accounts {
		if q == "" ||
			strings.Contains(strings.ToLower(a.Issuer), q) ||
			strings.Contains(strings.ToLower(a.Name), q) {
			s.filtered = append(s.filtered, a)
		}
	}
	grouped := s.settings.ShowGroups && q == "" && !s.manageMode
	s.rows = buildRows(s.filtered, grouped)
}

// unlock decrypts the vault with the unlock input's password. A plaintext
// vault has nothing to unlock and loads directly.
func (s *panelState) unlock() error {
	data, err := vault.LoadFile(s.vaultPath)
	if err != nil {
		return err
	}
	var v *vault.Vault
	if vault.IsEncrypted(data) {
		v, err = vault.OpenVault(data, s.unlockPw)
	} else {
		v, err = vault.Unmarshal(data)
	}
	if err != nil {
		return err
	}
	s.encrypted = vault.IsEncrypted(data)
	s.unlocked = true
	s.accounts = v.Accounts
	if s.encrypted {
		s.masterPw = s.unlockPw
	}
	s.unlockPw = ""
	s.err = ""
	s.filter()
	return nil
}

// tryAutoUnlock opens an encrypted vault with the keychain-stored master
// password, if the setting is on and a secret is stored. A stale secret
// (the password changed elsewhere) is dropped so the next launch asks
// for it again instead of failing forever.
func (s *panelState) tryAutoUnlock(data []byte) {
	if !s.settings.AutoUnlock {
		return
	}
	pw, err := s.readSecret()
	if err != nil || len(pw) == 0 {
		return // nothing stored or store unavailable: stay locked
	}
	v, err := vault.OpenVault(data, string(pw))
	if err != nil {
		if errors.Is(err, vault.ErrWrongPassword) {
			_ = s.dropSecret() // stale: the vault password changed
			s.settings.AutoUnlock = false
			s.saveSettings()
		}
		return
	}
	s.unlocked = true
	s.accounts = v.Accounts
	s.masterPw = string(pw)
	s.filter()
}

// SetAutoUnlock turns keychain auto-unlock on or off. Enabling stores the
// in-memory master password; disabling deletes it.
func (s *panelState) SetAutoUnlock(on bool) error {
	if !s.encrypted {
		return errors.New("先开启本地加密才能启用自动解锁")
	}
	if on {
		if !s.unlocked || s.masterPw == "" {
			return errors.New("解锁后才能启用自动解锁")
		}
		if err := s.writeSecret([]byte(s.masterPw)); err != nil {
			return fmt.Errorf("写入钥匙串失败:%w", err)
		}
	} else {
		if err := s.dropSecret(); err != nil {
			return fmt.Errorf("清除钥匙串失败:%w", err)
		}
	}
	s.settings.AutoUnlock = on
	s.saveSettings()
	return nil
}

// syncStoredSecret refreshes the keychain copy after a master-password
// change so auto-unlock keeps working. Errors surface but never block
// the password change itself.
func (s *panelState) syncStoredSecret() {
	if s.settings.AutoUnlock && s.encrypted && s.masterPw != "" {
		if err := s.writeSecret([]byte(s.masterPw)); err != nil {
			s.err = "自动解锁密钥更新失败:" + err.Error()
		}
	}
}

// lock forgets the decrypted vault; the master password is asked again.
// A plaintext vault cannot lock.
func (s *panelState) lock() {
	if !s.encrypted {
		return
	}
	s.unlocked = false
	s.accounts = nil
	s.masterPw = ""
	s.manageMode = false
	s.unlockPw = ""
	s.err = ""
	s.query = ""
	s.copiedLabel = ""
	s.filter()
}

// EnableEncryption sets a master password and rewrites the vault in
// encrypted form. Requires >= minMasterLen characters, twice.
func (s *panelState) EnableEncryption(pw, pw2 string) error {
	if s.encrypted {
		return errors.New("本地加密已开启")
	}
	if len(pw) < minMasterLen {
		return fmt.Errorf("主密码至少需要 %d 个字符", minMasterLen)
	}
	if pw != pw2 {
		return errors.New("两次输入的主密码不一致")
	}
	s.encrypted = true
	s.masterPw = pw
	if err := s.save(); err != nil {
		s.encrypted = false
		s.masterPw = ""
		return err
	}
	s.err = ""
	s.touch()
	return nil
}

// DisableEncryption verifies the master password and rewrites the vault
// as plaintext.
func (s *panelState) DisableEncryption(pw string) error {
	if !s.encrypted {
		return errors.New("本地加密未开启")
	}
	if pw != s.masterPw {
		return errors.New("主密码不正确")
	}
	s.encrypted = false
	s.masterPw = ""
	if err := s.save(); err != nil {
		s.encrypted = true
		s.masterPw = pw
		return err
	}
	if s.settings.AutoUnlock {
		_ = s.dropSecret()
		s.settings.AutoUnlock = false
		s.saveSettings()
	}
	s.err = ""
	return nil
}

// ChangeMasterPassword verifies the old password and re-encrypts the
// vault under a new one.
func (s *panelState) ChangeMasterPassword(oldPw, newPw string) error {
	if !s.encrypted {
		return errors.New("本地加密未开启")
	}
	if oldPw != s.masterPw {
		return errors.New("主密码不正确")
	}
	if len(newPw) < minMasterLen {
		return fmt.Errorf("新主密码至少需要 %d 个字符", minMasterLen)
	}
	prev := s.masterPw
	s.masterPw = newPw
	if err := s.save(); err != nil {
		s.masterPw = prev
		return err
	}
	s.syncStoredSecret()
	s.err = ""
	return nil
}

// copy writes row i's current code to the clipboard and schedules the
// delayed clipboard clear.
func (s *panelState) copy(i int) {
	if i < 0 || i >= len(s.filtered) {
		return
	}
	code, err := s.filtered[i].Code(s.now)
	if err != nil {
		return
	}
	s.copiedLabel, s.copiedAt = accountLabel(s.filtered[i]), time.Now()
	s.touch()
	if s.settings.HideAfterCopy {
		s.hideAt = time.Now().Add(2 * time.Second)
	}
	s.writeClip(code)
	s.scheduleClear(code)
}

func (s *panelState) copyHintVisible(now time.Time) bool {
	return s.copiedLabel != "" && now.Sub(s.copiedAt) < copiedHintFor
}

// setupHint is the soft, non-blocking hint shown while typing a new
// password (弱密码仅提示).
func passwordHint(pw, pw2 string) string {
	switch {
	case pw == "" && pw2 == "":
		return ""
	case len(pw) > 0 && len(pw) < minMasterLen:
		return "密码建议至少 8 位"
	case pw2 != "" && pw != pw2:
		return "两次输入不一致"
	}
	return ""
}

func accountLabel(a otp.Account) string {
	if a.Issuer != "" {
		return a.Issuer + ":" + a.Name
	}
	return a.Name
}

func unlockErrorText(err error) string {
	switch {
	case errors.Is(err, vault.ErrWrongPassword):
		return "密码错误,请重试"
	case errors.Is(err, vault.ErrCorrupt):
		return "金库文件已损坏"
	case errors.Is(err, vault.ErrNotFound):
		return "找不到金库文件"
	}
	return "解锁失败:" + err.Error()
}

// save persists the vault: encrypted under the held master password, or
// as plaintext when local encryption is off.
func (s *panelState) save() error {
	if s.encrypted && s.masterPw == "" {
		return errors.New("金库未解锁")
	}
	if err := os.MkdirAll(filepath.Dir(s.vaultPath), 0o700); err != nil {
		return err
	}
	v := &vault.Vault{Version: vault.Version, Accounts: s.accounts}
	if s.encrypted {
		data, err := vault.SealVault(v, s.masterPw, vault.DefaultParams())
		if err != nil {
			return err
		}
		if err := vault.SaveFile(s.vaultPath, data); err != nil {
			return err
		}
	} else if err := vault.SavePlain(s.vaultPath, v); err != nil {
		return err
	}
	s.exists = true
	return nil
}

// sameAccount is the full-value identity used by manage actions to map a
// visible row back to its slot in the vault's order.
func sameAccount(a, b otp.Account) bool {
	return a.Type == b.Type && a.Issuer == b.Issuer && a.Name == b.Name &&
		bytes.Equal(a.Secret, b.Secret) && a.Algorithm == b.Algorithm &&
		a.Digits == b.Digits && a.Period == b.Period && a.Counter == b.Counter
}

func (s *panelState) accountIndex(acc otp.Account) int {
	for i, a := range s.accounts {
		if sameAccount(a, acc) {
			return i
		}
	}
	return -1
}

// AddAccount appends an account and persists the vault.
func (s *panelState) AddAccount(acc otp.Account) error {
	s.accounts = append(s.accounts, acc)
	if err := s.save(); err != nil {
		s.accounts = s.accounts[:len(s.accounts)-1]
		return err
	}
	s.filter()
	return nil
}

// UpdateAccount replaces old (by value) with acc and persists.
func (s *panelState) UpdateAccount(old, acc otp.Account) error {
	i := s.accountIndex(old)
	if i < 0 {
		return errors.New("要编辑的账号不存在")
	}
	prev := s.accounts[i]
	s.accounts[i] = acc
	if err := s.save(); err != nil {
		s.accounts[i] = prev
		return err
	}
	s.filter()
	return nil
}

// RemoveAccount deletes an account (by value) and persists.
func (s *panelState) RemoveAccount(acc otp.Account) error {
	i := s.accountIndex(acc)
	if i < 0 {
		return nil
	}
	s.accounts = append(s.accounts[:i], s.accounts[i+1:]...)
	if err := s.save(); err != nil {
		s.accounts = append(s.accounts[:i], append([]otp.Account{acc}, s.accounts[i:]...)...)
		return err
	}
	s.filter()
	return nil
}

// MoveAccount moves an account up (delta -1) or down (+1) and persists.
func (s *panelState) MoveAccount(acc otp.Account, delta int) error {
	i := s.accountIndex(acc)
	j := i + delta
	if i < 0 || j < 0 || j >= len(s.accounts) {
		return nil
	}
	s.accounts[i], s.accounts[j] = s.accounts[j], s.accounts[i]
	if err := s.save(); err != nil {
		s.accounts[i], s.accounts[j] = s.accounts[j], s.accounts[i]
		return err
	}
	s.filter()
	return nil
}

// listRow is one row of the panel list: a group header or an account.
type listRow struct {
	header bool
	text   string // header title
	accIdx int    // index into accounts (account rows)
	ord    int    // account ordinal, for ⇧⌘N hints (headers: -1)
}

// buildRows derives the panel rows: grouped by issuer with sticky
// headers, or flat. Accounts without an issuer fall under "未分组".
func buildRows(accounts []otp.Account, grouped bool) []listRow {
	rows := make([]listRow, 0, len(accounts)+4)
	ord := 0
	if !grouped {
		for i := range accounts {
			rows = append(rows, listRow{accIdx: i, ord: ord})
			ord++
		}
		return rows
	}
	last := "\x00sentinel"
	for i, a := range accounts {
		key := a.Issuer
		if key == "" {
			key = "未分组"
		}
		if key != last {
			rows = append(rows, listRow{header: true, text: key})
			last = key
		}
		rows = append(rows, listRow{accIdx: i, ord: ord})
		ord++
	}
	return rows
}

// applyReorder moves the given row indices to land before index `to` in
// the pre-drag order (the semantics of mygo ListState.Reorder). Pure and
// testable; the view callback persists the result.
func applyReorder(accounts []otp.Account, rows []int, to int) []otp.Account {
	out := append([]otp.Account(nil), accounts...)
	if len(rows) == 0 {
		return out
	}
	sortedRows := append([]int(nil), rows...)
	slices.Sort(sortedRows)
	var moved []otp.Account
	for i := len(sortedRows) - 1; i >= 0; i-- {
		r := sortedRows[i]
		if r < 0 || r >= len(out) {
			return accounts // out of range: refuse rather than mangle
		}
		moved = append([]otp.Account{out[r]}, moved...)
		out = slices.Delete(out, r, r+1)
	}
	shift := 0
	for _, r := range sortedRows {
		if r < to {
			shift++
		}
	}
	dst := to - shift
	if dst < 0 {
		dst = 0
	}
	if dst > len(out) {
		dst = len(out)
	}
	out = append(out[:dst], append(moved, out[dst:]...)...)
	return out
}

// ImportURIs parses otpauth:// URIs separated by newlines (or other
// whitespace), skipping duplicates — same secret+issuer+name — and
// malformed lines. Returns added, skipped-duplicate and bad-line counts.
func (s *panelState) ImportURIs(text string) (added, skipped, bad int, err error) {
	split := func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ',' || r == ';'
	}
	var fresh []otp.Account
	for _, line := range strings.FieldsFunc(text, split) {
		if strings.HasPrefix(strings.ToLower(line), "otpauth-migration://") {
			// Google Authenticator export: one URI carries many accounts.
			migration, err := otp.ParseMigrationURI(line)
			if err != nil {
				bad++
				continue
			}
			for _, acc := range migration {
				if s.accountIndex(acc) >= 0 || containsAccount(fresh, acc) {
					skipped++
					continue
				}
				fresh = append(fresh, acc)
			}
			continue
		}
		acc, perr := otp.ParseURI(line)
		if perr != nil {
			bad++
			continue
		}
		if s.accountIndex(acc) >= 0 || containsAccount(fresh, acc) {
			skipped++
			continue
		}
		fresh = append(fresh, acc)
	}
	if len(fresh) > 0 {
		s.accounts = append(s.accounts, fresh...)
		if err = s.save(); err != nil {
			s.accounts = s.accounts[:len(s.accounts)-len(fresh)]
			return 0, 0, 0, err
		}
		s.filter()
	}
	return len(fresh), skipped, bad, nil
}

func containsAccount(list []otp.Account, acc otp.Account) bool {
	for _, a := range list {
		if sameAccount(a, acc) {
			return true
		}
	}
	return false
}

// reportErr surfaces a mutation error in the panel's menu row.
func (s *panelState) reportErr(err error) {
	if err != nil {
		s.err = err.Error()
	}
}

// toggleManage enters (clearing the search, so rows map 1:1 to the vault
// order) or leaves the manage mode with per-row edit/move/delete actions.
func (s *panelState) toggleManage() {
	s.manageMode = !s.manageMode
	if s.manageMode {
		s.query = ""
	}
	s.filter()
}

// centralCountdown returns the shared remaining seconds of standard 30s
// TOTP windows, and whether any such account is visible.
func centralCountdown(accounts []otp.Account, now time.Time) (uint32, bool) {
	for _, a := range accounts {
		if a.Type == otp.TOTP && a.Period == otp.DefaultPeriod {
			return a.SecondsRemaining(now), true
		}
	}
	return 0, false
}
