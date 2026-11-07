package vault

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"keytray/internal/otp"
)

// fastParams keeps KDF cost negligible for tests.
func fastParams() Params {
	return Params{Time: 1, MemoryKB: 64, Threads: 1, Salt: bytes.Repeat([]byte{0xAB}, 16)}
}

func testVault(t *testing.T) *Vault {
	t.Helper()
	v := New()
	acc1, err := otp.ParseURI("otpauth://totp/GitHub:feyman?secret=JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	acc2, err := otp.ParseURI("otpauth://hotp/OldBank:bob?secret=JBSWY3DPEHPK3PXP&counter=7")
	if err != nil {
		t.Fatal(err)
	}
	v.Accounts = append(v.Accounts, acc1, acc2)
	return v
}

func TestSealOpenRoundTrip(t *testing.T) {
	in := testVault(t)
	file, err := SealVault(in, "correct horse battery staple", fastParams())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(file, magic) {
		t.Error("file does not start with magic")
	}
	out, err := OpenVault(file, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestOpenWrongPassword(t *testing.T) {
	file, err := SealVault(testVault(t), "right password", fastParams())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVault(file, "wrong password"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("got %v, want ErrWrongPassword", err)
	}
}

func TestOpenTampered(t *testing.T) {
	file, err := SealVault(testVault(t), "pw", fastParams())
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"ciphertext": flipLast(file),
		"salt":       flipAt(file, 10),
		"nonce":      flipAt(file, 40),
	}
	for name, tampered := range cases {
		if _, err := Open(tampered, "pw"); !errors.Is(err, ErrWrongPassword) {
			t.Errorf("%s tamper: got %v, want ErrWrongPassword", name, err)
		}
	}

	// Absurd KDF values must be rejected before any CPU is spent deriving
	// (otherwise a tampered time/memory field turns unlock into a hang).
	for name, tampered := range map[string][]byte{
		"kdf-time":   flipAt(file, 28), // ~4 billion iterations
		"kdf-memory": flipAt(file, 32), // multi-gigabyte allocation (MSB of KB)
	} {
		if _, err := Open(tampered, "pw"); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s tamper: got %v, want ErrCorrupt", name, err)
		}
	}
}

func TestOpenRejectsForeignInput(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("short"),
		[]byte(strings.Repeat("x", headerLen)), // wrong magic
		append([]byte("KTVAULT\x09"), bytes.Repeat([]byte{0}, 64)...), // future version
	}
	for i, file := range cases {
		if _, err := Open(file, "pw"); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	if _, err := Open(cases[3], "pw"); !errors.Is(err, ErrBadVersion) {
		t.Errorf("case 3: got %v, want ErrBadVersion", err)
	}
}

func TestSealGeneratesSaltAndFreshNonce(t *testing.T) {
	in := testVault(t)
	a, err := SealVault(in, "pw", Params{Time: 1, MemoryKB: 64, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealVault(in, "pw", Params{Time: 1, MemoryKB: 64, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[9:25], b[9:25]) {
		t.Error("salt should be random per vault")
	}
	if bytes.Equal(a[34:46], b[34:46]) {
		t.Error("nonce should be random per save")
	}
	for _, f := range [][]byte{a, b} {
		if _, err := OpenVault(f, "pw"); err != nil {
			t.Errorf("reopen: %v", err)
		}
	}
}

func TestSealRejectsBadParams(t *testing.T) {
	cases := []Params{
		{Time: 0, MemoryKB: 64, Threads: 1},
		{Time: 1, MemoryKB: 0, Threads: 1},
		{Time: 1, MemoryKB: 64, Threads: 0},
		{Time: 1, MemoryKB: 64, Threads: 1, Salt: []byte("too-short")},
	}
	for i, p := range cases {
		if _, err := Seal(nil, "pw", p); err == nil {
			t.Errorf("case %d: expected error for %+v", i, p)
		}
	}
}

func TestUnmarshalValidatesAccounts(t *testing.T) {
	// An account with a broken secret must not load, even though the
	// container JSON is well formed.
	bad := []byte(`{"version":1,"accounts":[{"type":"TOTP","name":"x","secret":"!!!"}]}`)
	if _, err := Unmarshal(bad); err == nil {
		t.Error("expected account validation error")
	}
	if _, err := Unmarshal([]byte(`{"accounts":[]}`)); err == nil {
		t.Error("expected missing-version error")
	}
	if _, err := Unmarshal([]byte(`{"version":99,"accounts":[]}`)); !errors.Is(err, ErrBadVersion) {
		t.Errorf("got %v, want ErrBadVersion", err)
	}
}

func flipLast(b []byte) []byte {
	out := bytes.Clone(b)
	out[len(out)-1] ^= 0xFF
	return out
}

func flipAt(b []byte, i int) []byte {
	out := bytes.Clone(b)
	out[i] ^= 0xFF
	return out
}

func TestIsEncryptedAndPlainRoundTrip(t *testing.T) {
	in := testVault(t)
	dir := t.TempDir()
	path := dir + "/vault.kt"
	if err := SavePlain(path, in); err != nil {
		t.Fatal(err)
	}
	data, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if IsEncrypted(data) {
		t.Error("plain vault detected as encrypted")
	}
	out, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Errorf("plain round trip:\n got %+v\nwant %+v", out, in)
	}

	// The encrypted form of the same vault must be detected as encrypted.
	enc, err := SealVault(in, "pw", fastParams())
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(enc) {
		t.Error("sealed vault not detected as encrypted")
	}
}
