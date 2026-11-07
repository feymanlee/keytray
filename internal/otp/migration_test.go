package otp

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"
	"time"
)

var testTime = time.Unix(59, 0).UTC() // any instant; Code() just must not error

func mustEncodeMigration(t *testing.T, accounts []Account) string {
	t.Helper()
	uri, err := MigrationURI(accounts)
	if err != nil {
		t.Fatal(err)
	}
	return uri
}

func TestMigrationRoundTrip(t *testing.T) {
	in := []Account{
		{Type: TOTP, Issuer: "GitHub", Name: "feyman", Secret: []byte("hello-github-key")},
		{Type: TOTP, Issuer: "Tencent Cloud", Name: "100053131378", Secret: []byte("tencent-secret!!"), Algorithm: "SHA256", Digits: 8},
		{Type: HOTP, Issuer: "OldBank", Name: "bob", Secret: []byte("hotp-secret-123"), Counter: 7},
	}
	uri := mustEncodeMigration(t, in)

	got, err := ParseMigrationURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(in) {
		t.Fatalf("got %d accounts, want %d", len(got), len(in))
	}
	for i := range in {
		want := in[i]
		want.Normalize() // decoding materializes defaults
		if !reflect.DeepEqual(got[i], want) {
			t.Errorf("account %d:\n got %+v\nwant %+v", i, got[i], want)
		}
	}
}

// A hand-assembled payload (not produced by our encoder): two entries plus
// unknown fields that must be skipped, and one MD5 entry that must be
// dropped. Layout mirrors real GA exports.
func TestMigrationHandCraftedFixture(t *testing.T) {
	var entry1 []byte // GitHub:feyman, SHA1, 6, TOTP
	entry1 = appendField(entry1, 1, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	entry1 = appendStringField(entry1, 2, "feyman")
	entry1 = appendStringField(entry1, 3, "GitHub")
	entry1 = appendVarintField(entry1, 4, 1) // SHA1
	entry1 = appendVarintField(entry1, 5, 1) // SIX
	entry1 = appendVarintField(entry1, 6, 2) // TOTP
	entry1 = appendVarintField(entry1, 99, 5)

	var entry2 []byte // bob, HOTP counter 7, unspecified algorithm/digits
	entry2 = appendField(entry2, 1, []byte("hotp-secret"))
	entry2 = appendStringField(entry2, 2, "bob")
	entry2 = appendVarintField(entry2, 6, 1) // HOTP
	entry2 = appendVarintField(entry2, 7, 7)

	var entry3 []byte // MD5: unsupported, must be dropped
	entry3 = appendField(entry3, 1, []byte("md5-secret"))
	entry3 = appendStringField(entry3, 2, "legacy")
	entry3 = appendVarintField(entry3, 4, 4)
	entry3 = appendVarintField(entry3, 6, 2)

	var payload []byte
	payload = appendField(payload, 1, entry1)
	payload = appendField(payload, 1, entry2)
	payload = appendField(payload, 1, entry3)
	payload = appendVarintField(payload, 2, 1)                  // version
	payload = appendVarintField(payload, 3, 1)                  // batch_size
	payload = appendVarintField(payload, 4, 0)                  // batch_index
	payload = appendStringField(payload, 5, "batch1")           // batch_id
	payload = appendField(payload, 42, []byte("unknown-field")) // skipped

	uri := "otpauth-migration://offline?data=" + base64.StdEncoding.EncodeToString(payload)
	got, err := ParseMigrationURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d accounts, want 2 (MD5 dropped): %+v", len(got), got)
	}

	a := got[0]
	if a.Type != TOTP || a.Issuer != "GitHub" || a.Name != "feyman" ||
		!bytes.Equal(a.Secret, []byte{1, 2, 3, 4, 5, 6, 7, 8}) ||
		a.Algorithm != "SHA1" || a.Digits != 6 {
		t.Errorf("entry1: %+v", a)
	}
	b := got[1]
	if b.Type != HOTP || b.Counter != 7 || b.Issuer != "" ||
		!bytes.Equal(b.Secret, []byte("hotp-secret")) ||
		b.Algorithm != "SHA1" || b.Digits != 6 { // unspecified → defaults
		t.Errorf("entry2: %+v", b)
	}
	for i, acc := range got {
		if _, err := acc.Code(testTime); err != nil {
			t.Errorf("account %d generates no code: %v", i, err)
		}
	}
}

func TestMigrationErrors(t *testing.T) {
	cases := []string{
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",   // wrong scheme
		"otpauth-migration://offline",                // no data
		"otpauth-migration://offline?data=%21%21%21", // bad base64
		"otpauth-migration://offline?data=Cw",        // truncated field
	}
	for _, s := range cases {
		if _, err := ParseMigrationURI(s); err == nil {
			t.Errorf("ParseMigrationURI(%q) should fail", s)
		}
	}
	// An empty data value is a valid, zero-account payload.
	if got, err := ParseMigrationURI("otpauth-migration://offline?data="); err != nil || len(got) != 0 {
		t.Errorf("empty payload: got %d accounts, err %v", len(got), err)
	}
}

func TestMigrationTolerantBase64(t *testing.T) {
	accounts := []Account{{Type: TOTP, Issuer: "X", Name: "y", Secret: []byte("secret-bytes")}}
	uri := mustEncodeMigration(t, accounts)
	raw, err := base64.StdEncoding.DecodeString(uri[len("otpauth-migration://offline?data="):])
	if err != nil {
		t.Fatal(err)
	}
	variants := map[string]string{
		"padded-std": base64.StdEncoding.EncodeToString(raw),
		"raw-std":    base64.RawStdEncoding.EncodeToString(raw),
		"padded-url": base64.URLEncoding.EncodeToString(raw),
		"raw-url":    base64.RawURLEncoding.EncodeToString(raw),
	}
	for name, data := range variants {
		if _, err := ParseMigrationURI("otpauth-migration://offline?data=" + data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
