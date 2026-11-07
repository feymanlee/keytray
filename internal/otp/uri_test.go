package otp

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseURIFull(t *testing.T) {
	a, err := ParseURI("otpauth://totp/Example:alice@example.com?issuer=Example&secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60")
	if err != nil {
		t.Fatal(err)
	}
	want := Account{
		Type:      TOTP,
		Issuer:    "Example",
		Name:      "alice@example.com",
		Secret:    mustSecret(t, "JBSWY3DPEHPK3PXP"),
		Algorithm: "SHA256",
		Digits:    8,
		Period:    60,
	}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("got %+v, want %+v", a, want)
	}
}

func TestParseURIDefaults(t *testing.T) {
	a, err := ParseURI("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if a.Issuer != "" || a.Algorithm != "SHA1" || a.Digits != 6 || a.Period != 30 {
		t.Errorf("defaults not applied: %+v", a)
	}
}

func TestParseURIIssuerFromLabel(t *testing.T) {
	a, err := ParseURI("otpauth://totp/GitHub:feyman?secret=JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if a.Issuer != "GitHub" || a.Name != "feyman" {
		t.Errorf("label issuer not picked up: %+v", a)
	}
}

func TestParseURIHOTPCounter(t *testing.T) {
	a, err := ParseURI("otpauth://hotp/Example:bob?secret=JBSWY3DPEHPK3PXP&counter=42")
	if err != nil {
		t.Fatal(err)
	}
	if a.Type != HOTP || a.Counter != 42 || a.Period != 0 {
		t.Errorf("got %+v", a)
	}
}

func TestParseURITolerantSecret(t *testing.T) {
	for _, s := range []string{
		"jbswy3dpehpk3pxp",    // lower case
		"JBSWY3DPEHPK3PXP=",   // padded
		"JBSWY 3DPE HPK3 PXP", // spaced (as some providers show it)
	} {
		if _, err := ParseURI("otpauth://totp/a?secret=" + strings.ReplaceAll(s, " ", "%20")); err != nil {
			t.Errorf("secret %q: %v", s, err)
		}
	}
}

func TestParseURIErrors(t *testing.T) {
	bad := []string{
		"",
		"https://example.com/otpauth",
		"otpauth://steam/alice?secret=JBSWY3DPEHPK3PXP",
		"otpauth://totp/alice",               // missing secret
		"otpauth://totp/alice?secret=1!2!3!", // not base32
		"otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=5",
		"otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
		"otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&period=0",
		"otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=abc",
		"otpauth://totp/?secret=JBSWY3DPEHPK3PXP", // empty label
	}
	for _, s := range bad {
		if a, err := ParseURI(s); err == nil {
			t.Errorf("ParseURI(%q) = %+v, want error", s, a)
		}
	}
}

func TestURIRoundTrip(t *testing.T) {
	accounts := []Account{
		{Type: TOTP, Issuer: "GitHub", Name: "feyman", Secret: []byte("hello world keytray")},
		{Type: TOTP, Name: "bare@example.com", Secret: []byte("s2")},
		{Type: TOTP, Issuer: "A:B 康", Name: "张三 test/x", Secret: []byte("s3"), Algorithm: "SHA512", Digits: 8, Period: 60},
		{Type: HOTP, Issuer: "OldBank", Name: "bob", Secret: []byte("s4"), Counter: 7},
	}
	for i, a := range accounts {
		a.Normalize()
		uri, err := a.URI()
		if err != nil {
			t.Fatalf("account %d: %v", i, err)
		}
		if !strings.HasPrefix(uri, "otpauth://") {
			t.Fatalf("account %d: bad scheme in %q", i, uri)
		}
		got, err := ParseURI(uri)
		if err != nil {
			t.Fatalf("account %d: re-parse %q: %v", i, uri, err)
		}
		if !reflect.DeepEqual(got, a) {
			t.Errorf("account %d round trip mismatch:\n uri %s\n got %+v\nwant %+v", i, uri, got, a)
		}
	}
}

func TestURIOmitsDefaults(t *testing.T) {
	a := Account{Type: TOTP, Issuer: "GitHub", Name: "feyman", Secret: []byte("hello world keytray")}
	a.Normalize()
	uri, err := a.URI()
	if err != nil {
		t.Fatal(err)
	}
	for _, param := range []string{"algorithm", "digits", "period", "counter"} {
		if strings.Contains(uri, param+"=") {
			t.Errorf("URI %q should not contain default param %q", uri, param)
		}
	}
	// Secret is always present; issuer param mirrors the label.
	if !strings.Contains(uri, "secret=") || !strings.Contains(uri, "issuer=GitHub") {
		t.Errorf("URI %q missing secret/issuer", uri)
	}
}

func mustSecret(t *testing.T, s string) []byte {
	t.Helper()
	b, err := DecodeSecret(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
