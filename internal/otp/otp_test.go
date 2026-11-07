package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// RFC 4226 Appendix D: secret = ASCII "12345678901234567890", 6 digits.
func TestHOTPRFC4226(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	a := Account{Type: HOTP, Name: "rfc", Secret: []byte("12345678901234567890")}
	a.Normalize()
	for i, w := range want {
		got, err := a.HOTPCode(uint64(i))
		if err != nil {
			t.Fatalf("counter %d: %v", i, err)
		}
		if got != w {
			t.Errorf("counter %d: got %s, want %s", i, got, w)
		}
	}
}

// RFC 6238 Appendix B: 8 digits, T0=0, X=30.
func TestTOTPRFC6238(t *testing.T) {
	tests := []struct {
		alg    string
		secret string
		want   map[int64]string
	}{
		{
			"SHA1", "12345678901234567890",
			map[int64]string{
				59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
				1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130",
			},
		},
		{
			"SHA256", "12345678901234567890123456789012",
			map[int64]string{
				59: "46119246", 1111111109: "68084774", 1111111111: "67062674",
				1234567890: "91819424", 2000000000: "90698825", 20000000000: "77737706",
			},
		},
		{
			"SHA512", "1234567890123456789012345678901234567890123456789012345678901234",
			map[int64]string{
				59: "90693936", 1111111109: "25091201", 1111111111: "99943326",
				1234567890: "93441116", 2000000000: "38618901", 20000000000: "47863826",
			},
		},
	}
	for _, tt := range tests {
		a := Account{Type: TOTP, Name: "rfc", Secret: []byte(tt.secret), Algorithm: tt.alg, Digits: 8, Period: 30}
		for unix, w := range tt.want {
			got, err := a.TOTPCode(time.Unix(unix, 0).UTC())
			if err != nil {
				t.Fatalf("%s @%d: %v", tt.alg, unix, err)
			}
			if got != w {
				t.Errorf("%s @%d: got %s, want %s", tt.alg, unix, got, w)
			}
		}
	}
}

// 6-digit TOTP at T=59 must equal RFC 4226 counter 1 ("287082"), since 59/30 == 1.
func TestTOTPSixDigitsMatchesRFC4226(t *testing.T) {
	a := Account{Type: TOTP, Name: "rfc", Secret: []byte("12345678901234567890"), Digits: 6}
	a.Normalize()
	got, err := a.TOTPCode(time.Unix(59, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Errorf("got %s, want 287082", got)
	}
}

func TestTOTPRespectsPeriod(t *testing.T) {
	a := Account{Type: TOTP, Name: "rfc", Secret: []byte("12345678901234567890"), Period: 60}
	a.Normalize()
	// T=119 with period 60 is counter 1 == RFC 4226 counter 1.
	got, err := a.TOTPCode(time.Unix(119, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Errorf("got %s, want 287082", got)
	}
}

func TestCodeDispatch(t *testing.T) {
	totp := Account{Type: TOTP, Name: "rfc", Secret: []byte("12345678901234567890")}
	totp.Normalize()
	hotp := Account{Type: HOTP, Name: "rfc", Secret: []byte("12345678901234567890"), Counter: 9}
	hotp.Normalize()
	now := time.Unix(59, 0).UTC()

	got, err := totp.Code(now)
	if err != nil || got != "287082" {
		t.Errorf("TOTP Code = %q, %v; want 287082", got, err)
	}
	got, err = hotp.Code(now) // HOTP ignores the clock.
	if err != nil || got != "520489" {
		t.Errorf("HOTP Code = %q, %v; want 520489", got, err)
	}
}

func TestSecondsRemaining(t *testing.T) {
	a := Account{Type: TOTP, Name: "rfc", Secret: []byte("12345678901234567890"), Period: 30}
	a.Normalize()
	if got := a.SecondsRemaining(time.Unix(59, 0).UTC()); got != 1 {
		t.Errorf("got %d, want 1", got)
	}
	if got := a.SecondsRemaining(time.Unix(120, 0).UTC()); got != 30 {
		t.Errorf("got %d, want 30", got)
	}
}

func TestFormatCode(t *testing.T) {
	cases := map[string]string{
		"123456":   "123 456",
		"12345678": "1234 5678",
		"1234567":  "1234567",
		"":         "",
	}
	for in, want := range cases {
		if got := FormatCode(in); got != want {
			t.Errorf("FormatCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidRejectsBadAccounts(t *testing.T) {
	cases := []Account{
		{Type: TOTP, Name: "x", Secret: []byte("k"), Digits: 5},
		{Type: TOTP, Name: "x", Secret: []byte("k"), Digits: 9},
		{Type: TOTP, Name: "x", Secret: []byte("k"), Algorithm: "MD5"},
		{Type: TOTP, Name: "x", Secret: nil},
		{Type: "XYZ", Name: "x", Secret: []byte("k")},
	}
	for i, a := range cases {
		a.Normalize()
		if err := a.Valid(); err == nil {
			t.Errorf("case %d: expected error for %+v", i, a)
		}
	}
}

func TestAccountJSONRoundTrip(t *testing.T) {
	secret := []byte("hello world keytray")
	in := Account{Type: TOTP, Issuer: "GitHub", Name: "feyman", Secret: secret, Algorithm: "SHA256", Digits: 8, Period: 60}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Account
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}

	// Defaults are materialized on marshal and restored on unmarshal.
	minimal := Account{Type: TOTP, Name: "a", Secret: secret}
	data, err = json.Marshal(minimal)
	if err != nil {
		t.Fatal(err)
	}
	var got Account
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Algorithm != "SHA1" || got.Digits != 6 || got.Period != 30 {
		t.Errorf("defaults not applied: %+v", got)
	}
}

func TestAccountJSONRejectsBadSecret(t *testing.T) {
	var a Account
	err := json.Unmarshal([]byte(`{"type":"TOTP","name":"x","secret":"!!!not-base32!!!"}`), &a)
	if err == nil {
		t.Error("expected error for invalid base32 secret")
	}
}

// --- Steam Guard ---

// 独立实现(不经 otp 包)对 RFC 测试密钥算一遍 Steam 码,校验字符表映射。
func TestSteamCodeMatchesIndependentImpl(t *testing.T) {
	secret := []byte("12345678901234567890")
	steam := Account{Type: TOTP, Issuer: "Steam", Name: "player", Secret: secret}
	steam.Normalize()
	if steam.Digits != 5 {
		t.Fatalf("steam digits = %d, want 5", steam.Digits)
	}

	// 参考:用 stdlib 直接按 Steam 算法算 T=59(counter=1)的码。
	mac := hmac.New(sha1.New, secret)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], 1)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	full := uint32(sum[offset]&0x7f)<<24 | uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	chars := "23456789BCDFGHJKMNPQRTVWXY"
	want := make([]byte, 5)
	for i := range want {
		want[i] = chars[full%uint32(len(chars))]
		full /= uint32(len(chars))
	}

	got, err := steam.Code(time.Unix(59, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("steam code = %q, want %q", got, want)
	}
	for _, c := range got {
		if !strings.ContainsRune(chars, c) {
			t.Errorf("char %q not in Steam alphabet", c)
		}
	}
}

func TestSteamNormalizationAndRoundTrip(t *testing.T) {
	// issuer Steam:非 5 位声明被归一为 5;URI 往返保持 Steam 编码约定。
	a, err := ParseURI("otpauth://totp/Steam:player?secret=JBSWY3DPEHPK3PXP&issuer=Steam&digits=6")
	if err != nil {
		t.Fatal(err)
	}
	if !a.IsSteam() || a.Digits != 5 {
		t.Fatalf("parsed: %+v", a)
	}
	uri, err := a.URI()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uri, "digits=") {
		t.Errorf("steam URI should omit digits: %q", uri)
	}
	got, err := ParseURI(uri)
	if err != nil || !reflect.DeepEqual(got, a) {
		t.Errorf("round trip: got %+v err %v", got, err)
	}

	// 非 Steam issuer 的 5 位仍然非法。
	bad := Account{Type: TOTP, Issuer: "Other", Name: "x", Secret: []byte("k"), Digits: 5}
	bad.Normalize()
	if err := bad.Valid(); err == nil {
		t.Error("5 digits without Steam issuer must stay invalid")
	}
	// FormatCode 不分组 5 位码。
	if FormatCode("ABCDE") != "ABCDE" {
		t.Error("steam code should not be grouped")
	}
}
