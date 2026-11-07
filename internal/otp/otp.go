// Package otp implements HOTP (RFC 4226) and TOTP (RFC 6238) code
// generation plus the otpauth:// key URI format used by authenticator apps.
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

// Type distinguishes the two OTP mechanisms.
type Type string

const (
	TOTP Type = "TOTP"
	HOTP Type = "HOTP"

	// DefaultPeriod is the standard TOTP period in seconds.
	DefaultPeriod = 30
	// DefaultDigits is the standard code length.
	DefaultDigits = 6
)

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// Account holds everything needed to generate codes for one entry. The zero
// value is not valid; fill the fields and call Normalize, or use ParseURI.
type Account struct {
	Type      Type
	Issuer    string
	Name      string
	Secret    []byte // raw key bytes (base32-encoded in URIs and JSON)
	Algorithm string // SHA1 (default), SHA256, SHA512
	Digits    int    // 6 (default) through 8
	Period    uint32 // TOTP only, seconds (default 30)
	Counter   uint64 // HOTP only
}

// steamChars is Steam Guard's code alphabet (no 0/1/8/9 or vowels).
const steamChars = "23456789BCDFGHJKMNPQRTVWXY"

// IsSteam reports whether the account uses Steam Guard encoding, by the
// de-facto convention of issuer "Steam" shared with other authenticators.
func (a Account) IsSteam() bool {
	return strings.EqualFold(strings.TrimSpace(a.Issuer), "Steam")
}

// Normalize fills zero fields with their defaults. Steam accounts always
// render 5 characters, regardless of what the URI claimed.
func (a *Account) Normalize() {
	if a.Type == "" {
		a.Type = TOTP
	}
	a.Type = Type(strings.ToUpper(string(a.Type)))
	a.Algorithm = strings.ToUpper(strings.TrimSpace(a.Algorithm))
	if a.Algorithm == "" {
		a.Algorithm = "SHA1"
	}
	if a.Digits == 0 {
		a.Digits = DefaultDigits
	}
	if a.Type == TOTP && a.Period == 0 {
		a.Period = DefaultPeriod
	}
	if a.IsSteam() {
		a.Digits = 5
	}
}

// Valid reports whether the account can generate codes. It expects a
// normalized account; call Normalize first for hand-built values.
func (a Account) Valid() error {
	switch a.Type {
	case TOTP, HOTP:
	default:
		return fmt.Errorf("otp: unknown type %q", a.Type)
	}
	if len(a.Secret) == 0 {
		return errors.New("otp: empty secret")
	}
	switch a.Algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		return fmt.Errorf("otp: unsupported algorithm %q", a.Algorithm)
	}
	if a.Digits < 5 || a.Digits > 8 || (!a.IsSteam() && a.Digits == 5) {
		return fmt.Errorf("otp: digits must be 6 through 8 (5 for Steam), got %d", a.Digits)
	}
	if a.Type == TOTP && a.Period == 0 {
		return errors.New("otp: period must be > 0")
	}
	return nil
}

func (a Account) hashFunc() (func() hash.Hash, error) {
	switch a.Algorithm {
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return sha1.New, nil
	}
}

func pow10(n int) uint32 {
	v := uint32(1)
	for i := 0; i < n; i++ {
		v *= 10
	}
	return v
}

// HOTPCode returns the RFC 4226 code for the given moving factor.
func (a Account) HOTPCode(counter uint64) (string, error) {
	if a.Digits < 5 || a.Digits > 8 || (!a.IsSteam() && a.Digits == 5) {
		return "", fmt.Errorf("otp: digits must be 6 through 8 (5 for Steam), got %d", a.Digits)
	}
	newHash, err := a.hashFunc()
	if err != nil {
		return "", err
	}
	mac := hmac.New(newHash, a.Secret)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	// RFC 4226 dynamic truncation.
	offset := sum[len(sum)-1] & 0x0f
	bin := uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	if a.IsSteam() {
		return steamCode(bin), nil
	}
	return fmt.Sprintf("%0*d", a.Digits, bin%pow10(a.Digits)), nil
}

// steamCode maps the truncated value onto Steam's 5-character alphabet.
func steamCode(bin uint32) string {
	out := make([]byte, 5)
	for i := range out {
		out[i] = steamChars[bin%uint32(len(steamChars))]
		bin /= uint32(len(steamChars))
	}
	return string(out)
}

// TOTPCode returns the TOTP code valid at t.
func (a Account) TOTPCode(t time.Time) (string, error) {
	period := a.Period
	if period == 0 {
		period = DefaultPeriod
	}
	return a.HOTPCode(uint64(t.Unix() / int64(period)))
}

// Code returns the account's current code: TOTP at now, or HOTP at Counter.
func (a Account) Code(now time.Time) (string, error) {
	if a.Type == HOTP {
		return a.HOTPCode(a.Counter)
	}
	return a.TOTPCode(now)
}

// SecondsRemaining reports how long the current TOTP window still runs.
func (a Account) SecondsRemaining(t time.Time) uint32 {
	period := int64(a.Period)
	if period == 0 {
		period = DefaultPeriod
	}
	return uint32(period - t.Unix()%period)
}

// FormatCode groups a code for display ("123456" -> "123 456").
// Other lengths are returned unchanged.
func FormatCode(code string) string {
	if len(code) != 6 && len(code) != 8 {
		return code
	}
	mid := len(code) / 2
	return code[:mid] + " " + code[mid:]
}

// EncodeSecret returns the base32 (unpadded) form used by otpauth URIs.
func EncodeSecret(b []byte) string {
	return base32NoPad.EncodeToString(b)
}

// DecodeSecret accepts padded/unpadded, lower-case, space-separated base32.
func DecodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, errors.New("empty secret")
	}
	b, err := base32NoPad.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("empty secret")
	}
	return b, nil
}

// MarshalJSON stores the secret as unpadded base32 and materialized defaults.
func (a Account) MarshalJSON() ([]byte, error) {
	n := a
	n.Normalize()
	type alias struct {
		Type      string `json:"type"`
		Issuer    string `json:"issuer,omitempty"`
		Name      string `json:"name"`
		Secret    string `json:"secret"`
		Algorithm string `json:"algorithm,omitempty"`
		Digits    int    `json:"digits,omitempty"`
		Period    uint32 `json:"period,omitempty"`
		Counter   uint64 `json:"counter,omitempty"`
	}
	return json.Marshal(alias{
		Type:      string(n.Type),
		Issuer:    n.Issuer,
		Name:      n.Name,
		Secret:    EncodeSecret(n.Secret),
		Algorithm: n.Algorithm,
		Digits:    n.Digits,
		Period:    n.Period,
		Counter:   n.Counter,
	})
}

// UnmarshalJSON decodes the vault's account form and applies defaults.
func (a *Account) UnmarshalJSON(data []byte) error {
	type alias struct {
		Type      string `json:"type"`
		Issuer    string `json:"issuer"`
		Name      string `json:"name"`
		Secret    string `json:"secret"`
		Algorithm string `json:"algorithm"`
		Digits    int    `json:"digits"`
		Period    uint32 `json:"period"`
		Counter   uint64 `json:"counter"`
	}
	var al alias
	if err := json.Unmarshal(data, &al); err != nil {
		return err
	}
	secret, err := DecodeSecret(al.Secret)
	if err != nil {
		return fmt.Errorf("otp: account %q: %w", al.Name, err)
	}
	*a = Account{
		Type:      Type(strings.ToUpper(strings.TrimSpace(al.Type))),
		Issuer:    al.Issuer,
		Name:      al.Name,
		Secret:    secret,
		Algorithm: strings.ToUpper(strings.TrimSpace(al.Algorithm)),
		Digits:    al.Digits,
		Period:    al.Period,
		Counter:   al.Counter,
	}
	a.Normalize()
	return a.Valid()
}
