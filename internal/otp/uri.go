package otp

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseURI parses an otpauth:// key URI (the Google Authenticator format):
//
//	otpauth://TYPE/Issuer:account?secret=...&issuer=...&algorithm=...&digits=...&period=...&counter=...
func ParseURI(s string) (Account, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return Account{}, fmt.Errorf("otp: invalid URI: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "otpauth") {
		return Account{}, errors.New("otp: not an otpauth:// URI")
	}

	var a Account
	switch strings.ToLower(u.Host) {
	case "totp":
		a.Type = TOTP
	case "hotp":
		a.Type = HOTP
	default:
		return Account{}, fmt.Errorf("otp: unknown OTP type %q", u.Host)
	}

	// Split issuer/name on the *encoded* label: an issuer may itself
	// contain a ':' and would then arrive percent-escaped (%3A).
	rawLabel := strings.TrimPrefix(u.EscapedPath(), "/")
	if rawLabel == "" && u.Opaque != "" {
		rawLabel = u.Opaque
	}
	var rawIssuer, rawName string
	if i := strings.IndexByte(rawLabel, ':'); i >= 0 {
		rawIssuer, rawName = rawLabel[:i], rawLabel[i+1:]
	} else {
		rawName = rawLabel
	}
	var labelIssuer string
	if rawIssuer != "" {
		labelIssuer, err = url.PathUnescape(rawIssuer)
		if err != nil {
			return Account{}, fmt.Errorf("otp: invalid label: %w", err)
		}
		labelIssuer = strings.TrimSpace(labelIssuer)
	}
	name, err := url.PathUnescape(rawName)
	if err != nil {
		return Account{}, fmt.Errorf("otp: invalid label: %w", err)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Account{}, errors.New("otp: empty account name in label")
	}

	q := u.Query()
	if q.Get("secret") == "" {
		return Account{}, errors.New("otp: missing secret parameter")
	}
	secret, err := DecodeSecret(q.Get("secret"))
	if err != nil {
		return Account{}, fmt.Errorf("otp: invalid secret: %w", err)
	}

	issuer := strings.TrimSpace(q.Get("issuer"))
	if issuer == "" {
		issuer = strings.TrimSpace(labelIssuer)
	}

	if v := strings.TrimSpace(q.Get("algorithm")); v != "" {
		a.Algorithm = strings.ToUpper(v)
	}
	if v := q.Get("digits"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 6 || n > 8 {
			return Account{}, fmt.Errorf("otp: invalid digits %q", v)
		}
		a.Digits = n
	}
	if a.Type == TOTP {
		if v := q.Get("period"); v != "" {
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil || n == 0 {
				return Account{}, fmt.Errorf("otp: invalid period %q", v)
			}
			a.Period = uint32(n)
		}
	}
	if a.Type == HOTP {
		if v := q.Get("counter"); v != "" {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return Account{}, fmt.Errorf("otp: invalid counter %q", v)
			}
			a.Counter = n
		}
	}

	a.Issuer = issuer
	a.Name = name
	a.Secret = secret
	a.Normalize()
	if err := a.Valid(); err != nil {
		return Account{}, err
	}
	return a, nil
}

// URI renders the account as an otpauth:// URI, omitting default parameters.
func (a Account) URI() (string, error) {
	n := a
	n.Normalize()
	if err := n.Valid(); err != nil {
		return "", err
	}

	var b strings.Builder
	b.Grow(64)
	b.WriteString("otpauth://")
	b.WriteString(strings.ToLower(string(n.Type)))
	b.WriteByte('/')
	if n.Issuer != "" {
		b.WriteString(escapeLabel(n.Issuer))
		b.WriteByte(':')
	}
	b.WriteString(escapeLabel(n.Name))

	q := url.Values{}
	q.Set("secret", EncodeSecret(n.Secret))
	if n.Issuer != "" {
		q.Set("issuer", n.Issuer)
	}
	if n.Algorithm != "SHA1" {
		q.Set("algorithm", n.Algorithm)
	}
	if n.Digits != DefaultDigits && !n.IsSteam() {
		q.Set("digits", strconv.Itoa(n.Digits))
	}
	if n.Type == TOTP && n.Period != DefaultPeriod {
		q.Set("period", strconv.FormatUint(uint64(n.Period), 10))
	}
	if n.Type == HOTP {
		q.Set("counter", strconv.FormatUint(n.Counter, 10))
	}
	b.WriteByte('?')
	b.WriteString(q.Encode())
	return b.String(), nil
}

// escapeLabel percent-escapes a label component for use in the URI path.
// ':' is escaped explicitly because it separates issuer from account name.
func escapeLabel(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), ":", "%3A")
}
