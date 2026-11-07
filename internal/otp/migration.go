package otp

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Google Authenticator export format: otpauth-migration://offline?data=<base64>
// where data is a protobuf-encoded MigrationPayload. The schema is public:
//
//	message MigrationPayload {
//	  repeated OtpParameters otp_parameters = 1;
//	  optional int32 version = 2;      // ignored here
//	  optional int32 batch_size = 3;   // ignored: we merge whatever URIs arrive
//	  optional int32 batch_index = 4;
//	  optional string batch_id = 5;
//	}
//	message OtpParameters {
//	  bytes  secret    = 1;
//	  string name      = 2;  // account name
//	  string issuer    = 3;
//	  Algorithm algorithm = 4; // 0 unspecified, 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
//	  DigitCount digits   = 5; // 0 unspecified, 1 six, 2 eight
//	  OtpType type        = 6; // 0 unspecified, 1 HOTP, 2 TOTP
//	  uint64 counter      = 7;
//	}

var (
	// ErrNotMigration means the URI is not an otpauth-migration:// link.
	ErrNotMigration = errors.New("otp: not an otpauth-migration:// URI")
	// ErrBadMigration means the data payload could not be decoded.
	ErrBadMigration = errors.New("otp: undecodable migration payload")
)

// ParseMigrationURI decodes a Google Authenticator export URI into the
// accounts it carries (usually several). Unknown protobuf fields are
// skipped; MD5 entries are dropped as unsupported.
func ParseMigrationURI(s string) ([]Account, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotMigration, err)
	}
	if !strings.EqualFold(u.Scheme, "otpauth-migration") {
		return nil, ErrNotMigration
	}
	// Pull the data parameter from the raw query by hand: url.Values
	// would decode '+' as a space and silently corrupt the base64.
	dataB64, found := rawQueryParam(u.RawQuery, "data")
	if !found {
		return nil, fmt.Errorf("%w: missing data parameter", ErrBadMigration)
	}
	payload, err := decodeBase64Any(dataB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMigration, err)
	}
	return parseMigrationPayload(payload)
}

// rawQueryParam reads one query parameter without the '+'-to-space
// translation url.Values applies; only percent-escapes are decoded.
func rawQueryParam(rawQuery, name string) (string, bool) {
	for _, pair := range strings.Split(rawQuery, "&") {
		k, v, found := strings.Cut(pair, "=")
		if !found || k != name {
			continue
		}
		if unescaped, err := url.PathUnescape(v); err == nil {
			return unescaped, true
		}
		return v, true // undecodable escapes: try the raw bytes anyway
	}
	return "", false
}

// decodeBase64Any accepts standard and URL-safe base64, padded or not.
func decodeBase64Any(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "") // tolerate line breaks
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}

// parseMigrationPayload walks the protobuf wire format. Only fields of the
// documented schema are interpreted; everything else is skipped by wire type.
func parseMigrationPayload(b []byte) ([]Account, error) {
	var accounts []Account
	for len(b) > 0 {
		tag, rest, err := readVarint(b)
		if err != nil {
			return nil, err
		}
		field, wire := int(tag>>3), int(tag&7)
		val, rest, err := readValue(rest, wire)
		if err != nil {
			return nil, err
		}
		if field == 1 && wire == 2 {
			acc, err := parseOtpParameters(val)
			if err != nil {
				return nil, err
			}
			if acc != nil {
				accounts = append(accounts, *acc)
			}
		}
		b = rest
	}
	return accounts, nil
}

// parseOtpParameters converts one entry; a nil Account (and nil error)
// means the entry is unsupported (MD5) and was dropped.
func parseOtpParameters(b []byte) (*Account, error) {
	acc := &Account{Algorithm: "SHA1", Digits: DefaultDigits}
	haveType := false
	for len(b) > 0 {
		tag, rest, err := readVarint(b)
		if err != nil {
			return nil, err
		}
		field, wire := int(tag>>3), int(tag&7)
		val, rest, err := readValue(rest, wire)
		if err != nil {
			return nil, err
		}
		b = rest
		switch field {
		case 1:
			acc.Secret = val
		case 2:
			acc.Name = string(val)
		case 3:
			acc.Issuer = string(val)
		case 4:
			acc.Algorithm = migrationAlgorithm(wireVarint(val))
		case 5:
			if n := wireVarint(val); n == 2 {
				acc.Digits = 8
			}
		case 6:
			switch wireVarint(val) {
			case 1:
				acc.Type, haveType = HOTP, true
			case 2:
				acc.Type, haveType = TOTP, true
			}
		case 7:
			acc.Counter = wireVarint(val)
		}
	}
	if !haveType || len(acc.Secret) == 0 || acc.Name == "" {
		return nil, fmt.Errorf("%w: incomplete OtpParameters", ErrBadMigration)
	}
	if acc.Algorithm == "" {
		return nil, nil // MD5 or unknown algorithm: unsupported, drop silently
	}
	acc.Normalize()
	if err := acc.Valid(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMigration, err)
	}
	return acc, nil
}

func migrationAlgorithm(v uint64) string {
	switch v {
	case 2:
		return "SHA256"
	case 3:
		return "SHA512"
	case 0, 1: // Unspecified behaves as the SHA1 default
		return "SHA1"
	}
	return "" // 4 MD5 and anything unknown: unsupported, dropped
}

// wireVarint interprets a length-delimited value that actually held a
// varint field (protobuf lets ints travel either way; GA uses packed style
// with wire type 0 for scalars, but be tolerant).
func wireVarint(val []byte) uint64 {
	v, _, err := readVarint(val)
	if err != nil {
		return 0
	}
	return v
}

func readVarint(b []byte) (uint64, []byte, error) {
	var v uint64
	for shift := uint(0); ; shift += 7 {
		if shift >= 64 || len(b) == 0 {
			return 0, nil, errors.New("truncated varint")
		}
		c := b[0]
		b = b[1:]
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, b, nil
		}
	}
}

// readValue consumes one field value of the given wire type.
func readValue(b []byte, wire int) ([]byte, []byte, error) {
	switch wire {
	case 0: // varint — keep the consumed bytes for wireVarint
		v, rest, err := readVarint(b)
		if err != nil {
			return nil, nil, err
		}
		var scratch [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(scratch[:], v)
		return scratch[:n], rest, nil
	case 1: // 64-bit
		if len(b) < 8 {
			return nil, nil, errors.New("truncated fixed64")
		}
		return nil, b[8:], nil
	case 2: // length-delimited
		n, rest, err := readVarint(b)
		if err != nil || n > uint64(len(rest)) {
			return nil, nil, errors.New("truncated length-delimited field")
		}
		return rest[:n], rest[n:], nil
	case 5: // 32-bit
		if len(b) < 4 {
			return nil, nil, errors.New("truncated fixed32")
		}
		return nil, b[4:], nil
	}
	return nil, nil, fmt.Errorf("unsupported wire type %d", wire)
}

// MigrationURI builds an otpauth-migration:// URI carrying the given
// accounts — handy for tests and for moving accounts out of Keytray later.
func MigrationURI(accounts []Account) (string, error) {
	var payload bytes.Buffer
	for i := range accounts {
		payload.Write(appendField(nil, 1, otpParametersBytes(&accounts[i])))
	}
	payload.Write(appendVarintField(nil, 2, 1)) // version

	q := url.Values{}
	q.Set("data", base64.StdEncoding.EncodeToString(payload.Bytes()))
	return "otpauth-migration://offline?" + q.Encode(), nil
}

func otpParametersBytes(a *Account) []byte {
	n := *a
	n.Normalize()
	var b []byte
	b = appendField(b, 1, n.Secret)
	b = appendStringField(b, 2, n.Name)
	b = appendStringField(b, 3, n.Issuer)
	b = appendVarintField(b, 4, protoAlgorithm(n.Algorithm))
	b = appendVarintField(b, 5, protoDigits(n.Digits))
	if n.Type == HOTP {
		b = appendVarintField(b, 6, 1)
		b = appendVarintField(b, 7, n.Counter)
	} else {
		b = appendVarintField(b, 6, 2)
	}
	return b
}

func protoAlgorithm(alg string) uint64 {
	switch alg {
	case "SHA256":
		return 2
	case "SHA512":
		return 3
	}
	return 1 // SHA1
}

func protoDigits(digits int) uint64 {
	if digits >= 8 {
		return 2
	}
	return 1
}

// appendField appends a length-delimited field with the given content.
func appendField(b []byte, field int, content []byte) []byte {
	b = appendVarint(b, uint64(field)<<3|2)
	b = appendVarint(b, uint64(len(content)))
	return append(b, content...)
}

func appendStringField(b []byte, field int, s string) []byte {
	return appendField(b, field, []byte(s))
}

func appendVarintField(b []byte, field int, v uint64) []byte {
	b = appendVarint(b, uint64(field)<<3|0)
	return appendVarint(b, v)
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}
