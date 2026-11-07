// Package vault stores keytray accounts in a single encrypted file.
// The vault key is derived from the master password with Argon2id and the
// payload (vault JSON) is sealed with AES-256-GCM. The on-disk layout is:
//
//	offset  size  field
//	     0     7  magic "KTVAULT"
//	     7     2  format version (little endian)
//	     9    16  Argon2id salt
//	    25     4  Argon2id time (LE)
//	    29     4  Argon2id memory in KB (LE)
//	    33     1  Argon2id threads
//	    34    12  AES-GCM nonce
//	    46    ..  ciphertext (AAD = bytes 0..34)
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"

	"keytray/internal/otp"
)

var magic = []byte("KTVAULT")

const (
	// Version is the current on-disk format version.
	Version = 1

	headerLen = 46
	saltLen   = 16
	nonceLen  = 12
	keyLen    = 32
)

var (
	// ErrWrongPassword means the GCM authentication failed: either the
	// password is wrong or the file bytes were tampered with.
	ErrWrongPassword = errors.New("vault: wrong password or damaged vault")
	// ErrCorrupt means the file is not a recognizable vault.
	ErrCorrupt = errors.New("vault: not a keytray vault file")
	// ErrBadVersion means the file uses a newer format version.
	ErrBadVersion = errors.New("vault: unsupported vault format version")
	// ErrNotFound means the vault file does not exist yet (first run).
	ErrNotFound = errors.New("vault: vault file not found")
)

// Params are the Argon2id KDF parameters, stored in the file header so old
// files keep working if the defaults change later.
type Params struct {
	Time     uint32
	MemoryKB uint32
	Threads  uint8
	Salt     []byte
}

// DefaultParams returns the production KDF parameters (64 MiB, t=1).
func DefaultParams() Params {
	return Params{Time: 1, MemoryKB: 64 << 10, Threads: 4}
}

// Sane upper bounds for KDF parameters. They cap worst-case unlock cost and,
// more importantly, stop a tampered header from turning key derivation into
// a CPU/memory denial of service before the GCM tag can even be checked.
const (
	maxTime     = 16
	maxMemoryKB = 4 << 20 // 4 GiB
	maxThreads  = 64
)

func (p Params) validate() error {
	if p.Time == 0 || p.Time > maxTime {
		return fmt.Errorf("vault: argon2 time must be 1..%d, got %d", maxTime, p.Time)
	}
	if p.Threads == 0 || p.Threads > maxThreads {
		return fmt.Errorf("vault: argon2 threads must be 1..%d, got %d", maxThreads, p.Threads)
	}
	if p.MemoryKB < 8*uint32(p.Threads) || p.MemoryKB > maxMemoryKB {
		return fmt.Errorf("vault: argon2 memory out of range: %d KB", p.MemoryKB)
	}
	if len(p.Salt) != 0 && len(p.Salt) != saltLen {
		return fmt.Errorf("vault: salt must be %d bytes", saltLen)
	}
	return nil
}

func deriveKey(password string, p Params) []byte {
	return argon2.IDKey([]byte(password), p.Salt, p.Time, p.MemoryKB, p.Threads, keyLen)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Vault is the decrypted content of a vault file. The Accounts slice order
// is the display order shown in the panel.
type Vault struct {
	Version  int           `json:"version"`
	Accounts []otp.Account `json:"accounts"`
}

// New returns an empty vault.
func New() *Vault {
	return &Vault{Version: Version, Accounts: []otp.Account{}}
}

// Marshal serializes the vault. A zero version is upgraded in place.
func Marshal(v *Vault) ([]byte, error) {
	if v.Version == 0 {
		v.Version = Version
	}
	return json.Marshal(v)
}

// Unmarshal parses vault JSON and rejects newer formats.
func Unmarshal(data []byte) (*Vault, error) {
	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("vault: invalid vault data: %w", err)
	}
	if v.Version == 0 {
		return nil, errors.New("vault: missing version field")
	}
	if v.Version > Version {
		return nil, fmt.Errorf("%w: %d", ErrBadVersion, v.Version)
	}
	return &v, nil
}

// Seal encrypts payload (normally vault JSON) under password. If params.Salt
// is empty a random salt is generated; a fresh random nonce is always used.
func Seal(payload []byte, password string, params Params) ([]byte, error) {
	if params.Salt == nil {
		params.Salt = make([]byte, saltLen)
		if _, err := rand.Read(params.Salt); err != nil {
			return nil, fmt.Errorf("vault: generate salt: %w", err)
		}
	}
	if err := params.validate(); err != nil {
		return nil, err
	}
	key := deriveKey(password, params)
	defer wipe(key)

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: generate nonce: %w", err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	header := make([]byte, 0, headerLen)
	header = append(header, magic...)
	var b2 [2]byte
	var b4 [4]byte
	binary.LittleEndian.PutUint16(b2[:], uint16(Version))
	header = append(header, b2[:]...)
	header = append(header, params.Salt...)
	binary.LittleEndian.PutUint32(b4[:], params.Time)
	header = append(header, b4[:]...)
	binary.LittleEndian.PutUint32(b4[:], params.MemoryKB)
	header = append(header, b4[:]...)
	header = append(header, params.Threads)
	header = append(header, nonce...)
	return aead.Seal(header, nonce, payload, header[:headerLen-nonceLen]), nil
}

// Open verifies and decrypts a vault file, returning the vault JSON payload.
func Open(file []byte, password string) ([]byte, error) {
	if len(file) < headerLen || !bytes.Equal(file[:7], magic) {
		return nil, ErrCorrupt
	}
	if ver := binary.LittleEndian.Uint16(file[7:9]); ver != uint16(Version) {
		return nil, fmt.Errorf("%w: %d", ErrBadVersion, ver)
	}
	params := Params{
		Salt:     file[9:25],
		Time:     binary.LittleEndian.Uint32(file[25:29]),
		MemoryKB: binary.LittleEndian.Uint32(file[29:33]),
		Threads:  file[33],
	}
	if err := params.validate(); err != nil {
		// Out-of-range KDF parameters in a header can only come from a
		// damaged or hostile file; never spend CPU deriving with them.
		return nil, ErrCorrupt
	}

	key := deriveKey(password, params)
	defer wipe(key)
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	payload, err := aead.Open(nil, file[34:46], file[headerLen:], file[:34])
	if err != nil {
		return nil, ErrWrongPassword
	}
	return payload, nil
}

// IsEncrypted reports whether data carries the encrypted vault format
// (as opposed to a plaintext vault JSON).
func IsEncrypted(data []byte) bool {
	return len(data) >= 7 && bytes.Equal(data[:7], magic)
}

// SavePlain writes the vault as plaintext JSON (atomic, 0600). Plaintext
// mode is a user choice; the file holds secrets readable on disk.
func SavePlain(path string, v *Vault) error {
	data, err := Marshal(v)
	if err != nil {
		return err
	}
	return SaveFile(path, data)
}

// SealVault marshals and encrypts a vault in one step.
func SealVault(v *Vault, password string, params Params) ([]byte, error) {
	data, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	return Seal(data, password, params)
}

// OpenVault decrypts and parses a vault file in one step.
func OpenVault(file []byte, password string) (*Vault, error) {
	payload, err := Open(file, password)
	if err != nil {
		return nil, err
	}
	return Unmarshal(payload)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm: %w", err)
	}
	return aead, nil
}
