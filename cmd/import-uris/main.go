// import-uris merges a file of otpauth:// URIs (one per line) into a
// keytray vault, skipping duplicates — the same path the app's import
// window uses. The vault format (plain/encrypted) is auto-detected.
//
//	go run ./cmd/import-uris -vault path/vault.kt -file uris.txt [-password pw]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"keytray/internal/otp"
	"keytray/internal/vault"
)

func main() {
	vaultPath := flag.String("vault", "", "vault file (required)")
	file := flag.String("file", "", "URI list file, one per line (required)")
	password := flag.String("password", "", "master password (required when the vault is encrypted)")
	flag.Parse()

	if *vaultPath == "" || *file == "" {
		log.Fatal("usage: import-uris -vault PATH -file URIS.txt [-password PW]")
	}

	data, err := os.ReadFile(*vaultPath)
	if err != nil {
		log.Fatal(err)
	}
	encrypted := vault.IsEncrypted(data)
	var v *vault.Vault
	if encrypted {
		if *password == "" {
			log.Fatal("vault is encrypted: pass -password")
		}
		v, err = vault.OpenVault(data, *password)
	} else {
		v, err = vault.Unmarshal(data)
	}
	if err != nil {
		log.Fatal(err)
	}

	raw, err := os.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}

	added, skipped, bad := 0, 0, 0
	same := func(a, b otp.Account) bool {
		return a.Issuer == b.Issuer && a.Name == b.Name && string(a.Secret) == string(b.Secret)
	}
	for _, line := range strings.FieldsFunc(string(raw), func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		if strings.HasPrefix(strings.ToLower(line), "otpauth-migration://") {
			more, err := otp.ParseMigrationURI(line)
			if err != nil {
				bad++
				continue
			}
			for _, acc := range more {
				if dup(v.Accounts, acc, same) {
					skipped++
					continue
				}
				v.Accounts = append(v.Accounts, acc)
				added++
			}
			continue
		}
		acc, err := otp.ParseURI(line)
		if err != nil {
			bad++
			continue
		}
		if dup(v.Accounts, acc, same) {
			skipped++
			continue
		}
		v.Accounts = append(v.Accounts, acc)
		added++
	}

	var out []byte
	if encrypted {
		out, err = vault.SealVault(v, *password, vault.DefaultParams())
	} else {
		out, err = vault.Marshal(v)
	}
	if err != nil {
		log.Fatal(err)
	}
	if err := vault.SaveFile(*vaultPath, out); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("导入完成:新增 %d,跳过重复 %d,无法识别 %d,共 %d 个账号\n",
		added, skipped, bad, len(v.Accounts))
}

func dup(accounts []otp.Account, acc otp.Account, same func(a, b otp.Account) bool) bool {
	for _, a := range accounts {
		if same(a, acc) {
			return true
		}
	}
	return false
}
