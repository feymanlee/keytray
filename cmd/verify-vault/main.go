// verify-vault loads a keytray vault (plain or encrypted) and checks that
// every account can generate a code — a sanity check after imports.
//
//	go run ./cmd/verify-vault -vault path/vault.kt [-password pw]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"keytray/internal/vault"
)

func main() {
	vaultPath := flag.String("vault", "", "vault file (required)")
	password := flag.String("password", "", "master password (when encrypted)")
	flag.Parse()

	data, err := os.ReadFile(*vaultPath)
	if err != nil {
		log.Fatal(err)
	}
	var v *vault.Vault
	if vault.IsEncrypted(data) {
		v, err = vault.OpenVault(data, *password)
	} else {
		v, err = vault.Unmarshal(data)
	}
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	bad := 0
	for _, a := range v.Accounts {
		if _, err := a.Code(now); err != nil {
			bad++
			log.Printf("BAD: %s %s: %v", a.Issuer, a.Name, err)
			continue
		}
		label := a.Name
		if a.Issuer != "" {
			label = a.Issuer + ":" + a.Name
		}
		fmt.Println("ok:", label)
	}
	fmt.Printf("%d/%d 可出码\n", len(v.Accounts)-bad, len(v.Accounts))
}
