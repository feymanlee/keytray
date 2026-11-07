// devseed writes a demo vault file for manual verification of the panel:
//
//	go run ./cmd/devseed -vault /path/vault.kt -password demo-password \
//	    'otpauth://totp/GitHub:feyman?secret=JBSWY3DPEHPK3PXP' ...
//
// It is a development helper only and is not shipped with the app.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"keytray/internal/otp"
	"keytray/internal/vault"
)

func main() {
	vaultPath := flag.String("vault", "", "vault file to write (required)")
	password := flag.String("password", "", "master password (required)")
	flag.Parse()

	if *vaultPath == "" || *password == "" || flag.NArg() == 0 {
		log.Fatal("usage: devseed -vault PATH -password PW otpauth-uri...")
	}

	v := vault.New()
	for _, uri := range flag.Args() {
		acc, err := otp.ParseURI(uri)
		if err != nil {
			log.Fatalf("%s: %v", uri, err)
		}
		v.Accounts = append(v.Accounts, acc)
	}

	data, err := vault.SealVault(v, *password, vault.DefaultParams())
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(*vaultPath), 0o700); err != nil {
		log.Fatal(err)
	}
	if err := vault.SaveFile(*vaultPath, data); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %d accounts to %s\n", len(v.Accounts), *vaultPath)
}
