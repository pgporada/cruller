package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	zx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

func main() {
	// TODO: Get this directory from a flag or something
	dir := "./crls/2024-05-09/"
	crlDir, err := os.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	registry, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
		ExcludeSources: []lint.LintSource{lint.EtsiEsi},
	})
	if err != nil {
		log.Fatal("lint registry filter failed to apply:", err)
	}

	for _, file := range crlDir {
		filePath := filepath.Join(dir, file.Name())
		fileBytes, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Unable to read CRL from %q - %q\n", filePath, err)
		}

		if len(fileBytes) <= 0 {
			// TODO: Obviously bad, but there was some transient HTTP error that
			// prevented the CRawLer from downloading the CRL.
			continue
		} else {
			crl, err := zx509.ParseRevocationList(fileBytes)
			if err != nil {
				log.Printf("Failed to parse CRL %q - %q\n", filePath, err)
			} else {
				zlintResultSet := zlint.LintRevocationListEx(crl, registry)
				log.Printf("CRL %q - %q\n", filePath, crl.Issuer)
				fmt.Println(zlintResultSet)
			}
		}
	}
}
