package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

type CertInfo struct {
	Issuer   string
	Subject  string
	NotAfter time.Time
}

func fileExists(fileName string) bool {
	_, err := os.Stat(fileName)
	if err == nil {
		return true
	}
	return false
}

func errHandle(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func certInfo(certificate x509.Certificate) CertInfo {
	return CertInfo{
		Issuer:   certificate.Issuer.CommonName,
		Subject:  certificate.Subject.CommonName,
		NotAfter: certificate.NotAfter,
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: basic <path>")
		return
	}
	file := os.Args[1]

	pemData, err := os.ReadFile(file)
	errHandle(err)
	block, _ := pem.Decode(pemData)
	if block == nil {
		fmt.Fprintf(os.Stderr, "error: failed to decode PEM\n")
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	errHandle(err)

	info := certInfo(*cert)
	fmt.Printf("Issued by %s\n", info.Issuer)
	fmt.Printf("Issued to %s\n", info.Subject)
	fmt.Printf("Expires %v\n", info.NotAfter)
}
