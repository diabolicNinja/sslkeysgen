package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

/* rsa.GenerateKey() =>
x509.MarshalPKIXPublicKey() =>
pem.Encode() */

func main() {
	/* generate keys pair */
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publickey := &privatekey.PublicKey

	/* write private key to files */
	privatekeyBytes := x509.MarshalPKCS1PrivateKey(privatekey)
	privatekeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privatekeyBytes,
	}
	privatekeyPEM, err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	err = pem.Encode(privatekeyPEM, privatekeyBlock)
	if err != nil {
		panic(err)
	}

	/* write pub key to file */
	publickeyBytes := x509.MarshalPKCS1PublicKey(publickey)
	publickeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publickeyBytes,
	}
	publickeyPEM, err := os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	err = pem.Encode(publickeyPEM, publickeyBlock)
	if err != nil {
		panic(err)
	}

	/* cert */
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	startDate := time.Now()
	endDate := startDate.Add(time.Hour * 24 * 364)
	template := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Organization: []string{"Test Inc."},
		},
		NotBefore:             startDate,
		NotAfter:              endDate,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	crt, err := x509.CreateCertificate(rand.Reader, &template, &template, publickey, privatekey)
	if err != nil {
		panic(err)
	}
	crtfile, err := os.Create("server.crt")
	if err != nil {
		panic(err)
	}
	defer crtfile.Close()
	if err := pem.Encode(crtfile, &pem.Block{Type: "CERTIFICATE", Bytes: crt}); err != nil {
		panic(err)
	}
	os.Exit(0)
}
