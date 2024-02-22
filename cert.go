package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func ForgeCertificate(orig *x509.Certificate) (*tls.Certificate, error) {
	tmpl, err := createTemplate(orig)
	if err != nil {
		return nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	rootCert := RootCert()
	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert.Leaf, &key.PublicKey, rootCert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDer, RootCert().Certificate[0]},
		PrivateKey:  key,
	}, nil
}

func createTemplate(orig *x509.Certificate) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               orig.Subject,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             orig.NotBefore,
		NotAfter:              orig.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           orig.IPAddresses,
		DNSNames:              orig.DNSNames,
	}
	return &tmpl, nil
}

var _rootCert *tls.Certificate

func RootCert() *tls.Certificate {
	if _rootCert == nil {
		_, err := LoadRootCert("rootCACert.pem", "rootCAKey.pem")
		if err != nil {
			panic(err)
		}
	}
	return _rootCert
}

func LoadRootCert(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	_rootCert = &cert
	return cert, nil
}
