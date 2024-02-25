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

func ForgeCertificate(root *tls.Certificate, orig *x509.Certificate) (tls.Certificate, error) {
	tmpl, err := createTemplate(orig)
	if err != nil {
		return tls.Certificate{}, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	if root.Leaf == nil {
		root.Leaf, err = x509.ParseCertificate(root.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to parse root certificate: %w", err)
		}
	}

	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, root.Leaf, &key.PublicKey, root.PrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDer, root.Certificate[0]},
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

func LoadCertificate(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}
