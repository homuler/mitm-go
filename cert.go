package mitm

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// ForgeCertificate creates a new [tls.Certificate] that looks like the original certificate but signed by the specified root.
func ForgeCertificate(root *tls.Certificate, orig *x509.Certificate) (tls.Certificate, error) {
	tmpl, err := createTemplate(orig)
	if err != nil {
		return tls.Certificate{}, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate an RSA key: %w", err)
	}

	if root.Leaf == nil {
		root.Leaf, err = x509.ParseCertificate(root.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to parse root certificate: %w", err)
		}
	}

	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, root.Leaf, &key.PublicKey, root.PrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create a certificate of %s: %w", orig.Subject.CommonName, err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDer, root.Certificate[0]},
		PrivateKey:  key,
	}, nil
}

func createTemplate(orig *x509.Certificate) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate the serial number: %w", err)
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

// LoadCertificate loads a certificate from the specified files.
// The returned certificate has the Leaf field set.
func LoadCertificate(certPath, keyPath string) (cert tls.Certificate, err error) {
	cert, err = tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return
	}
	err = loadLeaf(&cert)
	return
}

func loadLeaf(cert *tls.Certificate) (err error) {
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	return
}

func CreateCACertPEM(subject pkix.Name, duration time.Duration) (*bytes.Buffer, *bytes.Buffer, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate the serial number: %w", err)
	}

	notBefore := time.Now()
	caCert := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(duration),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("faild to generate the private key: %w", err)
	}

	certDer, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	return caPEM, caPrivKeyPEM, nil
}

func CreateCACert(subject pkix.Name, duration time.Duration) (cert tls.Certificate, err error) {
	caPEM, caPrivKeyPEM, err := CreateCACertPEM(subject, duration)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(caPEM.Bytes(), caPrivKeyPEM.Bytes())
}
