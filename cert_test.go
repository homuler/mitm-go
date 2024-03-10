package mitm_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/homuler/mitm-proxy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	mitmCACert *tls.Certificate
	rootCACert *tls.Certificate
)

func init() {
	mitmCACert = loadCACert(pkix.Name{CommonName: "mitm-go"}, 1*time.Hour)
	rootCACert = loadCACert(pkix.Name{CommonName: "root"}, 1*time.Hour)
}

func loadCACert(subject pkix.Name, duretion time.Duration) *tls.Certificate {
	cert, err := mitm.CreateCACert(subject, duretion)
	if err != nil {
		return nil
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil
	}
	return &cert
}

func TestForgeCertificate(t *testing.T) {
	t.Parallel()

	if mitmCACert == nil {
		t.Fatal("mitmCACert is not initialized")
	}

	dnsName := "example.com"
	dummyCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("*.%s", dnsName),
			Country:    []string{"JP"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{
			net.ParseIP("192.168.0.1"),
			net.ParseIP("192.168.0.2"),
		},
		DNSNames: []string{dnsName},
	}

	cert, err := mitm.ForgeCertificate(mitmCACert, dummyCert)
	require.NoError(t, err)

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	certPool := x509.NewCertPool()
	certPool.AddCert(mitmCACert.Leaf)

	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   certPool,
	})
	assert.NoError(t, err, "failed to verify the forged certificate")
}
