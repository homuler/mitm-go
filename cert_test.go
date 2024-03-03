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

var rootCACert *tls.Certificate

func init() {
	cert, err := mitm.CreateCACert(pkix.Name{}, 1*time.Hour)
	if err != nil {
		return
	}
	rootCACert = &cert
	rootCACert.Leaf, _ = x509.ParseCertificate(rootCACert.Certificate[0])
}

func TestForgeCertificate(t *testing.T) {
	t.Parallel()

	if rootCACert == nil {
		t.Fatal("rootCACert is not initialized")
	}

	dnsName := "example.com"
	dummyCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("*.%s", dnsName),
			Organization: []string{"mitm-go"},
			Country:      []string{"JP"},
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

	cert, err := mitm.ForgeCertificate(rootCACert, dummyCert)
	require.NoError(t, err)

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	certPool := x509.NewCertPool()
	certPool.AddCert(rootCACert.Leaf)

	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   certPool,
	})
	assert.NoError(t, err, "failed to verify the forged certificate")
}
