package testutil

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"

	"github.com/homuler/mitm-go"
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

func RootCACert(t *testing.T) *tls.Certificate {
	t.Helper()

	if rootCACert == nil {
		t.Fatal("RootCACert is not initialized")
	}
	return rootCACert
}

func MITMCACert(t *testing.T) *tls.Certificate {
	t.Helper()

	if mitmCACert == nil {
		t.Fatal("MITMCACert is not initialized")
	}
	return mitmCACert
}

func RootCAs(t *testing.T) *x509.CertPool {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AddCert(RootCACert(t).Leaf)
	return pool
}

func ClientRootCAs(t *testing.T) *x509.CertPool {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AddCert(RootCACert(t).Leaf)
	pool.AddCert(MITMCACert(t).Leaf)
	return pool
}

func MustIssueCertificate(t *testing.T, subject pkix.Name, addr net.Addr) *tls.Certificate {
	t.Helper()

	rootCACert := RootCACert(t)

	var ipAddrs []net.IP
	{
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			// ipAddrs is nil
		} else {
			ipAddrs = append(ipAddrs, net.ParseIP(host))
		}
	}

	cert, err := mitm.ForgeCertificate(rootCACert, &x509.Certificate{
		Subject:     subject,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * time.Hour),
		DNSNames:    []string{subject.CommonName},
		IPAddresses: ipAddrs,
	})
	require.NoErrorf(t, err, "failed to issue a certificate")
	return &cert
}
