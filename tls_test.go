package mitm_test

import (
	"testing"

	"github.com/homuler/mitm-proxy-go"
	"github.com/stretchr/testify/assert"
)

func TestNewTLSListener_fails_if_the_root_certificate_is_missing(t *testing.T) {
	_, err := mitm.NewTLSListener(nil, &mitm.TLSConfig{})
	assert.ErrorIs(t, err, mitm.ErrMissingRootCertificate)
}
