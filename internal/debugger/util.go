package debugger

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
)

func base64Basic(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}

func tlsConfigFor(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool}
}
