// Package httpserver builds the TLS configuration for the standalone server:
// a self-signed localhost certificate when no keystore is configured
// (mirroring Ssl.kt), or a user-provided PKCS12 keystore.
package httpserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// TLS holds the ready-to-use server TLS config plus the server certificate
// (so in-server clients such as the debugger can trust it).
type TLS struct {
	Config *tls.Config
	// Certificates is the parsed server certificate chain.
	Certificates []*x509.Certificate
}

// Options mirrors the Kotlin SslConfig JSON shape.
type Options struct {
	KeyPassword      string
	KeystoreFile     string
	KeystoreType     string // "PKCS12" (default); "JKS" is rejected
	KeystorePassword string
}

// NewTLS builds the TLS setup. When KeystoreFile is empty a self-signed
// certificate for localhost/127.0.0.1 is generated (RSA 2048, SHA256withRSA,
// 365 days — the same shape as SslKeystore.generate).
func NewTLS(opts Options) (*TLS, error) {
	var cert tls.Certificate
	var chain []*x509.Certificate

	if opts.KeystoreFile == "" {
		generated, err := selfSignedCertificate(opts.KeyPassword)
		if err != nil {
			return nil, err
		}
		cert = generated
		leaf, err := x509.ParseCertificate(generated.Certificate[0])
		if err != nil {
			return nil, err
		}
		chain = []*x509.Certificate{leaf}
	} else {
		if opts.KeystoreType == "JKS" {
			return nil, fmt.Errorf("JKS keystores are not supported by the Go server; convert to PKCS12 with keytool -importkeystore")
		}
		data, err := os.ReadFile(opts.KeystoreFile)
		if err != nil {
			return nil, fmt.Errorf("reading keystore: %w", err)
		}
		priv, leaf, caCerts, err := pkcs12.DecodeChain(data, opts.KeystorePassword)
		if err != nil {
			return nil, fmt.Errorf("decoding PKCS12 keystore: %w", err)
		}
		chain = append([]*x509.Certificate{leaf}, caCerts...)
		der := make([][]byte, 0, len(chain))
		for _, c := range chain {
			der = append(der, c.Raw)
		}
		cert = tls.Certificate{Certificate: der, PrivateKey: priv}
	}

	return &TLS{
		Config: &tls.Config{Certificates: []tls.Certificate{cert}},
		// keyPassword: Go's TLS stack reads the private key directly, so the
		// PKCS12 key password only matters at decode time.
		Certificates: chain,
	}, nil
}

// TrustPool returns a pool containing the server certificate chain, for
// in-server clients that must trust this server over TLS.
func (t *TLS) TrustPool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range t.Certificates {
		pool.AddCert(c)
	}
	return pool
}

// selfSignedCertificate generates a localhost certificate and returns it as a
// TLS certificate whose PrivateKey is the generated RSA key (Go does not need
// the PKCS12 wrapping the Kotlin server produced).
func selfSignedCertificate(keyPassword string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now()
	spkDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	ski := sha1.Sum(spkDER)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixMilli()),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true, // the Kotlin self-signed cert marks itself CA
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          ski[:],
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
