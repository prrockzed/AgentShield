// Package tls provides TLS configuration helpers for the AgentShield gateway.
// Use GenerateSelfSigned for development/internal deployments and
// AcmeTLSConfig for production deployments with a real domain and Let's Encrypt.
package tls

import (
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// GenerateSelfSigned returns a *tls.Config with a freshly generated
// self-signed RSA-2048 certificate valid for 365 days. No files are
// written to disk — the certificate lives only in memory.
func GenerateSelfSigned() (*stdtls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"AgentShield"},
			CommonName:   "localhost",
		},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	cert, err := stdtls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &stdtls.Config{Certificates: []stdtls.Certificate{cert}}, nil
}

// AcmeTLSConfig returns a *tls.Config that automatically obtains and renews
// a Let's Encrypt certificate for domain. Certificates are cached in
// /tmp/acme-cache so they survive process restarts.
func AcmeTLSConfig(domain string) *stdtls.Config {
	m := &autocert.Manager{
		Cache:      autocert.DirCache("/tmp/acme-cache"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
	}
	return m.TLSConfig()
}
