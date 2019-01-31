package tlsserve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

type SelfSigner struct {
}

func (s *SelfSigner) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.Cert(hello.ServerName)
}

func (s *SelfSigner) Cert(cn string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	t := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames:              []string{cn},
		NotAfter:              time.Now().Add(24 * time.Hour),
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &t, &t, &priv.PublicKey, priv)
	if err != nil {
		return nil, errors.Wrap(err, "create")
	}

	return &tls.Certificate{
		PrivateKey:  priv,
		Certificate: [][]byte{der},
	}, nil
}
