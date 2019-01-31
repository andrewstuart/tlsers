package tlsers

import (
	"crypto/tls"
)

// A Certer is anything that can provision a *tls.Certificate for a common name.
type Certer interface {
	Cert(cn string) (*tls.Certificate, error)
}

// CertFunc returns a simple Func for use in the tls.Config.GetCertificate
// function.
func CertFunc(c Certer) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return c.Cert(hello.ServerName)
	}
}
