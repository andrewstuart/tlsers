package tlsers

import (
	"crypto/tls"
)

type Certer interface {
	Cert(cn string) (*tls.Certificate, error)
}
