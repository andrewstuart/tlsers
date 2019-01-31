package tlsserve

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSelf(t *testing.T) {
	asrt := assert.New(t)
	s := SelfSigner{}
	c, err := s.Cert("localhost")
	asrt.NoError(err)

	tc := &tls.Config{
		Certificates: []tls.Certificate{*c},
	}

	p := x509.NewCertPool()
	asrt.True(p.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})), "appended pool")
	tc.RootCAs = p

	l, err := tls.Listen("tcp", "localhost:8088", tc)
	asrt.NoError(err)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello world")
	})

	go http.Serve(l, nil)

	hc := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tc,
		},
	}

	res, err := hc.Get("https://localhost:8088/")
	asrt.NoError(err)

	bs, err := ioutil.ReadAll(res.Body)
	asrt.NoError(err)

	asrt.Equal(bs, []byte("hello world"))

	l.Close()
}
