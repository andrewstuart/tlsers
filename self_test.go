package tlsers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSelf(t *testing.T) {
	asrt := assert.New(t)
	s := SelfSigner{}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello world")
	})

	srv := http.Server{
		Addr: "localhost:8088",
		TLSConfig: &tls.Config{
			GetCertificate: s.GetCertificate,
		},
	}

	hc := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
					return nil
				},
			},
		},
	}

	go srv.ListenAndServeTLS("", "")

	res, err := hc.Get("https://localhost:8088/")
	asrt.NoError(err)

	bs, err := ioutil.ReadAll(res.Body)
	asrt.NoError(err)

	asrt.Equal(bs, []byte("hello world"))
}
