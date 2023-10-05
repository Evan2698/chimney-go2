package proxycore

import (
	"chimney-go2/configure"
	"chimney-go2/utils"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type http3ServerHolder struct {
	Config configure.AppConfig
	Pem    string
	Key    string
}

func (ts *http3ServerHolder) ListenAndServeTLS() error {
	serverHost := net.JoinHostPort(ts.Config.Server, strconv.Itoa(int(ts.Config.ServerPort)))
	pool := x509.NewCertPool()
	caPath, err := utils.RetrieveCertsPath()
	if err != nil {
		log.Println("get ca path failed", err)
		return err
	}

	rootCertFile := path.Join(caPath, "root.crt")
	ca, err := os.ReadFile(rootCertFile)
	if err != nil {
		log.Print("read root file failed", err)
		return err
	}
	ok := pool.AppendCertsFromPEM(ca)
	if !ok {
		log.Print("append root cert failed!")
		return errors.New("append root cert failed")
	}

	quicConf := &quic.Config{}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	// print(tlsConfig)
	server := http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		Addr:       serverHost,
		QuicConfig: quicConf,
		TLSConfig:  tlsConfig,
	}
	err = server.ListenAndServeTLS(ts.Pem, ts.Key)
	return err
}

func NewHttp3Server(config configure.AppConfig) (TlsServer, error) {
	certPath, err := utils.RetrieveCertsPath()
	if err != nil {
		log.Print("can not get cert path failed!", err)
		return nil, err
	}
	hostIP = config.Server
	pemPath := path.Join(certPath, "server.crt")
	keyPath := path.Join(certPath, "server.key")

	tlsServer := &http3ServerHolder{
		Pem:    pemPath,
		Key:    keyPath,
		Config: config,
	}

	return tlsServer, nil
}
