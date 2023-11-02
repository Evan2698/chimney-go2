package quicproxy

import (
	"chimney-go2/configure"
	"chimney-go2/utils"
	"log"
	"net"
	"net/http"
	"path"
	"strconv"

	"github.com/elazarl/goproxy"
)

type QuicServer interface {
	Serve() error
}

type quicServerHolder struct {
	config configure.AppConfig
}

//TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),

func (s *quicServerHolder) Serve() error {
	certPath, err := utils.RetrieveCertsPath()
	if err != nil {
		log.Println("cert file is not exist!", err)
		return err
	}
	pemPath := path.Join(certPath, "server.crt")
	keypath := path.Join(certPath, "server.key")
	rootCert := path.Join(certPath, "root.crt")

	l, err := NewQuicListener(keypath, pemPath, rootCert, s.config)
	if err != nil {
		return err
	}
	serverHost := net.JoinHostPort(s.config.Server, strconv.Itoa(int(s.config.QuicServerPort)))
	proxy := goproxy.NewProxyHttpServer()
	server := &http.Server{Addr: serverHost, Handler: proxy}
	server.Serve(l)
	return err
}

func NewQuicSever(c configure.AppConfig) QuicServer {
	return &quicServerHolder{
		config: c,
	}
}
