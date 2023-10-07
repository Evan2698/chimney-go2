package proxycore

import (
	"chimney-go2/configure"
	"chimney-go2/utils"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"sync"

	"github.com/quic-go/quic-go"
)

const (
	httpProtocol        = "vpn-for-evan"
	httpInternalAddress = "127.0.0.1:59846"
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
	cert, err := tls.LoadX509KeyPair(ts.Pem, ts.Key)
	if err != nil {
		log.Println("load cert path error", err)
		return err
	}

	go func() {
		listenHttpServer()
	}()

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
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{httpProtocol},
	}

	listener, err := quic.ListenAddr(serverHost, tlsConfig, quicConf)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			log.Println("http3 accept failed", err)
			break
		}
		handleHttp3Session(session)
	}

	return nil
}

func listenHttpServer() error {
	http.ListenAndServe(httpInternalAddress, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleTunneling(w, r)
		} else {
			handleHTTP(w, r)
		}
	}))

	return nil
}

func handleHttp3Session(session quic.Connection) {
	defer session.CloseWithError(0x90, "no reason")

	for {
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			log.Println("stream fetal error", err)
			break
		}

		handleStream(stream)
	}
}

func handleStream(stream quic.Stream) {
	defer stream.Close()
	conn, err := net.Dial("tcp", httpInternalAddress)
	if err != nil {
		log.Println("Inner http connection failed!", err)
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		io.Copy(conn, stream)
		wg.Done()
	}()
	go func() {
		io.Copy(stream, conn)
		wg.Done()
	}()
	wg.Wait()
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
