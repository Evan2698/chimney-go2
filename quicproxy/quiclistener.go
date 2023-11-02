package quicproxy

import (
	"chimney-go2/configure"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/quic-go/quic-go"
)

type QuicListener interface {
	net.Listener
}

type AcceptConn struct {
	conn net.Conn
	err  error
}

type QuicListenerHolder struct {
	Listener     *quic.Listener
	chAcceptConn chan *AcceptConn
}

func NewQuicListener(key, cert, root string, config configure.AppConfig) (QuicListener, error) {

	l, err := OpenQuicStream(key, cert, root, config)
	if err != nil {
		log.Println("can not open quic stream failed.", err)
		return nil, err
	}

	nl := &QuicListenerHolder{
		Listener:     l,
		chAcceptConn: make(chan *AcceptConn, 4),
	}
	go nl.doAccept()

	return nl, nil
}

func OpenQuicStream(key, pem, rootCert string, config configure.AppConfig) (*quic.Listener, error) {

	cert, err := tls.LoadX509KeyPair(pem, key)
	if err != nil {
		log.Println("load cert failed", err)
		return nil, err
	}
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(rootCert)
	if err != nil {
		log.Print("read root file failed", err)
		return nil, err
	}
	ok := pool.AppendCertsFromPEM(ca)
	if !ok {
		log.Print("append root cert failed!")
		return nil, errors.New("append root cert failed")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{protocol},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	}
	serverHost := net.JoinHostPort(config.Server, strconv.Itoa(int(config.QuicServerPort)))
	quicConf := &quic.Config{}
	listener, err := quic.ListenAddr(serverHost, tlsConfig, quicConf)

	return listener, err
}

func (ql *QuicListenerHolder) doAccept() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered. Error:\n", r)
		}
	}()

	for {
		sess, err := ql.Listener.Accept(context.Background())
		if err != nil {
			log.Printf("accept session failed:%v", err)
			continue
		}
		log.Print("accept a session")

		go func(sess quic.Connection) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Println("Recovered. Error:\n", r)
				}
			}()

			defer func() {
				sess.CloseWithError(2020, "AcceptStream error")
			}()

			for {
				stream, err := sess.AcceptStream(context.TODO())
				if err != nil {
					log.Println("session failed", err)
					break
				}
				log.Printf("accept stream %v", stream.StreamID())
				ql.chAcceptConn <- &AcceptConn{
					conn: &QuicStream{
						Connect:   sess,
						Stream:    stream,
						IsDestory: false,
					},
					err: nil,
				}
			}
		}(sess)
	}

}

func (ql *QuicListenerHolder) Accept() (net.Conn, error) {
	ac := <-ql.chAcceptConn
	return ac.conn, ac.err
}

func (ql *QuicListenerHolder) Close() error {
	err := ql.Listener.Close()
	return err
}

func (ql *QuicListenerHolder) Addr() net.Addr {
	return ql.Listener.Addr()
}
