package quicproxy

import (
	"chimney-go2/configure"
	"chimney-go2/utils"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"path"
	"strconv"
	"sync"

	"github.com/quic-go/quic-go"
)

type QuicProxyClient interface {
	Serve() error
	Stop()
}

type quicProxy struct {
	config configure.AppConfig
	exit   bool
}

func NewQuic(c configure.AppConfig) QuicProxyClient {
	return &quicProxy{
		config: c,
		exit:   false,
	}
}

func (c *quicProxy) Stop() {
	c.exit = true
}

func (c *quicProxy) Serve() error {
	certPath, err := utils.RetrieveCertsPath()
	if err != nil {
		log.Println("cert file is not exist!", err)
		return err
	}
	pemPath := path.Join(certPath, "client.crt")
	keypath := path.Join(certPath, "client.key")
	cert, err := tls.LoadX509KeyPair(pemPath, keypath)
	if err != nil {
		log.Println("load cert failed", err)
		return err
	}

	serverTCP := net.JoinHostPort(c.config.Local, strconv.Itoa(int(c.config.LocalQuicPort)))
	l, err := net.Listen("tcp", serverTCP)
	if err != nil {
		log.Println("listen failed ", err)
		return err
	}

	defer l.Close()

	for {
		con, err := l.Accept()
		if err != nil {
			log.Println(" accept failed ", err)
			break
		}
		if c.exit {
			log.Println(" Exit Flag is set!!!!")
			if con != nil {
				con.Close()
			}
			break
		}
		go c.serveOn(con, cert)
	}

	return nil
}

func (c *quicProxy) serveOn(con net.Conn, cert tls.Certificate) {
	defer con.Close()
	conn, err := c.tryOpenQuic(cert)
	if err != nil {
		log.Println("open quic failed", err)
		return
	}
	defer conn.CloseWithError(0, "0")

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Println("open stream failed", err)
		return
	}

	defer stream.Close()
	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		_, err := io.Copy(stream, con)
		if err != nil {
			log.Println("write data direction con-->stream failed", err)
		}
		wg.Done()
	}()
	go func() {
		_, err = io.Copy(con, stream)
		if err != nil {
			log.Println("write data direction stream-->con failed", err)
		}
		wg.Done()
	}()
	wg.Wait()
}

func (c *quicProxy) tryOpenQuic(cert tls.Certificate) (quic.Connection, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{protocol},
	}

	quicConf := &quic.Config{}
	serverHost := net.JoinHostPort(c.config.Server, strconv.Itoa(int(c.config.QuicServerPort)))
	conn, err := quic.DialAddr(context.Background(), serverHost, tlsConf, quicConf)
	if err != nil {
		log.Println("can not connect server", serverHost, err)
		return nil, err
	}

	return conn, nil
}
