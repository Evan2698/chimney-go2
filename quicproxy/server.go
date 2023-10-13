package quicproxy

import (
	"bufio"
	"chimney-go2/configure"
	"chimney-go2/utils"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type QuicServer interface {
	Serve() error
}

type quicServerHolder struct {
	config configure.AppConfig
}

func (s *quicServerHolder) Serve() error {
	certPath, err := utils.RetrieveCertsPath()
	if err != nil {
		log.Println("cert file is not exist!", err)
		return err
	}
	pemPath := path.Join(certPath, "server.crt")
	keypath := path.Join(certPath, "server.key")
	cert, err := tls.LoadX509KeyPair(pemPath, keypath)
	if err != nil {
		log.Println("load cert failed", err)
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{protocol},
	}

	serverHost := net.JoinHostPort(s.config.Server, strconv.Itoa(int(s.config.QuicServerPort)))
	quicConf := &quic.Config{}
	listener, err := quic.ListenAddr(serverHost, tlsConfig, quicConf)
	if err != nil {
		log.Println("quic server listen failed", err)
		return err
	}

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Println("quic server accept failed", err)
			break
		}
		go acceptQuicAccept(conn)
	}

	return err
}

func acceptQuicAccept(conn quic.Connection) {
	defer conn.CloseWithError(0x65, "exit")
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Println("accept stream failed", err)
			break
		}
		go acceptQuicStream(stream)
	}
}

func acceptQuicStream(stream quic.Stream) {
	defer stream.Close()
	reader := bufio.NewReader(stream)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Println("parse http header failed!")
		return
	}
	dest_conn, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
	if err != nil {
		resp := []byte("HTTP/1.1 505")
		stream.Write(resp)
		return
	}
	defer dest_conn.Close()

	if req.Method == http.MethodConnect {
		resp := []byte("HTTP/1.1 200")
		stream.Write(resp)
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go transfer(dest_conn, stream, &wg)
	go transfer(stream, dest_conn, &wg)
	wg.Wait()
}
func transfer(destination io.WriteCloser, source io.ReadCloser, wg *sync.WaitGroup) {
	io.Copy(destination, source)
	wg.Done()
}

func NewQuicSever(c configure.AppConfig) QuicServer {

	return &quicServerHolder{
		config: c,
	}
}
