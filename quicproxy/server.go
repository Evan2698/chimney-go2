package quicproxy

import (
	"bufio"
	"bytes"
	"chimney-go2/configure"
	"chimney-go2/utils"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

var values = []string{
	"X-Client-Ip",
	"HTTP_CLIENT_IP",
	"HTTP_X_FORWARDED_FOR",
}

var hostIP = ""

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

func writeHttpStatus(sb bytes.Buffer, status string) {
	sb.WriteString(fmt.Sprintf("HTTP/1.1 %s OK\r\n", status))
}

func handleTunneling(r *http.Request, stream quic.Stream) error {
	var sb bytes.Buffer
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		writeHttpStatus(sb, "501")
		stream.Write(sb.Bytes())
		return nil
	}
	defer dest_conn.Close()
	writeHttpStatus(sb, "200")
	stream.Write(sb.Bytes())
	wg := sync.WaitGroup{}
	wg.Add(2)
	go transfer(dest_conn, stream, &wg)
	go transfer(stream, dest_conn, &wg)
	wg.Wait()

	return nil
}

func formatHeader(sb bytes.Buffer, key string, value string) {
	sb.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
}

func copyHeader(sb bytes.Buffer, header http.Header) {
	for k, vv := range header {

		flag := false
		key := strings.ToLower(k)
		for _, v := range values {
			ip := strings.ToLower(v)
			if strings.Contains(key, ip) {
				flag = true
				break
			}
		}

		if flag {
			formatHeader(sb, k, hostIP)
			continue
		}

		for _, v := range vv {
			formatHeader(sb, k, v)
		}
	}

	sb.WriteString("\r\n")
}

func handleHTTP(r *http.Request, stream quic.Stream) error {
	var sb bytes.Buffer
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		writeHttpStatus(sb, "501")
		stream.Write(sb.Bytes())
		return nil
	}
	defer resp.Body.Close()
	writeHttpStatus(sb, "200")
	copyHeader(sb, resp.Header)
	stream.Write(sb.Bytes())

	io.Copy(stream, resp.Body)
	return nil
}

func acceptQuicStream(stream quic.Stream) {
	defer stream.Close()
	reader := bufio.NewReader(stream)
	r, err := http.ReadRequest(reader)
	if err != nil {
		log.Println("parse http header failed!")
		return
	}

	if r.Method == http.MethodConnect {
		handleTunneling(r, stream)
	} else {
		handleHTTP(r, stream)
	}
}

func transfer(destination io.WriteCloser, source io.ReadCloser, wg *sync.WaitGroup) {
	io.Copy(destination, source)
	wg.Done()
}

func NewQuicSever(c configure.AppConfig) QuicServer {

	hostIP = c.Server
	return &quicServerHolder{
		config: c,
	}
}
