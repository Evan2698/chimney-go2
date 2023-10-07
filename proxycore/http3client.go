package proxycore

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

	"github.com/quic-go/quic-go"
)

type http3ClientHub struct {
	clientHub
	Conn quic.Connection
}

func NewHttp3Client(c configure.AppConfig) (ClientProxy, error) {

	certPath, err := utils.RetrieveCertsPath()
	if err != nil {
		log.Println("get cert path error", err)
		return nil, err
	}
	pemPath := path.Join(certPath, "client.crt")
	keypath := path.Join(certPath, "client.key")
	cert, err := tls.LoadX509KeyPair(pemPath, keypath)
	if err != nil {
		log.Println("load cert path error", err)
		return nil, err
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert},
		InsecureSkipVerify: true,
		NextProtos:         []string{httpProtocol}}
	serverHost := net.JoinHostPort(c.Server, strconv.Itoa(int(c.ServerPort)))
	quicConf := &quic.Config{}

	conn, err := quic.DialAddr(context.Background(), serverHost, tlsConf, quicConf)
	if err != nil {
		log.Println("DialAddr failed", err)
		return nil, err
	}

	clientProxy := &http3ClientHub{
		clientHub: clientHub{
			Settings: ProxySetting{
				NetType: "http3",
				NetworkMakeFun: func(ac configure.AppConfig) (io.ReadWriteCloser, error) {
					stream, err := conn.OpenStreamSync(context.Background())
					if err != nil {
						log.Println("open stream sync failed", err)
					}
					return stream, err
				},
				config: c,
				Exit:   false,
			},
			cert: cert,
		},
		Conn: conn,
	}

	return clientProxy, nil
}

func (c *http3ClientHub) Close() {

	if c.Conn != nil {
		c.Conn.CloseWithError(0, "common")
	}
}
