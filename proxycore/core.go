package proxycore

import (
	"chimney-go2/configure"
	"chimney-go2/utils"
	"crypto/tls"
	"io"
	"log"
	"net"
	"strconv"
)

type MF func(configure.AppConfig) (io.ReadWriteCloser, error)

type ProxySetting struct {
	NetType        string
	NetworkMakeFun MF
	config         configure.AppConfig
	Exit           bool
}

type ClientProxy interface {
	RunClient() error
}

type clientHub struct {
	Settings ProxySetting
	cert     tls.Certificate
}

func NewTLsClient(c configure.AppConfig) ClientProxy {

	certPath, err := utils.RetrieveCertsPath()
	if err != nil {
		log.Println("get cert path error", err)
		return nil
	}

	a := &clientHub{Settings: ProxySetting{
		NetType: "tls",
		NetworkMakeFun: func(ac configure.AppConfig) (io.ReadWriteCloser, error) {
			cert, err := tls.LoadX509KeyPair(certPath+"/client.crt", certPath+"/client.key")
			if err != nil {
				log.Println("load cert path error", err)
				return nil, err
			}
			config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
			serverHost := net.JoinHostPort(ac.Server, strconv.Itoa(int(ac.ServerPort)))
			conn, err := tls.Dial("tcp", serverHost, &config)
			if err != nil {
				log.Println("client: dial:", err)
				return nil, err
			}
			return conn, nil
		},
		config: c,
		Exit:   false,
	},
	}

	return a
}
