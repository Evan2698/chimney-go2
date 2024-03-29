package vpnkinds

import (
	"chimney-go2/configure"
	"chimney-go2/proxycore"
	"chimney-go2/quicproxy"
	"errors"
	"log"
)

func runTlsClient(config configure.AppConfig) error {
	tlsClient, err := proxycore.NewTLsClient(config)
	if err != nil {
		log.Println("create tls client failed", err)
		return err
	}
	if tlsClient == nil {
		return errors.New("create client failed")
	}
	defer tlsClient.Close()

	err = tlsClient.RunClient()
	return err
}

func runTlsServer(config configure.AppConfig) error {
	tlsServer, err := proxycore.NewTlsServer(config)
	if err != nil {
		log.Println("create tls server failed", err)
		return err
	}
	err = tlsServer.ListenAndServeTLS()
	return err
}

func runQuicServer(config configure.AppConfig) error {
	quicServer := quicproxy.NewQuicSever(config)
	return quicServer.Serve()
}

func runQuicClient(config configure.AppConfig) error {
	quicServer := quicproxy.NewQuic(config)
	return quicServer.Serve()
}
