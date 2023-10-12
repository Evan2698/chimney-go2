package vpnkinds

import (
	"chimney-go2/configure"
	"chimney-go2/proxycore"
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
