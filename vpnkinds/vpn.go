package vpnkinds

import (
	"chimney-go2/configure"
	"strings"
)

const (
	KINDSOCKS5 = "socks5"
	KINDQUIC   = "quic"
	KINDTLS    = "tls"
	KINDBOTH   = "both"
)

func RunServer(config configure.AppConfig, isServer bool) {

	if isServer {
		if strings.Compare(config.Which, KINDSOCKS5) == 0 {
			runSocks5Server(config)
		} else if strings.Compare(config.Which, KINDTLS) == 0 {
			runTlsServer(config)
		} else if strings.Compare(config.Which, KINDQUIC) == 0 {
			runQuicServer(config)
		} else if strings.Compare(config.Which, KINDBOTH) == 0 {
			go runSocks5Server(config)
			runQuicServer(config)
		}

	} else {
		if strings.Compare(config.Which, KINDSOCKS5) == 0 {
			runSocks5Client(config)
		} else if strings.Compare(config.Which, KINDTLS) == 0 {
			runTlsClient(config)
		} else if strings.Compare(config.Which, KINDQUIC) == 0 {
			runQuicClient(config)
		} else if strings.Compare(config.Which, KINDBOTH) == 0 {
			go runSocks5Client(config)
			runQuicClient(config)
		}
	}

}
