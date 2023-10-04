package vpnkinds

import "chimney-go2/configure"

const (
	KINDSOCKS5 = "socks5"
	KINDQUIC   = "quic"
	KINDTLS    = "tls"
	KINDBOTH   = "both"
)

func RunServer(config configure.AppConfig, isServer bool) {

	if isServer {
		if config.Which == KINDSOCKS5 {
			runSocks5Server(config)
		} else if config.Which == KINDTLS {
			runTlsServer(config)
		} else if config.Which == KINDQUIC {

			print("")
		} else if config.Which == KINDBOTH {

			runSocks5Server(config)
		}

	} else {
		if config.Which == KINDSOCKS5 {
			runSocks5Client(config)
		} else if config.Which == KINDTLS {
			runTlsClient(config)
		} else if config.Which == KINDQUIC {

			print("")
		} else if config.Which == KINDBOTH {

			runSocks5Client(config)
		}
	}

}
