package vpnkinds

import (
	"chimney-go2/configure"
	"chimney-go2/privacy"
	"chimney-go2/socketcore"
	"chimney-go2/socks5server"
	"net"
	"strconv"
)

const (
	protocolTCP = "tcp"
)

func runSocks5Server(config configure.AppConfig) {
	user := privacy.BuildMacHash(privacy.MakeCompressKey(config.Password), "WhereRU")

	serverTCP := net.JoinHostPort(config.Server, strconv.Itoa(int(config.ServerPort)))

	sconf := &socks5server.SConfig{
		ServerAddress: serverTCP,
		Network:       protocolTCP,
		Tm:            config.Timeout,
		User:          user,
		Pass:          user,
		Key:           privacy.MakeCompressKey(config.Password),
		I:             privacy.NewMethodWithName(config.Method),
	}
	ss := socks5server.NewServer(sconf, nil)
	ss.Serve()
}

func runSocks5Client(config configure.AppConfig) {
	user := privacy.BuildMacHash(privacy.MakeCompressKey(config.Password), "WhereRU")
	serverHost := net.JoinHostPort(config.Server, strconv.Itoa(int(config.ServerPort)))
	settings := &socketcore.ClientConfig{
		User:    user,
		Pass:    user,
		Key:     privacy.MakeCompressKey(config.Password),
		Proxy:   serverHost,
		Tm:      config.Timeout,
		Network: protocolTCP,
	}

	sconf := &socks5server.SConfig{
		ServerAddress: net.JoinHostPort(config.Local, strconv.Itoa(int(config.LocalPort))),
		Network:       protocolTCP,
		CC:            settings,
		Tm:            config.Timeout,
	}
	ss := socks5server.NewServer(sconf, nil)
	ss.Serve()
}
