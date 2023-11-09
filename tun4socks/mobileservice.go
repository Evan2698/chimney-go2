package tun4socks

import (
	"chimney-go2/lwip2socks/common/dns/cache"
	"chimney-go2/lwip2socks/core"
	"chimney-go2/lwip2socks/proxy/socks"
	"chimney-go2/mobile"
	"chimney-go2/privacy"
	"chimney-go2/socketcore"
	"chimney-go2/socks5server"
	"chimney-go2/udpserver"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

// BindSocket How do you think about ?
type BindSocket interface {
	mobile.ProtectSocket
}

// VPNParam for start vpn service
type VPNParam struct {
	FileDescriptor int
	RemoteServer   string
	Port           int
	UDPPort        int
	PassWD         string
	CallBack       BindSocket
}

// StartVPN for tun-->socks5
func StartVPN(param *VPNParam) int {
	go func() {
		startChimney(param.PassWD, param.RemoteServer, param.Port, param.UDPPort, param.CallBack)
	}()
	startLwIP(param.FileDescriptor)
	return 0
}

// StopVPN ...
func StopVPN() int {

	stopChimney()
	stopLwIP()

	return 0
}

var gudp udpserver.UDPServer
var gtcp socks5server.Server

func startChimney(pw string, remoteHost string, port, dnsPort int, pFun mobile.ProtectSocket) {
	user := privacy.BuildMacHash(privacy.MakeCompressKey(pw), "WhereRU")
	serverHost := net.JoinHostPort(remoteHost, strconv.Itoa(port))
	settings := &socketcore.ClientConfig{
		User:    user,
		Pass:    user,
		Key:     privacy.MakeCompressKey(pw),
		Proxy:   serverHost,
		Tm:      600,
		Network: "tcp",
	}
	sconf := &socks5server.SConfig{
		ServerAddress: net.JoinHostPort("127.0.0.1", "9999"),
		Network:       "tcp",
		CC:            settings,
		Tm:            600,
	}
	go func() {
		localListen := net.JoinHostPort("127.0.0.1", "9999")
		remote := net.JoinHostPort(remoteHost, strconv.Itoa(dnsPort))
		gudp = udpserver.NewUDPClientServer(localListen, remote,
			privacy.NewMethodWithName("CHACHA-20"),
			privacy.MakeCompressKey(pw), pFun)
		gudp.Run()
	}()
	gtcp = socks5server.NewServer(sconf, pFun)
	gtcp.Serve()
}

func stopChimney() {
	if gtcp != nil {
		gtcp.Stop()
	}

	if gudp != nil {
		gudp.Stop()
	}
}

var dnsCache = cache.NewDNSCache()

var lwipWriter core.LWIPStack = nil

var tun *os.File

func startLwIP(fd int) {
	lwipWriter = core.NewLWIPStack()
	if lwipWriter == nil {
		log.Println("fetal error! create lwip stack failed!")
		return
	}

	tun = os.NewFile(uintptr(fd), "")

	core.RegisterTCPConnHandler(socks.NewTCPHandler("127.0.0.1", 9999))
	core.RegisterUDPConnHandler(socks.NewUDPHandler("127.0.0.1", 9999, 180*time.Second, dnsCache))

	core.RegisterOutputFn(func(data []byte) (int, error) {
		return tun.Write(data)
	})

	go func() {
		n, err := io.Copy(lwipWriter, tun)
		if err != nil {
			log.Println("tun will exit!!!", err)
		}
		log.Println("log failed.", n)
	}()
}

func stopLwIP() {
	if tun != nil {
		tun.Close()
		tun = nil
	}
	time.Sleep(2 * time.Second)

	if lwipWriter != nil {
		lwipWriter.Close()
		lwipWriter = nil
	}
}
