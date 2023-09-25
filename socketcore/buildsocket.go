package socketcore

import (
	"errors"
	"log"
	"net"
	"syscall"
)

// TCPDail for create tcp connection
func TCPDail(host string, pFun ProtectSocket) (net.Conn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", host)
	if err != nil {

		log.Println("parse tcp address failed!", host, err)
		return nil, err
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		log.Println("create tcp socket failed!!!", err)
		return nil, err
	}
	defer syscall.Close(fd)
	outcon, err := connectSocketCoreBase(fd, tcpAddr.IP, tcpAddr.Port, pFun, func(f int) error {

		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, 128)
		if err != nil {
			log.Println("set socket attributes ", err)
			return err
		}
		return nil
	})

	return outcon, nil
}

func buildSocketAddress(ip net.IP, port int) (sa syscall.Sockaddr, err error) {

	if ip == nil {
		return nil, errors.New("none address")
	}

	if ip.To4() == nil {
		ipa := ip.To16()
		sa = &syscall.SockaddrInet6{
			Port: port,
			Addr: [16]byte{ipa[0], ipa[1], ipa[2], ipa[3],
				ipa[4], ipa[5], ipa[6],
				ipa[7], ipa[8], ipa[9],
				ipa[10], ipa[11], ipa[12],
				ipa[13], ipa[14], ipa[15]},
		}
	} else {
		ipa := ip.To4()
		sa = &syscall.SockaddrInet4{
			Port: port,
			Addr: [4]byte{ipa[0], ipa[1], ipa[2], ipa[3]},
		}
	}

	return sa, err
}

// UDPDail for android
func UDPDail(host string, pFun ProtectSocket) (net.Conn, error) {

	tcpAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		log.Print("parse tcp address failed: ", err)
		return nil, err
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		log.Println("create udp socket failed!!!", err)
		return nil, err
	}
	defer syscall.Close(fd)

	outcon, err := connectSocketCoreBase(fd, tcpAddr.IP, tcpAddr.Port, pFun, nil)

	return outcon, err
}
