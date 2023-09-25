package socks5client

import (
	"chimney-go2/socketcore"
	"chimney-go2/utils"
	"log"
	"net"
)

func buildGeneralSocket(host, network string, tm uint32, profect socketcore.ProtectSocket) (con net.Conn, err error) {
	defer utils.Trace("buildGeneralSocket")()

	log.Println("function: ", host, network)

	log.Println("builcConnect: ", host)
	if profect != nil {
		con, err = socketcore.TCPDail(host, profect)
	} else {
		con, err = net.Dial("tcp", host)
	}
	if err == nil {
		socketcore.SetSocketTimeout(con, tm)
	}
	return con, err
}
