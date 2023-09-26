package proxycore

import (
	"io"
	"log"
	"net"
	"strconv"
)

func RunClient(settings ProxySetting) error {

	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on serveOn: ", err)
		}
	}()

	config := settings.config
	serverTCP := net.JoinHostPort(config.Local, strconv.Itoa(int(config.LocalPort)))
	l, err := net.Listen("tcp", serverTCP)
	if err != nil {
		log.Println("listen failed ", err)
		return err
	}

	defer l.Close()

	for {
		con, err := l.Accept()
		if err != nil {
			log.Println(" accept failed ", err)
			break
		}
		go serveOn(con, settings)
	}

	return nil

}

func serveOn(con net.Conn, settings ProxySetting) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on serveOn: ", err)
		}
	}()

	defer con.Close()
	dest := settings.NetworkMakeFun(settings.config)
	defer dest.Close()

	go io.Copy(dest, con)
	go io.Copy(con, dest)
}
