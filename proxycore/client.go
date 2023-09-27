package proxycore

import (
	"io"
	"log"
	"net"
	"strconv"
	"sync"
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

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		io.Copy(dest, con)
		wg.Done()
	}()
	go func() {
		io.Copy(con, dest)
		wg.Done()
	}()

	wg.Wait()

	log.Print("client handle once!!!!!!!")

}
