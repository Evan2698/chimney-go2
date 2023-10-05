package proxycore

import (
	"io"
	"log"
	"net"
	"strconv"
	"sync"
)

func (c *clientHub) RunClient() error {

	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on serveOn: ", err)
		}
	}()

	config := c.Settings.config
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
		if c.Settings.Exit {
			log.Println(" accept failed ", err)
			break
		}
		go c.serveOn(con)
	}

	return nil

}

func (c *clientHub) serveOn(con net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on serveOn: ", err)
		}
	}()

	defer con.Close()
	dest, err := c.Settings.NetworkMakeFun(c.Settings.config)
	if err != nil {
		log.Print("create client tls connection failed~", err)
		return
	}
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

func (c *clientHub) Close() {

}
