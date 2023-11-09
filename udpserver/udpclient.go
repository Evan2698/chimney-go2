package udpserver

import (
	"bytes"
	"chimney-go2/mobile"
	"chimney-go2/privacy"
	"chimney-go2/socketcore"
	"chimney-go2/utils"
	"log"
	"net"
)

type udpClient struct {
	udpproxy
	What       string
	protectFun mobile.ProtectSocket
}

// NewUDPClientServer ...
func NewUDPClientServer(listenAddress string, remote string, i privacy.EncryptThings, k []byte, pfun mobile.ProtectSocket) UDPServer {
	return &udpClient{
		udpproxy: udpproxy{
			listen: listenAddress,
			I:      i,
			key:    k,
			Flag:   false,
		},
		What:       remote,
		protectFun: pfun,
	}
}

func (s *udpClient) Stop() {
	s.Flag = true
}

func (s *udpClient) Run() {

	log.Println("local UDP server on ", s.listen)

	udpaddr, err := net.ResolveUDPAddr("udp", s.listen)
	if err != nil {
		log.Println(" UDP addres resolved failed", err)
		return
	}

	socket, err := net.ListenUDP("udp", udpaddr)
	if err != nil {
		log.Println(" can not listen on ", s.listen, " to recv client request.")
		return
	}
	go func(udp *net.UDPConn) {
		defer func() {
			if err := recover(); err != nil {
				log.Println(" fatal error on udp server: ", err)
			}
		}()
		defer udp.Close()

		for {
			data := WantAPiece()
			n, rAddr, err := udp.ReadFromUDP(data)
			if err != nil {
				log.Println(" read info failed ", err)
				ReturnAPice(data)
				continue
			}
			if s.Flag {
				log.Println(" read info failed ", err)
				ReturnAPice(data)
				break
			}

			go s.serveOne(data, rAddr, n, udp)
		}

	}(socket)
}

func (s *udpClient) serveOne(buf []byte, addr *net.UDPAddr, n int, udp *net.UDPConn) {
	defer func() {
		ReturnAPice(buf)
	}()

	out, err := s.I.Compress(buf[:n], s.key)
	if err != nil {
		log.Println("uncompressed failed", err)
		return
	}

	k := s.I.ToBytes()
	total := len(k) + len(out) + 1
	start := utils.Int2Bytes(uint32(total))

	var willdata bytes.Buffer
	willdata.Write(start)
	willdata.WriteByte(byte(len(k)))
	willdata.Write(k)
	willdata.Write(out)

	var socket net.Conn
	if s.protectFun != nil {
		socket, err = socketcore.UDPDail(s.What, s.protectFun)
	} else {
		socket, err = net.Dial("udp", s.What)
	}
	if err != nil {
		log.Println("dial udp failed  ", s.What)
		return
	}

	defer func() {
		socket.Close()
	}()

	_, err = socket.Write(willdata.Bytes())
	if err != nil {
		log.Println("dial udp failed  ", s.What)
		return
	}

	log.Println("send to proxy remote")

	readBuffer := WantAPiece()
	defer func() {
		ReturnAPice(readBuffer)
	}()

	n, err = socket.Read(readBuffer[:len(readBuffer)-512])
	if err != nil {
		log.Println("read from target failed ", err)
		return
	}

	data := readBuffer[:n]

	dataL := utils.Bytes2Int(data[:4])
	if dataL != uint32(len(data[4:])) {
		log.Println("partition of data was lost!!! ")
		return
	}

	I, err := privacy.FromBytes(data[5 : 5+data[4]])
	if err != nil {
		log.Println("got everything  failed", err)
		return
	}

	out, err = I.Uncompress(data[5+data[4]:], s.key)
	if err != nil {
		log.Println("uncompressed failed", err)
		return
	}
	_, err = udp.WriteToUDP(out, addr)

	log.Println("write to result", err)
}
