package socketcore

import (
	"chimney-go/mobile"
	"log"
	"net"
	"os"
	"syscall"
)

func connectSocketCoreBase(fd int,
	ip net.IP, port int,
	pFun mobile.ProtectSocket,
	funAttr func(fd int) error) (net.Conn, error) {

	sa, err := buildSocketAddress(ip, port)
	if err != nil {
		log.Println("construct network address failed!", err)
		return nil, err
	}

	if pFun != nil {
		ret := pFun.Protect(fd)
		log.Println("protect socket: ", ret)
	}

	if funAttr != nil {
		err = funAttr(fd)
		if err != nil {
			log.Println("set socket attrbuites failed!! ", err)
			return nil, err
		}
	}

	err = syscall.Connect(fd, sa)
	if err != nil {
		log.Println("connect remote end failed!!!!", err)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "")
	defer file.Close()

	outcon, err := net.FileConn(file)
	if err != nil {
		log.Println("convert to FileConn failed:", err)
		return nil, err
	}
	return outcon, nil
}