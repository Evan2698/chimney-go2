package socks5server

import (
	"bytes"

	"chimney-go2/privacy"
	"chimney-go2/socketcore"
	"chimney-go2/socks5client"
	"chimney-go2/utils"
	"errors"
	"log"
	"net"
	"sync"
)

const (
	protocolTCP  = "tcp"
	protocolQuic = "quic"
	offset4B     = 256
)
const (
	socks5Version          uint8 = 0x5
	socks5NoAuth           uint8 = 0x0
	socks5AuthWithUserPass uint8 = 0x2
)

const (
	socks5CMDConnect uint8 = 0x1
	socks5CMDBind    uint8 = 0x2
	socks5CMDUDP     uint8 = 0x3
)

const (
	socks5AddressIPV4   uint8 = 0x1
	socks5AddressIPV6   uint8 = 0x4
	socks5AddressDomain uint8 = 0x3
)

const (
	socks5ReplySuccess uint8 = 0x0
	socks5ReplyRefused uint8 = 0x5
)

// Server ...
type Server interface {
	Serve() error
	Stop()
}

// SConfig ...
type SConfig struct {
	ServerAddress string
	Network       string
	User          []byte
	Pass          []byte
	Key           []byte
	I             privacy.EncryptThings
	CC            *socketcore.ClientConfig
	Tm            uint32
}

// Server ..
type serverHolder struct {
	ServerAddress string
	Network       string
	User          []byte
	Pass          []byte
	Key           []byte
	I             privacy.EncryptThings
	CC            *socketcore.ClientConfig
	Tm            uint32
	ProtectFun    socketcore.ProtectSocket
	Flag          bool
}

// NewServer ...
func NewServer(settings *SConfig, f socketcore.ProtectSocket) Server {

	return &serverHolder{
		ServerAddress: settings.ServerAddress,
		Network:       settings.Network,
		User:          settings.User,
		Pass:          settings.Pass,
		Key:           settings.Key,
		I:             settings.I,
		CC:            settings.CC,
		Tm:            settings.Tm,
		ProtectFun:    f,
		Flag:          false,
	}
}

func (s *serverHolder) Stop() {
	s.Flag = true
}

// Serve ..
func (s *serverHolder) Serve() error {

	log.Println("which network: ", s.Network)

	// to TCP
	log.Println("server run on " + s.ServerAddress + " with tcp protocol.")
	l, err := net.Listen("tcp", s.ServerAddress)
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
		if s.Flag {
			log.Println("EXIT TCP")
			break
		}

		go s.serveOn(con)
	}

	return err
}

func (s *serverHolder) serveOn(conn net.Conn) error {
	defer utils.Trace("serveOn")()
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on serveOn: ", err)
		}
	}()

	socketcore.SetSocketTimeout(conn, s.Tm)

	err := s.echoHello(conn)
	if err != nil {
		conn.Close()
		log.Println("echo hello say: ", err)
		return err
	}
	dst, err := s.echoConnect(conn)
	if err != nil {
		conn.Close()
		log.Println("connect failed: ", err)
		return err
	}
	socketcore.SetSocketTimeout(dst, s.Tm)

	defer func() {
		dst.Close()
		conn.Close()
	}()

	wg := sync.WaitGroup{}
	wg.Add(2)

	isAuth := len(s.Pass) > 0 && len(s.User) > 0
	if s.CC != nil {
		destination, ok := dst.(socketcore.SocksStream)
		if !ok {
			return errors.New("fatal error")
		}
		vdst := destination.MakeSocket()
		defer vdst.Close()

		go s.proxyWrite(vdst, conn, &wg)
		go s.proxyRead(conn, vdst, &wg)
	} else if isAuth {
		src := socketcore.NewISocket(conn, s.I, s.Key)
		defer src.Close()
		go s.proxyRead(dst, src, &wg)
		go s.proxyWrite(src, dst, &wg)
	} else {
		go s.proxy(dst, conn, &wg)
		go s.proxy(conn, dst, &wg)
	}

	wg.Wait()
	log.Println("exit!!!!!")

	return nil
}

func (s *serverHolder) proxy(dst, src net.Conn, wg *sync.WaitGroup) {
	defer utils.Trace("proxy")()
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on proxy: ", err)
		}
	}()

	tempBuffer := socketcore.Alloc()
	defer socketcore.Free(tempBuffer)
	for {
		n, err := src.Read(tempBuffer)
		if err != nil {
			src.Close()
			log.Println("read src failed ", err)
			break
		}
		_, err = dst.Write(tempBuffer[:n])
		if err != nil {
			dst.Close()
			log.Println("write dst failed ", err)
			break
		}
	}
	log.Println("proxy end!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	wg.Done()
}

func (s *serverHolder) proxyRead(dst net.Conn, src socketcore.ISocket, wg *sync.WaitGroup) {
	defer utils.Trace("proxyRead")()
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on proxyRead: ", err)
		}
	}()
	for {
		out, err := src.Read()
		if err != nil {
			src.Close()
			log.Println("read failed from SSL: ", err)
			break
		}

		_, err = dst.Write(out)
		if err != nil {
			dst.Close()
			log.Println("write bytes to raw failed  ", err)
			break
		}
	}
	wg.Done()
}

func (s *serverHolder) proxyWrite(dst socketcore.ISocket, src net.Conn, wg *sync.WaitGroup) {
	defer utils.Trace("proxyWrite")()
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on proxyWrite: ", err)
		}
	}()

	tempBuffer := socketcore.Alloc()
	defer socketcore.Free(tempBuffer)
	readBuffer := tempBuffer[:len(tempBuffer)-offset4B]

	for {
		n, err := src.Read(readBuffer[:])
		if err != nil {
			src.Close()
			log.Println("read content failed: ", err)
			break
		}

		err = dst.Write(readBuffer[:n])
		if err != nil {
			dst.Close()
			log.Println("write to SSL failed: ", err)
			break
		}
	}
	wg.Done()
}

func (s *serverHolder) echoConnect(conn net.Conn) (net.Conn, error) {
	tmpBuffer := socketcore.AskBuffer()
	defer socketcore.ReleaseBuffer(tmpBuffer)
	var target net.Conn
	n, err := conn.Read(tmpBuffer)
	if err != nil {
		conn.Write([]byte{0x05, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("read connect command failed", err)
		return nil, err
	}
	cmd := tmpBuffer[:n]
	log.Println("connect: ", tmpBuffer[:n])
	if len(cmd) < 4 {
		conn.Write([]byte{0x05, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("cmd length is too short!!")
		return nil, errors.New("cmd length is too short")
	}
	if tmpBuffer[0] != socks5Version {
		conn.Write([]byte{0x05, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("cmd protocol is incorrect")
		return nil, errors.New("cmd protocol is incorrect")
	}
	switch cmd[1] {
	case socks5CMDConnect:
		target, err = s.responseCommandConnect(conn, cmd)
		if err != nil {
			conn.Write([]byte{0x05, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			log.Println("handleConnect", err)
			return nil, errors.New("connect failed")
		}

	case socks5CMDBind:
		fallthrough
	case socks5CMDUDP:
		fallthrough
	default:
		conn.Write([]byte{0x05, 0x0B, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("Not Support this CMD", cmd)
		return nil, errors.New("not Support this CMD")
	}

	return target, nil
}

func (s *serverHolder) responseCommandConnect(conn net.Conn, cmd []byte) (net.Conn, error) {
	isAuth := len(s.Pass) > 0 && len(s.User) > 0
	aocks := &socketcore.Socks5Addr{}
	log.Println("connect command", cmd)
	if isAuth {
		if int(cmd[4]) != len(cmd[5:]) {
			log.Println("content length is incorrect", cmd)
			return nil, errors.New("content length is incorrect")
		}
		content, err := s.I.Uncompress(cmd[5:], s.Key)
		if err != nil {
			log.Println("can not uncompressed command content.", err)
			return nil, err
		}
		port := utils.Bytes2Uint16(content[len(content)-2:])
		aocks.Port = port
		if cmd[3] == socks5AddressIPV4 || cmd[3] == socks5AddressIPV6 {
			aocks.IPvX = net.IP(content[:len(content)-2])
			aocks.AddressType = cmd[3]
		} else if cmd[3] == socks5AddressDomain {
			aocks.Domain = string(content[:len(content)-2])
			aocks.AddressType = cmd[3]
		} else {
			log.Println("responseCommandConnect", cmd)
			return nil, errors.New("content length is incorrect")
		}

	} else {
		aocks.AddressType = cmd[3]
		content := cmd[4:]
		port := utils.Bytes2Uint16(content[len(content)-2:])
		aocks.Port = port
		if cmd[3] == socks5AddressIPV4 || cmd[3] == socks5AddressIPV6 {
			aocks.IPvX = net.IP(content[:len(content)-2])
			aocks.AddressType = cmd[3]
		} else if cmd[3] == socks5AddressDomain {
			aocks.Domain = string(content[1 : len(content)-2])
			aocks.AddressType = cmd[3]
		} else {
			log.Println("connect command is incorrect", cmd)
			return nil, errors.New("connect command is incorrect")
		}
	}
	log.Println("Connect Address:", aocks.String())

	var target net.Conn
	var err error

	if s.CC != nil {
		target, err = s.buildSocksClient(conn, aocks)
		if err != nil {
			log.Println("build socks client failed ", cmd)
			return nil, err
		}
	} else {
		target, err = s.buildClient(conn, aocks)
		if err != nil {
			log.Println("build socks client failed ", cmd)
			return nil, err
		}
	}

	if target != nil {
		socksAddr, err := socketcore.ParseTargetAddress(target.LocalAddr().String())
		if err != nil {
			target.Close()
			log.Println("ParseTargetAddress failed ", cmd)
			return nil, err
		}
		var op bytes.Buffer
		op.Write([]byte{socks5Version, socks5ReplySuccess, 0x00, socksAddr.GetAddressType()})
		content := socksAddr.GetAddressRawBytes()
		if isAuth {
			out, err := s.I.Compress(content, s.Key)
			if err != nil {
				target.Close()
				log.Println("compress connect command failed ", err)
				return nil, err
			}
			op.WriteByte(byte(len(out)))
			op.Write(out)
		} else {
			if socks5AddressDomain == socksAddr.GetAddressType() {
				op.WriteByte(byte(len(content) - 2))
			}
			op.Write(content)
		}
		//var ans bytes.Buffer
		//ans.Write([]byte{0x05, 0x00, 0x00, 0x1, 0x00, 0x00, 0x00, 0x00})
		log.Println("reback: ", op.Bytes())
		conn.Write(op.Bytes())
	}
	err = nil
	if target == nil {
		err = errors.New("NULL socket")
	}
	return target, err
}

func (s *serverHolder) buildClient(conn net.Conn, sa *socketcore.Socks5Addr) (net.Conn, error) {
	defer utils.Trace("buildClient")()
	target, err := net.Dial("tcp", sa.String())
	return target, err
}

func (s *serverHolder) buildSocksClient(conn net.Conn, socks *socketcore.Socks5Addr) (net.Conn, error) {
	defer utils.Trace("buildSocksClient")()
	client := socks5client.NewClient(s.CC, s.ProtectFun)
	return client.Dial(s.CC.Network, socks.String())
}

func (s *serverHolder) echoHello(conn net.Conn) error {
	defer utils.Trace("echoHello")()
	tmpBuffer := socketcore.AskBuffer()
	defer socketcore.ReleaseBuffer(tmpBuffer)

	isAuth := len(s.User) > 0 && len(s.Pass) > 0
	n, err := conn.Read(tmpBuffer)
	if err != nil {
		return err
	}
	res := []byte{socks5Version, 0xff}
	if n < 3 || tmpBuffer[0] != socks5Version {
		conn.Write(res)
		log.Println("client hello message: ", tmpBuffer[:n])
		return errors.New("client hello message error")
	}
	if tmpBuffer[1] < 1 {
		conn.Write(res)
		log.Println("length of method : ", tmpBuffer[:n])
		return errors.New("length of method format error")
	}
	if tmpBuffer[2] == socks5NoAuth {
		if isAuth {
			conn.Write(res)
			return errors.New("not Support client method")
		}
		res = []byte{socks5Version, socks5NoAuth}
		_, err = conn.Write(res)
		if err != nil {
			log.Println("write hello failed (NoAuth)", err)
			return err
		}

	} else if tmpBuffer[2] == socks5AuthWithUserPass {
		if !isAuth {
			conn.Write(res)
			return errors.New("not Support client method X")
		}
		var out bytes.Buffer
		out.Write([]byte{socks5Version, socks5AuthWithUserPass})
		ii := s.I.ToBytes()
		out.WriteByte(byte(len(ii)))
		out.Write(ii)
		_, err = conn.Write(out.Bytes())
		if err != nil {
			log.Println("write hello failed(U&P) ", err)
			return err
		}

		err = s.verifyUserPass(conn)
		if err != nil {
			log.Println("verify user and pass result", err)
			return err
		}

	} else {
		conn.Write(res)
		return errors.New("not implement for other method")
	}
	return nil
}

func (s *serverHolder) verifyUserPass(conn net.Conn) error {
	tmpBuffer := socketcore.AskBuffer()
	defer socketcore.ReleaseBuffer(tmpBuffer)
	res := []byte{socks5Version, 0xff}
	n, err := conn.Read(tmpBuffer)
	if err != nil {
		conn.Write(res)
		return err
	}
	userPass := tmpBuffer[:n]
	if len(userPass) < 10 {
		conn.Write(res)
		return errors.New("user pass protocol is incorrect")
	}
	if userPass[0] != socks5Version {
		conn.Write(res)
		return errors.New("prefix user pass protocol is incorrect")
	}
	usrlen := int(userPass[1])
	user := userPass[2 : 2+usrlen]
	pass := userPass[2+usrlen+1:]
	plen := int(userPass[2+usrlen])

	if usrlen != len(user) || plen != len(pass) {
		conn.Write(res)
		log.Println("user and pass length ", usrlen, user, pass, plen)
		return errors.New("user and pass length error")
	}
	pa, err := s.I.Uncompress(pass, s.Key)
	if err != nil {
		conn.Write(res)
		log.Println("uncompressed user and pass failed ", err)
		return err
	}

	if bytes.Equal(pa, s.Pass) && bytes.Equal(user, s.User) {
		conn.Write([]byte{socks5Version, 0x00})
		log.Println("verify success!")
	} else {
		conn.Write(res)
		log.Println("verify failed ")
		return errors.New("verify failed")
	}

	return nil
}
