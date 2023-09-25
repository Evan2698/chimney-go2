package socks5client

import (
	"bytes"

	"chimney-go2/privacy"
	"chimney-go2/socketcore"
	"chimney-go2/utils"
	"errors"
	"io"
	"log"
	"net"
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

// Socks5Client ..
type Socks5Client interface {
	Dial(network, target string) (socketcore.SocksStream, error)
	Close()
}

// socksHolder ..
type socksHolder struct {
	Settings   *socketcore.ClientConfig
	tmpBuffer  []byte
	I          privacy.EncryptThings
	FunProtect socketcore.ProtectSocket
}

// NewClient ..
func NewClient(settings *socketcore.ClientConfig, f socketcore.ProtectSocket) Socks5Client {
	return &socksHolder{
		Settings:   settings,
		tmpBuffer:  socketcore.AskBuffer(),
		FunProtect: f,
	}
}

// Dial ..
func (c *socksHolder) Dial(network, target string) (socketcore.SocksStream, error) {
	defer utils.Trace("Dial")()
	log.Println("proxy addr: ", c.Settings.Proxy, network)
	con, err := buildGeneralSocket(c.Settings.Proxy, network, c.Settings.Tm, c.FunProtect)
	if err != nil {
		log.Println("create connection socket failed: ", err)
		return nil, err
	}
	if err = c.sayHello(con); err != nil {
		con.Close()
		log.Println("say hello failed! ", err)
		return nil, err
	}

	if err = c.authenticateUser(con); err != nil {
		con.Close()
		log.Println("authenticate failed! ", err)
		return nil, err
	}
	newcon, err := c.sendRequest(con, target)
	if err != nil {
		con.Close()
		log.Println("send command failed! ", err)
		return nil, err
	}

	return newcon, nil
}

func (c *socksHolder) sayHello(writer io.ReadWriteCloser) error {
	isAuth := len(c.Settings.User) > 0 && len(c.Settings.Pass) > 0
	welcome := []byte{socks5Version, 1, socks5NoAuth}
	if isAuth {
		welcome = []byte{socks5Version, 1, socks5AuthWithUserPass}
	}
	if _, err := writer.Write(welcome); err != nil {
		log.Println("hello message failed: ", err)
		return err
	}
	return nil
}

func (c *socksHolder) authenticateUser(con io.ReadWriteCloser) error {

	n, err := con.Read(c.tmpBuffer)
	if err != nil {
		log.Println("hello response read failed: ", err)
		return err
	}

	if n < 2 || c.tmpBuffer[0] != socks5Version {
		log.Println("server protocol format is incorrect : ", c.tmpBuffer[:n])
		return errors.New("server protocol format is incorrect")
	}
	isAuth := len(c.Settings.User) > 0 && len(c.Settings.Pass) > 0
	method := c.tmpBuffer[1]
	switch method {
	case socks5NoAuth:
		if isAuth {
			log.Println("server & client are inconsistent ", c.tmpBuffer[:n])
			return errors.New("server & client are inconsistent")
		}
	case socks5AuthWithUserPass:
		if !isAuth {
			log.Println("server & client are inconsistent  (socks5AuthWithUserPass)", c.tmpBuffer[:n])
			return errors.New("server & client are inconsistent")
		}

		if n < 5 {
			log.Println("custom protocol is incorrect!! ", c.tmpBuffer[:n])
			return errors.New("custom protocol is incorrect")
		}

		aLen := int(c.tmpBuffer[2])
		aCon := c.tmpBuffer[3:n]
		if aLen != len(aCon) {
			log.Println("encrypt bytes format is incorrect!!  ", c.tmpBuffer[:n])
			return errors.New("encrypt bytes format is incorrect")
		}
		i, err := privacy.FromBytes(aCon)
		if err != nil {
			log.Println("parse I failed  ", err, aCon)
			return err
		}
		c.I = i

		user := c.Settings.User
		passOrigin := c.Settings.Pass
		pass, err := c.I.Compress(passOrigin, c.Settings.Key)
		if err != nil {
			log.Println("compress pass failed ", err)
			return err
		}

		var out bytes.Buffer
		out.WriteByte(socks5Version)
		out.WriteByte(byte(len(user)))
		out.Write(user)
		out.WriteByte(byte(len(pass)))
		out.Write(pass)
		if _, err = con.Write(out.Bytes()); err != nil {
			log.Println("send user and pass failed! ", err)
			return err
		}

		n, err = con.Read(c.tmpBuffer)
		if err != nil {
			log.Println("read authentication response failed! ", err)
			return err
		}
		if n != 2 {
			log.Println("authentication result format is incorrect ! ", c.tmpBuffer[:n])
			return errors.New("authentication result format is incorrect")
		}
		if !bytes.Equal([]byte{socks5Version, 0x00}, c.tmpBuffer[:n]) {
			log.Println("authentication result is incorrect ! ", c.tmpBuffer[:n])
			return errors.New("authentication result is incorrect")
		}

	default:
		return errors.New("Not Support")
	}

	return nil
}

func (c *socksHolder) sendRequest(con net.Conn, target string) (socketcore.SocksStream, error) {
	rawAddr, err := socketcore.ParseTargetAddress(target)
	if err != nil {
		log.Println("parse target address failed ", err)
		return nil, err
	}
	isAuth := len(c.Settings.User) > 0 && len(c.Settings.Pass) > 0
	var op bytes.Buffer
	op.Write([]byte{socks5Version, socks5CMDConnect, 0x00, rawAddr.GetAddressType()})
	content := rawAddr.GetAddressRawBytes()
	if isAuth {
		if len(c.Settings.Key) < 1 || c.I == nil {
			return nil, errors.New("key and I oops")
		}
		out, err := c.I.Compress(content, c.Settings.Key)
		if err != nil {
			log.Println("compress connect command failed ", err)
			return nil, err
		}
		op.WriteByte(byte(len(out)))
		op.Write(out)
	} else {
		if socks5AddressDomain == rawAddr.GetAddressType() {
			op.WriteByte(byte(len(content) - 2))
		}
		op.Write(content)
	}
	if _, err = con.Write(op.Bytes()); err != nil {
		log.Println("send request failed ", err)
		return nil, err
	}

	// read request response
	n, err := con.Read(c.tmpBuffer[:])
	if err != nil {
		log.Println("request response read failed ", err)
		return nil, err
	}

	if n < 10 || !bytes.Equal(c.tmpBuffer[:3], []byte{socks5Version, 0x00, 00}) {
		log.Println("there is a format error in response ", c.tmpBuffer[:n])
		return nil, err
	}
	atype := c.tmpBuffer[3]
	response := c.tmpBuffer[4:n]

	var addr *socketcore.Socks5Addr
	if isAuth {
		if int(response[0]) != len(response[1:]) {
			log.Println("read response failed ", c.tmpBuffer[:n])
			return nil, errors.New("read response failed ")
		}

		out, err := c.I.Uncompress(response[1:], c.Settings.Key)
		if err != nil {
			log.Println("uncompress address failed ", err)
			return nil, err
		}
		addr = &socketcore.Socks5Addr{
			AddressType: atype,
			Port:        utils.Bytes2Uint16(out[len(out)-2:]),
		}
		if socks5AddressIPV4 == atype || socks5AddressIPV6 == atype {
			addr.IPvX = net.IP(out[:len(out)-2])
		} else if socks5AddressDomain == atype {
			addr.Domain = string(out[:len(out)-2])
		} else {
			log.Println("address type error:", atype, c.tmpBuffer[3])
			return nil, errors.New("can not support this type of address")
		}

	} else {
		addr = &socketcore.Socks5Addr{
			AddressType: atype,
			Port:        utils.Bytes2Uint16(response[len(response)-2:]),
		}
		if socks5AddressIPV4 == atype || socks5AddressIPV6 == atype {
			addr.IPvX = net.IP(response[:len(response)-2])
		} else if socks5AddressDomain == atype {
			addr.Domain = string(response[1 : len(response)-2])
		} else {
			log.Println("address type error:", atype, c.tmpBuffer[:n])
			return nil, errors.New("can not support this type of address")
		}
	}
	log.Println("bound address:[" + addr.String() + "]")
	return &socketcore.Socks5Socket{
		Raw:        con,
		Socks5Addr: addr,
		I:          c.I,
		Key:        c.Settings.Key,
	}, nil
}

func (c *socksHolder) Close() {
	if c.tmpBuffer != nil {
		socketcore.ReleaseBuffer(c.tmpBuffer)
		c.tmpBuffer = nil
	}
}
