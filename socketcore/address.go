package socketcore

import (
	"bytes"
	"chimney-go2/utils"
	"net"
	"strconv"
)

// Socks5Address ..
type Socks5Address interface {
	net.Addr
	GetAddressType() uint8
	GetAddressRawBytes() []byte
	GetPort() uint16
}

// Socks5Addr ..
type Socks5Addr struct {
	AddressType uint8
	IPvX        net.IP
	Domain      string
	Port        uint16
	NetType     string
}

// Network ..
func (a *Socks5Addr) Network() string {
	if len(a.NetType) == 0 {
		return "socks5"
	}
	return a.NetType
}

// String ..
func (a *Socks5Addr) String() string {
	if a.IPvX != nil {
		if a.AddressType == 0x1 {
			return net.JoinHostPort(a.IPvX.To4().String(), strconv.Itoa(int(a.Port)))
		}
		return net.JoinHostPort(a.IPvX.String(), strconv.Itoa(int(a.Port)))
	}
	return net.JoinHostPort(a.Domain, strconv.Itoa(int(a.Port)))
}

// GetAddressType ..
func (a *Socks5Addr) GetAddressType() uint8 {
	return a.AddressType
}

// GetAddressRawBytes ..
func (a *Socks5Addr) GetAddressRawBytes() []byte {
	var hello bytes.Buffer
	if a.IPvX != nil {
		if a.AddressType == 0x1 {
			hello.Write(a.IPvX.To4())
		} else {
			hello.Write(a.IPvX)
		}
	} else {
		hello.Write([]byte(a.Domain))
	}
	hello.Write(utils.Port2Bytes(a.Port))
	return hello.Bytes()
}

// GetPort ..
func (a *Socks5Addr) GetPort() uint16 {
	return a.Port
}

// ParseTargetAddress ...
func ParseTargetAddress(host string) (Socks5Address, error) {
	s, p, err := net.SplitHostPort(host)
	if err != nil {
		return nil, err
	}
	np, _ := strconv.Atoi(p)
	v := &Socks5Addr{
		IPvX: net.ParseIP(s),
		Port: uint16(np),
	}
	if v.IPvX == nil {
		v.Domain = s
		v.AddressType = 0x3
	} else {
		v.AddressType = 0x1
		if v.IPvX.To4() == nil {
			v.AddressType = 0x4
		}
	}
	return v, nil
}
