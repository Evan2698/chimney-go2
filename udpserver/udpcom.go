package udpserver

import (
	"bytes"
	"chimney-go2/socketcore"
	"chimney-go2/utils"
)

// UDPCom ...
type UDPCom struct {
	Src  socketcore.Socks5Address
	Dst  socketcore.Socks5Address
	Cmd  uint8
	Data []byte
}

//| 1 cmd| 2(len) | 1 type|  ip(domain) target | 2(len) 1 type| ip(domain) src| (3072)data|

// ParseData ..
func ParseData(in []byte) (*UDPCom, error) {
	v := &UDPCom{}

	op := bytes.NewBuffer(in)
	tmp := op.Next(1)
	v.Cmd = tmp[0]
	tmp = op.Next(2)
	ll := utils.Bytes2Uint16(tmp)
	tmp = op.Next(int(ll))
	t := tmp[0]
	ip1 := tmp[1 : len(tmp)-2]
	port := utils.Bytes2Uint16(tmp[len(tmp)-2:])
	vv := &socketcore.Socks5Addr{
		AddressType: t,
		Port:        port,
	}
	if t == 1 || t == 4 {
		vv.IPvX = ip1
	} else if t == 3 {
		vv.Domain = string(ip1)
	}
	v.Dst = vv
	tmp = op.Next(2)
	ll = utils.Bytes2Uint16(tmp)
	tmp = op.Next(int(ll))
	t = tmp[0]
	ip1 = tmp[1 : len(tmp)-2]
	port = utils.Bytes2Uint16(tmp[len(tmp)-2:])

	vv = &socketcore.Socks5Addr{
		AddressType: t,
		Port:        port,
	}
	if t == 1 || t == 4 {
		vv.IPvX = ip1
	} else if t == 3 {
		vv.Domain = string(ip1)
	}
	v.Src = vv

	v.Data = op.Next(op.Len())

	return v, nil
}

// 1 answer |2(len) | 1 type|  ip(domain) target | 2(len) 1 type| ip(domain) src| data(3072)

// ToAnswer ..
func ToAnswer(n *UDPCom) []byte {
	var buffer bytes.Buffer

	buffer.WriteByte(n.Cmd)
	l := n.Dst.GetAddressRawBytes()
	buffer.Write(utils.Uint162Bytes(uint16(len(l) + 1)))
	buffer.WriteByte(n.Dst.GetAddressType())
	buffer.Write(l)
	l = n.Src.GetAddressRawBytes()
	buffer.Write(utils.Uint162Bytes(uint16(len(l) + 1)))
	buffer.WriteByte(n.Src.GetAddressType())
	buffer.Write(l)
	buffer.Write(n.Data)

	return buffer.Bytes()
}
