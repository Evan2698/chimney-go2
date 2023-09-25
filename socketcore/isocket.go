package socketcore

import (
	"chimney-go2/privacy"
	"chimney-go2/utils"
	"errors"
	"log"
	"net"
)

// ISocket ...
type ISocket interface {
	Read() ([]byte, error)
	Write(b []byte) error
	Close()
}

type iSocketHolder struct {
	EChannel net.Conn
	Key      []byte
	I        privacy.EncryptThings
	inBuffer []byte
}

const (
	offset = 512
)

// NewISocket ...
func NewISocket(con net.Conn, i privacy.EncryptThings, key []byte) ISocket {
	return &iSocketHolder{
		EChannel: con,
		Key:      key,
		I:        i,
		inBuffer: Alloc(),
	}
}

func readXBytes(bytes uint32, buffer []byte, con net.Conn) ([]byte, error) {
	defer utils.Trace("readXBytes.readXBytes")()
	if bytes <= 0 {
		return nil, errors.New("0 bytes can not read! ")
	}

	var index uint32
	var err error
	var n int
	for {
		n, err = con.Read(buffer[index:])
		log.Println("read from socket size: ", n, err)
		if err != nil {
			log.Println("error on read_bytes_from_socket ", n, err)
			break
		}
		index = index + uint32(n)

		if index >= bytes {
			log.Println("read count for output ", index, err)
			break
		}
	}
	if index == bytes {
		err = nil
	}

	log.Println("read result size: ", index, err)
	return buffer[:bytes], err
}

func (s *iSocketHolder) Close() {
	log.Println("CLOSE*********")
	if s.inBuffer != nil {
		Free(s.inBuffer)
		s.inBuffer = nil
	}
}

func (s *iSocketHolder) Read() ([]byte, error) {
	defer utils.Trace("iSocketHolder.Read")()

	buffer, err := readXBytes(4, s.inBuffer[:4], s.EChannel)
	if err != nil {
		log.Println("read raw content failed", err)
		return nil, err
	}

	vLen := utils.Bytes2Int(buffer)
	log.Println("read: ", buffer, vLen)

	if vLen > pageSize {
		log.Println("content length is too long", vLen)
		return nil, errors.New("Length is too long")
	}

	buffer, err = readXBytes(vLen, s.inBuffer[:vLen], s.EChannel)
	if err != nil {
		log.Println("read content failed: ", err)
		return nil, err
	}
	out, err := s.I.Uncompress(buffer, s.Key)
	if err != nil {
		log.Println("uncompress failed: ", err)
		return nil, err
	}

	log.Println("Uncompress rEAD: ", vLen)
	return out, nil

}

func writeXBytes(buffer []byte, con net.Conn) (int, error) {
	defer utils.Trace("writeXBytes.writeXBytes")()
	nbytes := uint32(len(buffer))
	var index uint32 = 0
	var err error
	var n int
	for {
		n, err = con.Write(buffer[index:])
		if err != nil {
			log.Println("write bytes error! ", n, err)
			break
		}
		index = index + uint32(n)
		if index >= nbytes {
			break
		}
	}
	if index == nbytes {
		err = nil
	}

	log.Println("writeXBytes >>>>>>", n, err)

	return int(index), err
}

func (s *iSocketHolder) Write(b []byte) error {
	defer utils.Trace("iSocketHolder.Write")()

	out, err := s.I.Compress(b, s.Key)
	if err != nil {
		log.Println("zip content failed: ", err)
		return err
	}
	oLen := len(out)

	if oLen+4 > pageSize {
		log.Println("out of memory!!", oLen+4)
		return errors.New("out of memory")
	}

	vLenBuffer := utils.Int2Bytes(uint32(oLen))
	_, err = writeXBytes(vLenBuffer, s.EChannel)
	if err != nil {
		log.Println("write length of content failed: ", err)
		return err
	}
	_, err = writeXBytes(out, s.EChannel)
	if err != nil {
		log.Println("write content failed: ", err)
		return err
	}

	return nil

}
