package socketcore

import (
	"log"
	"net"
	"time"
)

// ConEX ...
type ConEX interface {
	net.Conn
	ReadXBytes(b []byte) (n int, err error)
}

type conEXHolder struct {
	con net.Conn
}

//NewCon ...
func NewCon(cc net.Conn) ConEX {
	return &conEXHolder{
		con: cc,
	}
}

func (c *conEXHolder) ReadXBytes(buffer []byte) (int, error) {
	bytes := uint32(len(buffer))
	var index uint32
	var err error
	var n int
	for {
		n, err = c.con.Read(buffer[index:])
		log.Println("read raw socket info[ReadXBytes] ", n, err)
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
	return int(index), err

}

func (c *conEXHolder) Read(b []byte) (n int, err error) {
	return c.con.Read(b)
}

func (c *conEXHolder) Write(buffer []byte) (int, error) {
	nbytes := uint32(len(buffer))
	var index uint32 = 0
	var err error
	var n int
	for {
		n, err = c.con.Write(buffer[index:])
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

	log.Println("Write X bytes:", n, err)
	return int(index), err
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *conEXHolder) Close() error {
	return c.con.Close()

}

// LocalAddr returns the local network address.
func (c *conEXHolder) LocalAddr() net.Addr {
	return c.con.LocalAddr()

}

// RemoteAddr returns the remote network address.
func (c *conEXHolder) RemoteAddr() net.Addr {

	return c.con.RemoteAddr()
}

func (c *conEXHolder) SetDeadline(t time.Time) error {

	return c.con.SetDeadline(t)
}

func (c *conEXHolder) SetReadDeadline(t time.Time) error {
	return c.con.SetReadDeadline(t)

}

func (c *conEXHolder) SetWriteDeadline(t time.Time) error {
	return c.con.SetWriteDeadline(t)
}
