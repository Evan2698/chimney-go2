package quicproxy

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type QuicStream struct {
	Connect quic.Connection
	Stream  quic.Stream
}

type QuicConn interface {
	net.Conn
}

func (s *QuicStream) Read(b []byte) (n int, err error) {
	n, err = s.Stream.Read(b)
	return n, err
}

func (s *QuicStream) Write(b []byte) (n int, err error) {
	n, err = s.Stream.Write(b)
	return n, err
}

func (s *QuicStream) Close() error {
	err := s.Stream.Close()
	s.Connect.CloseWithError(0x45, "op")
	return err
}

// LocalAddr returns the local network address, if known.
func (s *QuicStream) LocalAddr() net.Addr {
	return s.Connect.LocalAddr()
}

// RemoteAddr returns the remote network address, if known.
func (s *QuicStream) RemoteAddr() net.Addr {
	return s.Connect.RemoteAddr()
}

func (s *QuicStream) SetDeadline(t time.Time) error {
	return s.Stream.SetDeadline(t)
}

func (s *QuicStream) SetReadDeadline(t time.Time) error {
	return s.Stream.SetReadDeadline(t)
}

func (s *QuicStream) SetWriteDeadline(t time.Time) error {
	return s.Stream.SetWriteDeadline(t)
}
