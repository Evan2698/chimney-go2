package socketcore

import (
	"chimney-go2/privacy"
	"net"
	"time"
)

// ClientConfig ...
type ClientConfig struct {
	User    []byte
	Pass    []byte
	Key     []byte
	Proxy   string
	Tm      uint32
	Network string
}

// SocksStream ..
type SocksStream interface {
	net.Conn
	GetBoundAddress() Socks5Address
	MakeSocket() ISocket
}

// Socks5Socket ..
type Socks5Socket struct {
	Raw        net.Conn
	Socks5Addr *Socks5Addr
	I          privacy.EncryptThings
	Key        []byte
}

// MakeSocket ...
func (s *Socks5Socket) MakeSocket() ISocket {
	return NewISocket(s.Raw, s.I, s.Key)
}

// GetBoundAddress ...
func (s *Socks5Socket) GetBoundAddress() Socks5Address {
	return s.Socks5Addr
}

// Read
func (s *Socks5Socket) Read(b []byte) (n int, err error) {
	return s.Raw.Read(b)
}

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (s *Socks5Socket) Write(b []byte) (n int, err error) {
	return s.Raw.Write(b)
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (s *Socks5Socket) Close() error {
	err := s.Raw.Close()
	s.Socks5Addr = nil
	s.Raw = nil
	return err
}

// LocalAddr returns the local network address.
func (s *Socks5Socket) LocalAddr() net.Addr {
	if s.Socks5Addr != nil {
		return s.Socks5Addr
	}

	return s.Raw.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (s *Socks5Socket) RemoteAddr() net.Addr {
	if s.Socks5Addr != nil {
		return s.Socks5Addr
	}

	return &net.TCPAddr{
		IP:   []byte("127.0.0.1"),
		Port: 1111,
	}
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to Read or
// Write. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
//
// Note that if a TCP connection has keep-alive turned on,
// which is the default unless overridden by Dialer.KeepAlive
// or ListenConfig.KeepAlive, then a keep-alive failure may
// also return a timeout error. On Unix systems a keep-alive
// failure on I/O can be detected using
// errors.Is(err, syscall.ETIMEDOUT).
func (s *Socks5Socket) SetDeadline(t time.Time) error {

	return s.Raw.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (s *Socks5Socket) SetReadDeadline(t time.Time) error {
	return s.Raw.SetReadDeadline(t)

}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (s *Socks5Socket) SetWriteDeadline(t time.Time) error {
	return s.Raw.SetWriteDeadline(t)
}
