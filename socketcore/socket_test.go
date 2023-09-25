package socketcore

import (
	"testing"
)

func TestSocket(t *testing.T) {

	con, err := TCPDail("127.0.0.1:1080", nil)
	if err != nil {
		t.Log(err)
	}

	defer con.Close()

	n, err := con.Write([]byte{5, 1, 0})
	if err != nil {
		t.Log(err, n)
	}

	buffer := make([]byte, 250)
	n, err = con.Read(buffer)

	t.Log(err, n, buffer[:n])

}
