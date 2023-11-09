package udpserver

import "sync"

const (
	pageSize = 4096
)

var (
	memorypooltmp = &sync.Pool{
		New: func() interface{} {
			return make([]byte, pageSize)
		},
	}
)

// WantAPiece ...
func WantAPiece() []byte {
	return memorypooltmp.Get().([]byte)
}

// ReturnAPice ..
func ReturnAPice(b []byte) {
	if b != nil {
		memorypooltmp.Put(b)
	}
}
