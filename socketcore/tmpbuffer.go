package socketcore

import "sync"

const (
	tmpsize = 512
)

var (
	memorypool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, tmpsize)
		},
	}
)

// AskBuffer ...
func AskBuffer() []byte {
	return memorypool.Get().([]byte)
}

// ReleaseBuffer ..
func ReleaseBuffer(b []byte) {
	if b != nil {
		memorypool.Put(b)
	}
}
