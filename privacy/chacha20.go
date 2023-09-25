package privacy

import (
	"bytes"
	"chimney-go2/privacy/chacha20"
	"chimney-go2/utils"
	"crypto/rand"
	"errors"
	"io"
)

type cha20 struct {
	iv []byte
}

const (
	chacha20Name = "CHACHA-20"
	chacha20Code = 0x1235
)

func (chacha *cha20) Compress(src []byte, key []byte) ([]byte, error) {
	defer utils.Trace("Compress")()

	if len(key) != 32 || len(src) == 0 {
		return nil, errors.New("parameter is invalid")
	}

	dst := make([]byte, len(src))

	a, err := chacha20.NewXChaCha(key, chacha.iv)
	if err != nil {
		return nil, err
	}

	a.XORKeyStream(dst, src)

	if len(dst) == 0 {
		return nil, errors.New("compressed failed")
	}

	return dst, nil

}

func (chacha *cha20) Uncompress(src []byte, key []byte) ([]byte, error) {
	return chacha.Compress(src, key)
}

func (chacha *cha20) MakeSalt() []byte {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil
	}
	return nonce
}

func (chacha *cha20) GetIV() []byte {
	return chacha.iv
}

func (chacha *cha20) SetIV(iv []byte) {
	chacha.iv = make([]byte, len(iv))
	copy(chacha.iv, iv)
}

func (chacha *cha20) GetSize() int {
	return 2 + 1 + len(chacha.iv)
}

func (chacha *cha20) ToBytes() []byte {
	var op bytes.Buffer
	mask := utils.Uint162Bytes(chacha20Code)
	op.Write(mask)
	lv := (byte)(len(chacha.iv))
	op.WriteByte(lv)
	if lv > 0 {
		op.Write(chacha.iv)
	}
	return op.Bytes()
}

// From bytes
func (chacha *cha20) FromBytes(v []byte) error {
	op := bytes.NewBuffer(v)
	lvl := op.Next(1)
	if len(lvl) < 1 {
		return errors.New("out of length")
	}

	value := int(lvl[0])
	if value > 0 {
		iv := op.Next(value)
		chacha.SetIV(iv)
	}
	return nil
}

func init() {
	register(chacha20Name, chacha20Code, &cha20{})
}
