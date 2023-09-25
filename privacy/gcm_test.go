package privacy

import (
	"encoding/hex"
	"strings"
	"testing"
)

func tospace(s string) string {

	return strings.ToUpper(s)
}

func TestGCM(t *testing.T) {

	iv := []byte("123456789012123456789012")
	src := []byte("Im a secret message!")
	key := []byte("12345678901234567890123456789012")

	cha20 := NewMethodWithName("CHACHA-20")
	cha20.SetIV(iv)
	out, err := cha20.Compress(src, key)
	t.Log(strings.ToUpper(hex.EncodeToString(out)), err)
}
