// Package keygen designed for keys generation
package keygen

import (
	"crypto/rand"
	"io"
)

const (
	num   = "0123456789"
	smStr = "abcdefghijklmnopqrstuvwxyz"
	bgStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	symb  = "~!@#$%^&*_+-="
)

// NewKey generates key of a specified length (a-z0-9)
func NewKey(length int) string {
	return randChar(length, []byte(smStr+num))
}

// NewPass generates password key of a specified length (a-z0-9.)
func NewPass(length int) string {
	return randChar(length, []byte(smStr+num+bgStr+symb))
}

// NewAPIKey Generates keys such kind: uuu-xxxx-zzzzz
func NewAPIKey(length int) string {
	return NewKey(length) + '-' + NewKey(length+1) + '-' + NewKey(length+2)
}

func randChar(length int, chars []byte) string {
	pword := make([]byte, length)
	data := make([]byte, length+(length/4)) // storage for random bytes.
	clen := byte(len(chars))
	maxrb := byte(256 - (256 % len(chars)))
	i := 0
	for {
		if _, err := io.ReadFull(rand.Reader, data); err != nil {
			panic(err)
		}
		for _, c := range data {
			if c >= maxrb {
				continue
			}
			pword[i] = chars[c%clen]
			i++
			if i == length {
				return string(pword)
			}
		}
	}
	panic("unreachable")
}
