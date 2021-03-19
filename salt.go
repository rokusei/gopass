package gopass

import (
	"bytes"
	"math/rand"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"

	"github.com/nwtgck/go-fakelish"
)

func GenerateSalt(words int) []byte {
	w := make([]string, words)
	for i := 0; i < words; i++ {
		w[i] = fakelish.GenerateFakeWord(3, 8)
	}
	return []byte(strings.Join(w, "-"))
}

func GenerateRandomSalt() []byte {
	rand.Seed(time.Now().Unix())
	return GenerateSalt(4 + rand.Int()%3)
}

func SaltQR(b []byte) []byte {
	buf := new(bytes.Buffer)
	qrterminal.Generate(string(b), qrterminal.L, buf)
	return buf.Bytes()
}
