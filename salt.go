package gopass

import (
	"bytes"
	"math/rand"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"

	"github.com/nwtgck/go-fakelish"
)

func generateSalt(words int) []byte {
	w := make([]string, words)
	for i := 0; i < words; i++ {
		w[i] = fakelish.GenerateFakeWord(3, 8)
	}
	return []byte(strings.Join(w, "-"))
}

func generateRandomSalt() []byte {
	rand.Seed(time.Now().Unix())
	return generateSalt(4 + rand.Int()%3)
}

func GenerateSaltQR(b []byte) []byte {
	buf := new(bytes.Buffer)
	qrterminal.Generate(string(b), qrterminal.M, buf)
	return buf.Bytes()
}
