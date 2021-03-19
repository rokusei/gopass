package gopass

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_GenerateSalt(t *testing.T) {
	wordTests := 10
	for i := 1; i < wordTests; i++ {
		c := bytes.Count(generateSalt(i), []byte("-"))
		require.Equal(t, i-1, c)
	}
}
