package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Encrypt(t *testing.T) {
	testCases := []struct {
		input    []byte
		key      []byte
		expected []byte
	}{}
	for _, test := range testCases {
		require.Equal(t, test.expected, Encrypt(test.input, test.key))
	}
}
