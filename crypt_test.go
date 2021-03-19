package gopass

import (
	"crypto/aes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func DecodeString(str string) []byte {
	b, _ := hex.DecodeString(str)
	return b
}

func Test_EncryptDecrypt(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		key      []byte
		expected []byte
		enc_err  error
		dec_err  error
	}{
		{
			name:     "aes128 no input",
			input:    []byte(""),
			key:      DecodeString("6368616e676520746869732070617373"),
			expected: []byte(""),
			enc_err:  ErrPlaintextEmpty,
			dec_err:  ErrCiphertextTooShort,
		},
		{
			name:     "aes128, input < blocksize (padded)",
			input:    []byte("abc123"),
			key:      DecodeString("6368616e676520746869732070617373"),
			expected: []byte("abc123"),
		},
		{
			name:     "aes128, input == blocksize (unpadded)",
			input:    []byte("abcdefgh12345678"),
			key:      DecodeString("6368616e676520746869732070617373"),
			expected: []byte("abcdefgh12345678"),
		},
		{
			name:     "aes128, input > blocksize (padded)",
			input:    []byte("abcdefhijl1234567890"),
			key:      DecodeString("6368616e676520746869732070617373"),
			expected: []byte("abcdefhijl1234567890"),
		},
		{
			name:     "aes192 no input",
			input:    []byte(""),
			key:      DecodeString("6368616e6765207468697320706173736368616e67652074"),
			expected: []byte(""),
			enc_err:  ErrPlaintextEmpty,
			dec_err:  ErrCiphertextTooShort,
		},
		{
			name:     "aes192, input < blocksize (padded)",
			input:    []byte("abc123"),
			key:      DecodeString("6368616e6765207468697320706173736368616e67652074"),
			expected: []byte("abc123"),
		},
		{
			name:     "aes192, input == blocksize (unpadded)",
			input:    []byte("abcdefgh12345678"),
			key:      DecodeString("6368616e6765207468697320706173736368616e67652074"),
			expected: []byte("abcdefgh12345678"),
		},
		{
			name:     "aes192, input > blocksize (padded)",
			input:    []byte("abcdefhijl1234567890"),
			key:      DecodeString("6368616e6765207468697320706173736368616e67652074"),
			expected: []byte("abcdefhijl1234567890"),
		},
		{
			name:     "aes256 no input",
			input:    []byte(""),
			key:      DecodeString("6368616e6765207468697320706173736368616e676520746869732070617373"),
			expected: []byte(""),
			enc_err:  ErrPlaintextEmpty,
			dec_err:  ErrCiphertextTooShort,
		},
		{
			name:     "aes256, input < blocksize (padded)",
			input:    []byte("abc123"),
			key:      DecodeString("6368616e6765207468697320706173736368616e676520746869732070617373"),
			expected: []byte("abc123"),
		},
		{
			name:     "aes256, input == blocksize (unpadded)",
			input:    []byte("abcdefgh12345678"),
			key:      DecodeString("6368616e6765207468697320706173736368616e676520746869732070617373"),
			expected: []byte("abcdefgh12345678"),
		},
		{
			name:     "aes256, input > blocksize (padded)",
			input:    []byte("abcdefhijl1234567890"),
			key:      DecodeString("6368616e6765207468697320706173736368616e676520746869732070617373"),
			expected: []byte("abcdefhijl1234567890"),
		},
		{
			name:     "aes key size too small",
			input:    []byte("abc123"),
			key:      DecodeString("abc123"),
			enc_err:  aes.KeySizeError(3),
			dec_err:  ErrCiphertextTooShort,
			expected: []byte(""),
		},
		{
			name:     "aes key size too big",
			input:    []byte("abc123"),
			key:      DecodeString("6368616e6765207468697320706173736368616e6765207468697320706173732070617373"),
			enc_err:  aes.KeySizeError(37),
			dec_err:  ErrCiphertextTooShort,
			expected: []byte(""),
		},
		{
			name:     "aes empty key",
			input:    []byte("exampleplaintext"),
			key:      DecodeString(""),
			expected: []byte(""),
			enc_err:  aes.KeySizeError(0),
			dec_err:  ErrCiphertextTooShort,
		},
	}
	for _, test := range testCases {
		ciphertext, err := Encrypt(test.input, test.key)
		require.Equal(t, test.enc_err, err, test.name)
		plaintext, err := Decrypt(ciphertext, test.key)
		require.Equal(t, test.dec_err, err, test.name)
		require.Equal(t, test.expected, plaintext, test.name)
	}
}
