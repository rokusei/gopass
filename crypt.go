package gopass

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

var ErrPlaintextEmpty = errors.New("plaintext is empty")
var ErrCiphertextEmpty = errors.New("ciphertext is empty")
var ErrCiphertextTooShort = errors.New("ciphertext too short")
var ErrCiphertextNotMultiple = errors.New("ciphertext is not a multiple of the AES block size")

func Encrypt(plaintext []byte, key EncryptionKey) ([]byte, error) {
	if len(plaintext) == 0 {
		return []byte{}, ErrPlaintextEmpty
	}
	// pad if plaintext is not a multiple of the blocksize
	if len(plaintext)%aes.BlockSize != 0 {
		padding := (aes.BlockSize - len(plaintext)%aes.BlockSize)
		padtext := bytes.Repeat([]byte{byte(padding)}, padding)
		plaintext = append(plaintext, padtext...)
	}

	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	// length == aes.Blocksize iif err != nil
	// so no point checking length of returned iv
	if err != nil {
		return []byte{}, err
	}

	// create new aes cipher using provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	// encrypt AES CBC
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// append iv to front of ciphertext
	return append(iv, ciphertext...), nil
}

func Decrypt(ciphertext []byte, key EncryptionKey) ([]byte, error) {
	// ensure ciphertext contains atleast a block (which is the IV)
	if len(ciphertext) < aes.BlockSize {
		return []byte{}, ErrCiphertextTooShort
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// ensure ciphertext (minus IV) isn't blank
	if len(ciphertext) == 0 {
		return []byte{}, ErrCiphertextEmpty
	}

	// ensure ciphertext is a multiple of the block size
	if len(ciphertext)%aes.BlockSize != 0 {
		return []byte{}, ErrCiphertextNotMultiple
	}

	// create new aes cipher using provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	// encrypt AES CBC
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	last := int(plaintext[len(plaintext)-1:][0])
	if len(plaintext) > last && last > 0 && last < 15 {
		for i := len(plaintext) - last; i < len(plaintext); i++ {
			if plaintext[i] != byte(last) {
				// not actually padded
				return plaintext, nil
			}
		}
		plaintext = plaintext[:len(plaintext)-last]
	}
	return plaintext, nil
}

// Given an encrypted blob, re-encrypt it using a new key
func Reencrypt(ciphertext []byte, oldKey EncryptionKey, newKey EncryptionKey) ([]byte, error) {
	p, err := Decrypt(ciphertext, oldKey)
	if err != nil {
		return []byte{}, nil
	}
	ciphertext, err = Encrypt(p, newKey)
	if err != nil {
		return []byte{}, nil
	}
	return ciphertext, nil
}

func MustEncrypt(plaintext []byte, key EncryptionKey) []byte {
	c, err := Encrypt(plaintext, key)
	if err != nil {
		panic(err)
	}
	return c
}

func MustDecrypt(ciphertext []byte, key EncryptionKey) []byte {
	p, err := Decrypt(ciphertext, key)
	if err != nil {
		panic(err)
	}
	return p
}

func MustReecrypt(ciphertext []byte, oldKey EncryptionKey, newKey EncryptionKey) []byte {
	c, err := Reencrypt(ciphertext, oldKey, newKey)
	if err != nil {
		panic(err)
	}
	return c
}
