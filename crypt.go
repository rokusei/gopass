package gopass

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

func Encrypt(plaintext, key []byte) ([]byte, error) {
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

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	// ensure
	if len(ciphertext) < aes.BlockSize {
		return []byte{}, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// ensure ciphertext is a multiple of the block size
	if len(ciphertext)%aes.BlockSize != 0 {
		return []byte{}, errors.New("ciphertext is not a multiple of the block size")
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
	return ciphertext, nil
}
