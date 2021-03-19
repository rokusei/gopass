package gopass

import (
	"crypto/sha512"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

var ErrEncryptionKeySize = errors.New("Incorrect Encryption Key size")

const PBKDF2Iterations = 101101

type AuthenticationHash []byte
type EncryptionKey []byte

func GenerateAuthEncHashes(masterPassword string) (AuthenticationHash, EncryptionKey, []byte, error) {
	salt := generateRandomSalt()
	ek := DeriveEncryptionKey(masterPassword, salt)
	ah, err := DeriveAuthenticationHash(ek, salt)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}
	return ah, ek, salt, nil
}

func DeriveEncryptionKey(masterPassword string, salt []byte) EncryptionKey {
	return pbkdf2.Key([]byte(masterPassword), salt, PBKDF2Iterations, 32, sha512.New)
}

func DeriveAuthenticationHash(encryptionKey EncryptionKey, salt []byte) (AuthenticationHash, error) {
	if len(encryptionKey) != 32 {
		return []byte{}, ErrEncryptionKeySize
	}
	return pbkdf2.Key(encryptionKey, salt, 1, 64, sha512.New), nil
}
