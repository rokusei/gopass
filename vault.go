package gopass

import (
	"crypto/sha512"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

var ErrIncorrectKeySize = errors.New("Incorrect Encryption Key size")

const PBKDF2Iterations = 101101

type AuthenticationHash []byte
type EncryptionKey []byte
type Salt []byte

type Vault struct {
	VaultSecrets
	Entries map[string]interface{}
}

type VaultSecrets struct {
	AuthenticationHash AuthenticationHash
	EncryptionKey      EncryptionKey
	Salt               Salt
}

func GenerateVaultSecrets(masterPassword string) (VaultSecrets, error) {
	salt := generateRandomSalt()
	ek := DeriveEncryptionKey(masterPassword, salt)
	ah, err := DeriveAuthenticationHash(ek, salt)
	if err != nil {
		return VaultSecrets{}, err
	}
	return VaultSecrets{ah, ek, salt}, nil
}

func DeriveEncryptionKey(masterPassword string, salt []byte) EncryptionKey {
	return pbkdf2.Key([]byte(masterPassword), salt, PBKDF2Iterations, 32, sha512.New)
}

func DeriveAuthenticationHash(encryptionKey EncryptionKey, salt []byte) (AuthenticationHash, error) {
	if len(encryptionKey) != 32 {
		return []byte{}, ErrIncorrectKeySize
	}
	return pbkdf2.Key(encryptionKey, salt, 1, 64, sha512.New), nil
}
