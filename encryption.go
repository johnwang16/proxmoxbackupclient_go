package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"golang.org/x/crypto/scrypt"
)

type ScryptKDF struct {
	N    int    `json:"n"`
	R    int    `json:"r"`
	P    int    `json:"p"`
	Salt string `json:"salt"`
}

type KDFConfig struct {
	Scrypt *ScryptKDF `json:"Scrypt,omitempty"`
}

type EncryptionKey struct {
	Data        string     `json:"data"`
	KDF         KDFConfig  `json:"kdf"`
	Created     string     `json:"created"`
	Modified    string     `json:"modified"`
	Fingerprint string     `json:"fingerprint"`
}

type CryptConfig struct {
	encKey    []byte
	gcm       cipher.AEAD
	masterKey *rsa.PublicKey
}

func NewCryptConfig(keyPath string, password string, masterKeyPath string) (*CryptConfig, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encryption key: %v", err)
	}

	var encKey EncryptionKey
	err = json.Unmarshal(keyData, &encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encryption key file - make sure it's a valid PBS JSON key file (not a raw key string): %v", err)
	}

	var actualKey []byte
	
	// Handle PBS KDF format
	if encKey.KDF.Scrypt != nil {
		if password == "" {
			return nil, fmt.Errorf("password required for scrypt-encrypted key")
		}
		
		scryptKDF := encKey.KDF.Scrypt
		salt, err2 := base64.StdEncoding.DecodeString(scryptKDF.Salt)
		if err2 != nil {
			return nil, fmt.Errorf("failed to decode scrypt salt: %v", err2)
		}
		
		actualKey, err2 = scrypt.Key([]byte(password), salt, scryptKDF.N, scryptKDF.R, scryptKDF.P, 32)
		if err2 != nil {
			return nil, fmt.Errorf("scrypt key derivation failed: %v", err2)
		}
	} else {
		return nil, fmt.Errorf("unsupported KDF type - only scrypt is supported")
	}

	block, err := aes.NewCipher(actualKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	config := &CryptConfig{
		encKey: actualKey,
		gcm:    gcm,
	}

	if masterKeyPath != "" {
		masterKey, err := loadMasterKey(masterKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load master key: %v", err)
		}
		config.masterKey = masterKey
	}

	return config, nil
}

func (cc *CryptConfig) EncryptChunk(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, cc.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := cc.gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (cc *CryptConfig) DecryptChunk(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < cc.gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:cc.gcm.NonceSize()], ciphertext[cc.gcm.NonceSize():]
	plaintext, err := cc.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}



func loadMasterKey(path string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read master key: %v", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA public key")
	}

	return rsaPubKey, nil
}


