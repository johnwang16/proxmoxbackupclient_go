package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"github.com/klauspost/compress/zstd"
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
	encKey       []byte
	idKey        []byte  // derived key for digest calculation (PBKDF2 of encKey)
	gcm          cipher.AEAD  // GCM instance with 16-byte nonce support
	masterKey    *rsa.PublicKey
	lastDigestData []byte // stores the data that was actually encrypted for digest calculation
}

func NewCryptConfig(keyPath string, password string, masterKeyPath string) (*CryptConfig, error) {
	// Check if file exists first
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("key file not found: %s", keyPath)
	}
	
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
		
		derivedKey, err2 := scrypt.Key([]byte(password), salt, scryptKDF.N, scryptKDF.R, scryptKDF.P, 32)
		if err2 != nil {
			return nil, fmt.Errorf("scrypt key derivation failed: %v", err2)
		}
		
		// Decode the encrypted key data
		encryptedData, err2 := base64.StdEncoding.DecodeString(encKey.Data)
		if err2 != nil {
			return nil, fmt.Errorf("failed to decode encrypted key data: %v", err2)
		}
		
		if len(encryptedData) < 32 {
			return nil, fmt.Errorf("encrypted key data too short: %d bytes", len(encryptedData))
		}
		
		// Extract IV, tag, and encrypted key (same format as PBS)
		iv := encryptedData[0:16]
		tag := encryptedData[16:32]
		encryptedKeyData := encryptedData[32:]
		
		// Decrypt the actual encryption key using OpenSSL DLL (matching PBS)
		actualKey, err2 = dynamicOpenSSLAESGCMDecrypt(derivedKey, iv, encryptedKeyData, tag)
		if err2 != nil {
			return nil, fmt.Errorf("failed to decrypt encryption key: %v", err2)
		}
	} else {
		return nil, fmt.Errorf("unsupported KDF type - only scrypt is supported")
	}

	// Derive id_key for digest calculation (PBS uses PBKDF2 with "_id_key" salt)
	idKey := pbkdf2.Key(actualKey, []byte("_id_key"), 10, 32, sha256.New)

	block, err := aes.NewCipher(actualKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Use NewGCMWithNonceSize to support 16-byte IVs natively (discovered solution)
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM with 16-byte nonce support: %v", err)
	}

	config := &CryptConfig{
		encKey: actualKey,
		idKey:  idKey,
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
	// Generate 16-byte nonce for PBS compatibility
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := cc.gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptChunk decrypts PBS DataBlob format using native Go GCM with 16-byte IV support
func (cc *CryptConfig) DecryptChunk(dataBlobBytes []byte) ([]byte, error) {
	if len(dataBlobBytes) < 44 {
		return nil, fmt.Errorf("DataBlob too short: %d bytes (minimum 44)", len(dataBlobBytes))
	}
	
	// Parse PBS DataBlob header
	magic := dataBlobBytes[0:8]
	crc32Bytes := dataBlobBytes[8:12]
	iv := dataBlobBytes[12:28]       // 16 bytes IV
	tag := dataBlobBytes[28:44]      // 16 bytes GCM tag
	encryptedData := dataBlobBytes[44:]
	
	// Check magic bytes to determine blob type
	var isCompressed bool
	if bytes.Equal(magic, []byte{123, 103, 133, 190, 34, 45, 76, 240}) {
		// ENCRYPTED_BLOB_MAGIC_1_0
		isCompressed = false
	} else if bytes.Equal(magic, []byte{230, 89, 27, 191, 11, 191, 216, 11}) {
		// ENCR_COMPR_BLOB_MAGIC_1_0 
		isCompressed = true
	} else {
		return nil, fmt.Errorf("unknown encrypted blob magic: %x", magic)
	}
	
	// Verify CRC32 over encrypted data
	expectedCrc := binary.LittleEndian.Uint32(crc32Bytes)
	actualCrc := crc32.ChecksumIEEE(encryptedData)
	if expectedCrc != actualCrc {
		return nil, fmt.Errorf("CRC32 mismatch: expected %08x, got %08x", expectedCrc, actualCrc)
	}
	
	// Decrypt using native Go GCM with 16-byte IV support
	// Reconstruct the full ciphertext with tag appended for Go's GCM.Open
	fullCiphertext := append(encryptedData, tag...)
	decryptedData, err := cc.gcm.Open(nil, iv, fullCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %v", err)
	}
	
	// Decompress if this was a compressed blob
	if isCompressed {
		decoder, err := zstd.NewReader(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create zstd decoder: %v", err)
		}
		defer decoder.Close()
		
		decompressed, err := decoder.DecodeAll(decryptedData, nil)
		if err != nil {
			return nil, fmt.Errorf("zstd decompression failed: %v", err)
		}
		return decompressed, nil
	}
	
	return decryptedData, nil
}

// DecodeDataBlob decodes both encrypted and unencrypted PBS DataBlob formats
func DecodeDataBlob(dataBlobBytes []byte, cryptConfig *CryptConfig) ([]byte, error) {
	if len(dataBlobBytes) < 12 {
		return nil, fmt.Errorf("DataBlob too short: %d bytes (minimum 12)", len(dataBlobBytes))
	}
	
	// Parse magic to determine blob type
	magic := dataBlobBytes[0:8]
	
	// Check for encrypted blobs first
	if bytes.Equal(magic, []byte{123, 103, 133, 190, 34, 45, 76, 240}) || 
	   bytes.Equal(magic, []byte{230, 89, 27, 191, 11, 191, 216, 11}) {
		// Encrypted blob - requires CryptConfig
		if cryptConfig == nil {
			return nil, fmt.Errorf("encrypted blob requires encryption key")
		}
		return cryptConfig.DecryptChunk(dataBlobBytes)
	}
	
	// Handle unencrypted blobs
	if bytes.Equal(magic, []byte{66, 171, 56, 7, 190, 131, 112, 161}) {
		// UNCOMPRESSED_BLOB_MAGIC_1_0
		crc32Bytes := dataBlobBytes[8:12]
		data := dataBlobBytes[12:]
		
		// Verify CRC32
		expectedCrc := binary.LittleEndian.Uint32(crc32Bytes)
		actualCrc := crc32.ChecksumIEEE(data)
		if expectedCrc != actualCrc {
			return nil, fmt.Errorf("CRC32 mismatch: expected %08x, got %08x", expectedCrc, actualCrc)
		}
		
		return data, nil
	} else if bytes.Equal(magic, []byte{49, 185, 88, 66, 111, 182, 163, 127}) {
		// COMPRESSED_BLOB_MAGIC_1_0
		crc32Bytes := dataBlobBytes[8:12]
		compressedData := dataBlobBytes[12:]
		
		// Verify CRC32
		expectedCrc := binary.LittleEndian.Uint32(crc32Bytes)
		actualCrc := crc32.ChecksumIEEE(compressedData)
		if expectedCrc != actualCrc {
			return nil, fmt.Errorf("CRC32 mismatch: expected %08x, got %08x", expectedCrc, actualCrc)
		}
		
		// Decompress
		decoder, err := zstd.NewReader(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create zstd decoder: %v", err)
		}
		defer decoder.Close()
		
		decompressed, err := decoder.DecodeAll(compressedData, nil)
		if err != nil {
			return nil, fmt.Errorf("zstd decompression failed: %v", err)
		}
		
		return decompressed, nil
	}
	
	return nil, fmt.Errorf("unknown blob magic: %x", magic)
}

// ComputeDigest computes the chunk digest for encrypted chunks following PBS spec:
// Fixed: PBS uses encKey (not idKey) for encrypted chunk digest calculation
func (cc *CryptConfig) ComputeDigest(data []byte) [32]byte {
	h := sha256.New()
	h.Write(data)          // plaintext data first
	h.Write(cc.encKey)     // encryption key appended (NOT idKey!) - this was the main bug
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// EncodeDataBlob creates a properly formatted DataBlob for encrypted chunks
// following the PBS DataBlob format: MAGIC || CRC32 || IV || TAG || EncryptedData
func (cc *CryptConfig) EncodeDataBlob(plaintext []byte, compress bool) ([]byte, error) {
	var dataToEncrypt []byte
	var magic []byte
	
	if compress {
		// Try compression first
		compressor, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			return nil, fmt.Errorf("failed to create zstd compressor: %v", err)
		}
		compressed := compressor.EncodeAll(plaintext, nil)
		compressor.Close()
		
		// Use compression if it actually reduces size (PBS behavior)
		if len(compressed) < len(plaintext) {
			dataToEncrypt = compressed
			// PBS compressed encrypted magic: SHA256("Proxmox Backup zstd compressed encrypted blob v1.0")[0..8]
			magic = []byte{230, 89, 27, 191, 11, 191, 216, 11} // ENCR_COMPR_BLOB_MAGIC_1_0
		} else {
			dataToEncrypt = plaintext
			magic = []byte{123, 103, 133, 190, 34, 45, 76, 240} // ENCRYPTED_BLOB_MAGIC_1_0
		}
	} else {
		dataToEncrypt = plaintext
		magic = []byte{123, 103, 133, 190, 34, 45, 76, 240} // ENCRYPTED_BLOB_MAGIC_1_0
	}
	
	// Store the ORIGINAL data for digest calculation (PBS always uses original data for digest)
	// Even when compression is used, the digest is calculated on the original plaintext
	cc.lastDigestData = plaintext
	
	// Generate 16-byte random IV directly - now natively supported by Go GCM
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %v", err)
	}
	
	// Encrypt using native Go GCM with 16-byte nonce support
	encryptedData := cc.gcm.Seal(nil, iv, dataToEncrypt, nil)
	actualEncrypted := encryptedData[:len(encryptedData)-16]
	tag := encryptedData[len(encryptedData)-16:]
	
	// Build DataBlob: MAGIC || CRC32 || IV || TAG || EncryptedData
	var result []byte
	result = append(result, magic...)         // 8 bytes magic
	result = append(result, make([]byte, 4)...)  // 4 bytes CRC (placeholder)
	result = append(result, iv...)            // 16 bytes IV (full, no padding needed)
	result = append(result, tag...)           // 16 bytes tag
	result = append(result, actualEncrypted...) // encrypted data
	
	// Calculate and set CRC32 over encrypted data only (after full header)
	headerSize := 8 + 4 + 16 + 16  // magic + crc + iv + tag = 44 bytes
	crcData := result[headerSize:]  // Only the encrypted data part
	checksum := crc32.ChecksumIEEE(crcData)
	binary.LittleEndian.PutUint32(result[8:12], checksum)
	
	return result, nil
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


