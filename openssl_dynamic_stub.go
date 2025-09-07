//go:build !windows

package main

import "fmt"

// Stub implementations for non-Windows platforms
func dynamicOpenSSLAESGCMEncrypt(key []byte, iv []byte, plaintext []byte) (ciphertext []byte, tag []byte, err error) {
	return nil, nil, fmt.Errorf("Dynamic OpenSSL not available on this platform")
}

func dynamicOpenSSLAESGCMDecrypt(key []byte, iv []byte, ciphertext []byte, tag []byte) (plaintext []byte, err error) {
	return nil, fmt.Errorf("Dynamic OpenSSL not available on this platform")
}