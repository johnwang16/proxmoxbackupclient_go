//go:build windows

package main

/*
#include <windows.h>
#include <stdio.h>

// Try to find OpenSSL installation path via registry
int find_openssl_path(char* path_buffer, int buffer_size) {
    HKEY hKey;
    DWORD dwType = REG_SZ;
    DWORD dwSize = buffer_size;
    
    // Try common registry locations for OpenSSL
    const char* reg_paths[] = {
        "SOFTWARE\\OpenSSL-Win64",
        "SOFTWARE\\OpenSSL", 
        "SOFTWARE\\WOW6432Node\\OpenSSL-Win64",
        "SOFTWARE\\WOW6432Node\\OpenSSL",
        NULL
    };
    
    for (int i = 0; reg_paths[i] != NULL; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_paths[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hKey, "InstallDir", NULL, &dwType, (LPBYTE)path_buffer, &dwSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                // Append \\bin\\ to the path
                strcat(path_buffer, "\\bin\\libcrypto-3-x64.dll");
                return 1;
            }
            RegCloseKey(hKey);
        }
    }
    return 0;
}

// OpenSSL function pointers (will be loaded dynamically)
typedef void* (*EVP_CIPHER_CTX_new_func)(void);
typedef void (*EVP_CIPHER_CTX_free_func)(void*);
typedef void* (*EVP_aes_256_gcm_func)(void);
typedef int (*EVP_EncryptInit_ex_func)(void*, void*, void*, const void*, const void*);
typedef int (*EVP_EncryptUpdate_func)(void*, void*, int*, const void*, int);
typedef int (*EVP_EncryptFinal_ex_func)(void*, void*, int*);
typedef int (*EVP_CIPHER_CTX_ctrl_func)(void*, int, int, void*);
typedef int (*EVP_DecryptInit_ex_func)(void*, void*, void*, const void*, const void*);
typedef int (*EVP_DecryptUpdate_func)(void*, void*, int*, const void*, int);
typedef int (*EVP_DecryptFinal_ex_func)(void*, void*, int*);

// EVP control commands (OpenSSL constants)
#define EVP_CTRL_GCM_SET_IVLEN 0x9
#define EVP_CTRL_GCM_GET_TAG 0x10
#define EVP_CTRL_GCM_SET_TAG 0x11

// Global function pointers
static HMODULE crypto_dll = NULL;
static EVP_CIPHER_CTX_new_func pEVP_CIPHER_CTX_new = NULL;
static EVP_CIPHER_CTX_free_func pEVP_CIPHER_CTX_free = NULL;
static EVP_aes_256_gcm_func pEVP_aes_256_gcm = NULL;
static EVP_EncryptInit_ex_func pEVP_EncryptInit_ex = NULL;
static EVP_EncryptUpdate_func pEVP_EncryptUpdate = NULL;
static EVP_EncryptFinal_ex_func pEVP_EncryptFinal_ex = NULL;
static EVP_CIPHER_CTX_ctrl_func pEVP_CIPHER_CTX_ctrl = NULL;
static EVP_DecryptInit_ex_func pEVP_DecryptInit_ex = NULL;
static EVP_DecryptUpdate_func pEVP_DecryptUpdate = NULL;
static EVP_DecryptFinal_ex_func pEVP_DecryptFinal_ex = NULL;

// Initialize OpenSSL DLL
int init_openssl_dll() {
    if (crypto_dll != NULL) return 1; // Already loaded
    
    // First, try to find OpenSSL via registry
    char registry_path[512];
    if (find_openssl_path(registry_path, sizeof(registry_path))) {
        crypto_dll = LoadLibraryA(registry_path);
        if (crypto_dll) {
            goto load_functions;
        }
    }
    
    // Try different possible DLL names and paths
    const char* dll_paths[] = {
        // Local directory first (portable mode)
        ".\\libcrypto-3-x64.dll",
        ".\\libcrypto-3.dll",
        ".\\libcrypto.dll",
        
        // Common OpenSSL installation paths
        "C:\\Program Files\\OpenSSL-Win64\\bin\\libcrypto-3-x64.dll",
        "C:\\Program Files\\OpenSSL\\bin\\libcrypto-3-x64.dll", 
        "C:\\OpenSSL-Win64\\bin\\libcrypto-3-x64.dll",
        "C:\\OpenSSL\\bin\\libcrypto-3-x64.dll",
        
        // System PATH (standard DLL names)
        "libcrypto-3-x64.dll",
        "libcrypto-3.dll",
        "libcrypto.dll",
        "crypto.dll",
        
        // Try with version numbers
        "libcrypto-3-x64.dll",
        "libcrypto-1_1-x64.dll",
        
        NULL
    };
    
    for (int i = 0; dll_paths[i] != NULL; i++) {
        crypto_dll = LoadLibraryA(dll_paths[i]);
        if (crypto_dll) {
            break;
        }
    }
    
    if (!crypto_dll) {
        return 0;
    }
    
load_functions:
    // Load function pointers
    pEVP_CIPHER_CTX_new = (EVP_CIPHER_CTX_new_func)GetProcAddress(crypto_dll, "EVP_CIPHER_CTX_new");
    pEVP_CIPHER_CTX_free = (EVP_CIPHER_CTX_free_func)GetProcAddress(crypto_dll, "EVP_CIPHER_CTX_free");
    pEVP_aes_256_gcm = (EVP_aes_256_gcm_func)GetProcAddress(crypto_dll, "EVP_aes_256_gcm");
    pEVP_EncryptInit_ex = (EVP_EncryptInit_ex_func)GetProcAddress(crypto_dll, "EVP_EncryptInit_ex");
    pEVP_EncryptUpdate = (EVP_EncryptUpdate_func)GetProcAddress(crypto_dll, "EVP_EncryptUpdate");
    pEVP_EncryptFinal_ex = (EVP_EncryptFinal_ex_func)GetProcAddress(crypto_dll, "EVP_EncryptFinal_ex");
    pEVP_CIPHER_CTX_ctrl = (EVP_CIPHER_CTX_ctrl_func)GetProcAddress(crypto_dll, "EVP_CIPHER_CTX_ctrl");
    pEVP_DecryptInit_ex = (EVP_DecryptInit_ex_func)GetProcAddress(crypto_dll, "EVP_DecryptInit_ex");
    pEVP_DecryptUpdate = (EVP_DecryptUpdate_func)GetProcAddress(crypto_dll, "EVP_DecryptUpdate");
    pEVP_DecryptFinal_ex = (EVP_DecryptFinal_ex_func)GetProcAddress(crypto_dll, "EVP_DecryptFinal_ex");
    
    // Check if all functions loaded successfully
    if (!pEVP_CIPHER_CTX_new || !pEVP_CIPHER_CTX_free || !pEVP_aes_256_gcm ||
        !pEVP_EncryptInit_ex || !pEVP_EncryptUpdate || !pEVP_EncryptFinal_ex ||
        !pEVP_CIPHER_CTX_ctrl || !pEVP_DecryptInit_ex || !pEVP_DecryptUpdate || !pEVP_DecryptFinal_ex) {
        FreeLibrary(crypto_dll);
        crypto_dll = NULL;
        return 0;
    }
    
    return 1;
}

// Dynamic OpenSSL AES-GCM encrypt
int dynamic_openssl_aes_gcm_encrypt(const unsigned char *key, int key_len,
                                   const unsigned char *iv, int iv_len,
                                   const unsigned char *plaintext, int plaintext_len,
                                   unsigned char *ciphertext,
                                   unsigned char *tag, int tag_len) {
    if (!init_openssl_dll()) return -1;
    
    void *ctx;
    int len;
    int ciphertext_len;
    
    // Create context
    if(!(ctx = pEVP_CIPHER_CTX_new())) return -1;
    
    // Initialize encryption
    if(1 != pEVP_EncryptInit_ex(ctx, pEVP_aes_256_gcm(), NULL, NULL, NULL)) {
        pEVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Set IV length for 16-byte IV support
    if(1 != pEVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        pEVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Set key and IV
    if(1 != pEVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        pEVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Encrypt
    if(1 != pEVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        pEVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    
    // Finalize
    if(1 != pEVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        pEVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    
    // Get tag
    if(1 != pEVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
        pEVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    pEVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Dynamic OpenSSL AES-GCM decrypt
int dynamic_openssl_aes_gcm_decrypt(const unsigned char *key, int key_len,
                                   const unsigned char *iv, int iv_len,
                                   const unsigned char *ciphertext, int ciphertext_len,
                                   const unsigned char *tag, int tag_len,
                                   unsigned char *plaintext) {
    if (!init_openssl_dll()) return -1;
    
    void *ctx;
    int len;
    int plaintext_len;
    int ret;
    
    // Create context
    if(!(ctx = pEVP_CIPHER_CTX_new())) return -1;
    
    // Initialize decryption
    if(!pEVP_DecryptInit_ex(ctx, pEVP_aes_256_gcm(), NULL, NULL, NULL)) {
        pEVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Set IV length
    if(!pEVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        pEVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Set key and IV
    if(!pEVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        pEVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Decrypt
    if(!pEVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        pEVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    
    // Set expected tag
    if(!pEVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag)) {
        pEVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Finalize and verify tag
    ret = pEVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    
    pEVP_CIPHER_CTX_free(ctx);
    
    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;
    }
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func dynamicOpenSSLAESGCMEncrypt(key []byte, iv []byte, plaintext []byte) (ciphertext []byte, tag []byte, err error) {
	ciphertext = make([]byte, len(plaintext))
	tag = make([]byte, 16)
	
	ret := C.dynamic_openssl_aes_gcm_encrypt(
		(*C.uchar)(unsafe.Pointer(&key[0])), C.int(len(key)),
		(*C.uchar)(unsafe.Pointer(&iv[0])), C.int(len(iv)),
		(*C.uchar)(unsafe.Pointer(&plaintext[0])), C.int(len(plaintext)),
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		(*C.uchar)(unsafe.Pointer(&tag[0])), C.int(16))
	
	if ret < 0 {
		return nil, nil, fmt.Errorf("Dynamic OpenSSL AES-GCM encryption failed")
	}
	
	return ciphertext[:ret], tag, nil
}

func dynamicOpenSSLAESGCMDecrypt(key []byte, iv []byte, ciphertext []byte, tag []byte) (plaintext []byte, err error) {
	plaintext = make([]byte, len(ciphertext))
	
	ret := C.dynamic_openssl_aes_gcm_decrypt(
		(*C.uchar)(unsafe.Pointer(&key[0])), C.int(len(key)),
		(*C.uchar)(unsafe.Pointer(&iv[0])), C.int(len(iv)),
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])), C.int(len(ciphertext)),
		(*C.uchar)(unsafe.Pointer(&tag[0])), C.int(len(tag)),
		(*C.uchar)(unsafe.Pointer(&plaintext[0])))
	
	if ret < 0 {
		return nil, fmt.Errorf("Dynamic OpenSSL AES-GCM decryption failed")
	}
	
	return plaintext[:ret], nil
}