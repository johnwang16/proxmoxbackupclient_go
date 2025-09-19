package main

// Common buffer and chunk size constants used across the application
const (
	// DEFAULT_BUFFER_SIZE_KB is the default buffer size in KB for fallback cases
	DEFAULT_BUFFER_SIZE_KB = 64

	// DEFAULT_CHUNK_AVG_SIZE_MB is the default average chunk size in MB (PBS standard)
	DEFAULT_CHUNK_AVG_SIZE_MB = 4

	// Buffer size in bytes for convenience
	DEFAULT_BUFFER_SIZE = DEFAULT_BUFFER_SIZE_KB * 1024

	// Chunk size in bytes for convenience
	DEFAULT_CHUNK_SIZE = DEFAULT_CHUNK_AVG_SIZE_MB * 1024 * 1024

	// DIDX_ENTRY_SIZE is the size of a dynamic index entry: 8 bytes offset + 32 bytes SHA256 digest
	DIDX_ENTRY_SIZE = 40

	// MUTEX_NAME is used for Windows single instance locking
	MUTEX_NAME = "proxmoxbackupclient_go"
)

// Magic byte arrays for various file formats and protocols
var (
	// PBS DataBlob magic bytes
	BLOB_COMPRESSED_MAGIC           = []byte{0x31, 0xb9, 0x58, 0x42, 0x6f, 0xb6, 0xa3, 0x7f}
	BLOB_UNCOMPRESSED_MAGIC         = []byte{0x42, 0xab, 0x38, 0x07, 0xbe, 0x83, 0x70, 0xa1}
	BLOB_ENCRYPTED_MAGIC            = []byte{0x7b, 0x67, 0x85, 0xbe, 0x22, 0x2d, 0x4c, 0xf0}
	BLOB_ENCRYPTED_COMPRESSED_MAGIC = []byte{0xe6, 0x59, 0x1b, 0xbf, 0x0b, 0xbf, 0xd8, 0x0b}

	// PXAR archive format magic bytes
	CATALOG_MAGIC          = []byte{0x91, 0xfd, 0x60, 0xf9, 0xc4, 0x67, 0x58, 0xd5}
	PXAR_ENTRY_MAGIC_LE    = []byte{0xef, 0xac, 0x88, 0xe5, 0x74, 0x64, 0x95, 0xd5} // PXAR_ENTRY
	PXAR_FILENAME_MAGIC_LE = []byte{0xb3, 0x17, 0x39, 0x06, 0x21, 0x11, 0x70, 0x16} // PXAR_FILENAME
	PXAR_PAYLOAD_MAGIC_LE  = []byte{0x25, 0x1a, 0x7c, 0x0b, 0x1b, 0x7a, 0x14, 0x28} // PXAR_PAYLOAD
	PXAR_GOODBYE_MAGIC_LE  = []byte{0x1d, 0x73, 0xd5, 0x42, 0xa6, 0x4f, 0xec, 0x2f} // PXAR_GOODBYE

	// Dynamic index magic bytes
	DIDX_MAGIC = []byte{0x1c, 0x91, 0x4e, 0xa5, 0x19, 0xba, 0xb3, 0xcd}
)