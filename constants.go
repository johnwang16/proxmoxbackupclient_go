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

	// DIDX_HEADER_SIZE is the size of the DIDX header before entries
	DIDX_HEADER_SIZE = 4096

	// MUTEX_NAME is used for Windows single instance locking
	MUTEX_NAME = "proxmoxbackupclient_go"

	// Buffer sizes in bytes
	COPY_BUFFER_SIZE = 32 * 1024 // 32KB for file copy operations
	BUFFER_POOL_SIZE = 8 * 1024 * 1024 // 8MB for buffer pool capacity

	// Chunk processing constants
	CHUNK_ASSIGNMENT_BATCH_SIZE = 128 // Number of chunks to assign per request
	ENCRYPTION_SAFETY_MARGIN = 100    // Bytes to reduce from chunk size for encryption overhead

	// Archive and file extensions
	PXAR_ARCHIVE_NAME = "backup.pxar.didx"
	CATALOG_ARCHIVE_NAME = "catalog.pcat1.didx"
	DIDX_EXTENSION = ".didx"
	FIDX_EXTENSION = ".fidx"

	// API endpoints
	API_BACKUP_ENDPOINT = "/api2/json/backup"
	API_READER_ENDPOINT = "/api2/json/reader"
	API_SNAPSHOTS_ENDPOINT = "/api2/json/admin/datastore/"

	// Default log level
	DEFAULT_LOG_LEVEL = "info"

	// PXAR constants
	PXAR_HEADER_MIN_SIZE   = 16
	PXAR_ENTRY_STRUCT_SIZE = 40

	// File mode constants (Unix file types and permissions)
	IFMT   uint64 = 0o0170000 // File type mask
	IFSOCK uint64 = 0o0140000 // Socket
	IFLNK  uint64 = 0o0120000 // Symbolic link
	IFREG  uint64 = 0o0100000 // Regular file
	IFBLK  uint64 = 0o0060000 // Block device
	IFDIR  uint64 = 0o0040000 // Directory
	IFCHR  uint64 = 0o0020000 // Character device
	IFIFO  uint64 = 0o0010000 // FIFO

	ISUID uint64 = 0o0004000 // Set user ID
	ISGID uint64 = 0o0002000 // Set group ID
	ISVTX uint64 = 0o0001000 // Sticky bit

	// Log level constants
	LOG_LEVEL_INFO        = "info"
	LOG_LEVEL_PERFORMANCE = "performance"
	LOG_LEVEL_DEBUG       = "debug"

	// PXAR entry type constants
	PXAR_ENTRY               uint64 = 0xd5956474e588acef
	PXAR_ENTRY_V1            uint64 = 0x11da850a1c1cceff
	PXAR_FILENAME            uint64 = 0x16701121063917b3
	PXAR_SYMLINK             uint64 = 0x27f971e7dbf5dc5f
	PXAR_DEVICE              uint64 = 0x9fc9e906586d5ce9
	PXAR_XATTR               uint64 = 0x0dab0229b57dcd03
	PXAR_ACL_USER            uint64 = 0x2ce8540a457d55b8
	PXAR_ACL_GROUP           uint64 = 0x136e3eceb04c03ab
	PXAR_ACL_GROUP_OBJ       uint64 = 0x10868031e9582876
	PXAR_ACL_DEFAULT         uint64 = 0xbbbb13415a6896f5
	PXAR_ACL_DEFAULT_USER    uint64 = 0xc89357b40532cd1f
	PXAR_ACL_DEFAULT_GROUP   uint64 = 0xf90a8a5816038ffe
	PXAR_FCAPS               uint64 = 0x2da9dd9db5f7fb67
	PXAR_QUOTA_PROJID        uint64 = 0xe07540e82f7d1cbb
	PXAR_HARDLINK            uint64 = 0x51269c8422bd7275
	PXAR_PAYLOAD             uint64 = 0x28147a1b0b7c1a25
	PXAR_GOODBYE             uint64 = 0x2fec4fa642d5731d
	PXAR_GOODBYE_TAIL_MARKER uint64 = 0xef5eed5b753e1555
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