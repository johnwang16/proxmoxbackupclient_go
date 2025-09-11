package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"os"
	"sort"

	//	"io/ioutil"
	"path/filepath"

	"github.com/dchest/siphash"
)


const (
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

var catalog_magic = []byte{145, 253, 96, 249, 196, 103, 88, 213}

// PXAR magic bytes in little-endian format for header alignment scanning
var pxar_entry_magic_le = []byte{0xef, 0xac, 0x88, 0xe5, 0x74, 0x64, 0x95, 0xd5}    // PXAR_ENTRY
var pxar_filename_magic_le = []byte{0xb3, 0x17, 0x39, 0x06, 0x21, 0x11, 0x70, 0x16} // PXAR_FILENAME
var pxar_payload_magic_le = []byte{0x25, 0x1a, 0x7c, 0x0b, 0x1b, 0x7a, 0x14, 0x28}  // PXAR_PAYLOAD
var pxar_goodbye_magic_le = []byte{0x1d, 0x73, 0xd5, 0x42, 0xa6, 0x4f, 0xec, 0x2f}  // PXAR_GOODBYE

// PXAR entry header structure
type PXARHeader struct {
	Type   uint64
	Length uint64
}

// PXAR entry structure  
type PXAREntry struct {
	Mode     uint64
	Flags    uint64
	UID      uint32
	GID      uint32
	MTime    uint64
	MTimeNs  uint32
	_        uint32 // padding
}

const (
	IFMT   uint64 = 0o0170000
	IFSOCK uint64 = 0o0140000
	IFLNK  uint64 = 0o0120000
	IFREG  uint64 = 0o0100000
	IFBLK  uint64 = 0o0060000
	IFDIR  uint64 = 0o0040000
	IFCHR  uint64 = 0o0020000
	IFIFO  uint64 = 0o0010000

	ISUID uint64 = 0o0004000
	ISGID uint64 = 0o0002000
	ISVTX uint64 = 0o0001000
)

type MTime struct {
	secs    uint64
	nanos   uint32
	padding uint32
}
type PXARFileEntry struct {
	hdr   uint64
	len   uint64
	mode  uint64
	flags uint64
	uid   uint32
	gid   uint32
	mtime MTime
}

type PXARFilenameEntry struct {
	hdr uint64
	len uint64
}

type GoodByeItem struct {
	hash   uint64
	offset uint64
	len    uint64
}

type GoodByeBST struct {
	self  *GoodByeItem
	left  *GoodByeBST
	right *GoodByeBST
}

func (B *GoodByeBST) AddNode(i *GoodByeItem) {
	if i.hash < B.self.hash {
		if B.left == nil {
			B.left = &GoodByeBST{
				self: i,
			}
		} else {
			B.left.AddNode(i)
		}
	}
	if i.hash > B.self.hash {
		if B.right == nil {
			B.right = &GoodByeBST{
				self: i,
			}
		} else {
			B.right.AddNode(i)
		}
	}
}

func pow_of_2(e uint64) uint64 {
	return 1 << e
}

func log_of_2(k uint64) uint64 {
	return 8*8 - uint64(bits.LeadingZeros64(k)) - 1
}

func make_bst_inner(input []GoodByeItem, n uint64, e uint64, output *[]GoodByeItem, i uint64) {
	if n == 0 {
		return
	}
	p := pow_of_2(e - 1)
	q := pow_of_2(e)
	var k uint64
	if n >= p-1+p/2 {
		k = (q - 2) / 2
	} else {
		v := p - 1 + p/2 - n
		k = (q-2)/2 - v
	}

	(*output)[i] = input[k]

	make_bst_inner(input, k, e-1, output, i*2+1)
	make_bst_inner(input[k+1:], n-k-1, e-1, output, i*2+2)
}

func ca_make_bst(input []GoodByeItem, output *[]GoodByeItem) {
	n := uint64(len(input))
	make_bst_inner(input, n, log_of_2(n)+1, output, 0)
}

type PXAROutCB func([]byte)

type PXARArchive struct {
	//Create(filename string, writeCB PXAROutCB)
	//AddFile(filename string)
	//AddDirectory(dirname string)
	writeCB        PXAROutCB
	catalogWriteCB PXAROutCB
	buffer         bytes.Buffer
	pos            uint64
	archivename    string

	catalog_pos uint64
}

//This function will flush the internal buffer and update position
//WriteCB for pxar stream will be called.
//It is useful when we building a data structure and we need to keep a specific offset and output it only at the end

func (a *PXARArchive) Flush() {

	b := make([]byte, 64*1024)
	for {
		count, _ := a.buffer.Read(b)
		if count <= 0 {
			break
		}
		a.writeCB(b[:count])
		a.pos = a.pos + uint64(count)
	}
	//fmt.Printf("Flush %d bytes\n", count)
}

func (a *PXARArchive) Create() {
	a.pos = 0
	a.catalog_pos = 8
}

type CatalogDir struct {
	Pos  uint64 //Points to next table so parent has always to be written before children
	Name string
}

type CatalogFile struct {
	Name  string
	MTime uint64
	Size  uint64
}

func append_u64_7bit(a []byte, v uint64) []byte {
	x := a
	for {
		if v < 128 {
			x = append(x, byte(v&0x7f))
			break
		}
		x = append(x, byte(v&0x7f)|byte(0x80))
		v = v >> 7
	}
	return x
}

//PXAR format, documentation had many missing bits i had to figure out
/*
	Suppose we have
	abc
		file.txt
		ced
			file2.txt
			file3.txt

	First entry is always without filename

	PXAR_ENTRY(DIR)
		PXAR_FILENAME(file.txt)
		PXAR_ENTRY(file, attributes etc)
		PXAR_PAYLOAD(file.txt)
		PXAR_FILENAME(ced)
			PXAR_FILENAME(file2.txt)
			PXAR_ENTRY(file,attributes etc)
			PXAR_PAYLOAD(file2.txt)
			PXAR_FILENAME(file3.txt)
			PXAR_ENTRY(file,attributes etc)
			PXAR_PAYLOAD(file3.txt)
			PXAR_GOODBYE( relative to ced
				will have entries sorted using casync algorithms below
				for sip hash of "file2.txt" and "file3.txt", offset is relative to PXAR_GOODBYE header offset
				last special entry with fixed hash and not sorted
			)
		PXAR_GOODBYE(relative to abc or top dir )
			will have entries sorted using casync algorithms below
			for sip hash of "file.txt" and "ced", offset is relative to PXAR_GOODBYE header offset
			last special entry with fixed hash and not sorted
		)

*/

func (a *PXARArchive) WriteDir(path string, dirname string, toplevel bool) CatalogDir {
	//fmt.Printf("Write dir %s at %d\n", path, a.pos)
	files, err := os.ReadDir(path)
	if err != nil {
		return CatalogDir{}
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		fmt.Printf("Failed to stat %s\n", path)
		return CatalogDir{}
	}

	//Avoid writing filename entry on root
	if !toplevel {
		fname_entry := &PXARFilenameEntry{
			hdr: PXAR_FILENAME,
			len: uint64(16) + uint64(len(dirname)) + 1,
		}

		binary.Write(&a.buffer, binary.LittleEndian, fname_entry)

		a.buffer.WriteString(dirname)
		a.buffer.WriteByte(0x00)
	} else {
		if a.catalogWriteCB != nil {
			a.catalogWriteCB(catalog_magic)
			a.catalog_pos = 8
		}
	}

	a.Flush()

	dir_start_pos := a.pos

	entry := &PXARFileEntry{
		hdr:   PXAR_ENTRY,
		len:   56,
		mode:  IFDIR | 0o777,
		flags: 0,
		uid:   1000, //This is fixed because this project for now targeting windows , on which execute, traverse etc permissions don't exist
		gid:   1000,
		mtime: MTime{
			secs:    uint64(fileInfo.ModTime().Unix()),
			nanos:   0,
			padding: 0,
		},
	}
	binary.Write(&a.buffer, binary.LittleEndian, entry)

	a.Flush()

	goodbyteitems := make([]GoodByeItem, 0)
	catalog_files := make([]CatalogFile, 0)
	catalog_dirs := make([]CatalogDir, 0)

	for _, file := range files {
		startpos := a.pos
		if file.IsDir() {

			D := a.WriteDir(filepath.Join(path, file.Name()), file.Name(), false)
			catalog_dirs = append(catalog_dirs, D)
			goodbyteitems = append(goodbyteitems, GoodByeItem{
				offset: startpos,
				hash:   siphash.Hash(0x83ac3f1cfbb450db, 0xaa4f1b6879369fbd, []byte(file.Name())),
				len:    a.pos - startpos,
			})
		} else {
			F := a.WriteFile(filepath.Join(path, file.Name()), file.Name())

			catalog_files = append(catalog_files, F)
			goodbyteitems = append(goodbyteitems, GoodByeItem{
				offset: startpos,
				hash:   siphash.Hash(0x83ac3f1cfbb450db, 0xaa4f1b6879369fbd, []byte(file.Name())),
				len:    a.pos - startpos,
			})
		}
	}

	//Here we can write AFTER the recursion so leaves get written first
	//We need to write leaves first because otherwise we won't know offsets
	oldpos := a.catalog_pos
	tabledata := make([]byte, 0)
	tabledata = append_u64_7bit(tabledata, uint64(len(catalog_files)+len(catalog_dirs)))
	for _, d := range catalog_dirs {
		tabledata = append(tabledata, 'd')
		tabledata = append_u64_7bit(tabledata, uint64(len(d.Name)))
		tabledata = append(tabledata, []byte(d.Name)...)
		tabledata = append_u64_7bit(tabledata, oldpos-d.Pos)
	}

	for _, f := range catalog_files {
		tabledata = append(tabledata, 'f')
		tabledata = append_u64_7bit(tabledata, uint64(len(f.Name)))
		tabledata = append(tabledata, []byte(f.Name)...)
		tabledata = append_u64_7bit(tabledata, f.Size)
		tabledata = append_u64_7bit(tabledata, f.MTime)
	}

	catalog_outdata := make([]byte, 0)
	catalog_outdata = append_u64_7bit(catalog_outdata, uint64(len(tabledata)))
	catalog_outdata = append(catalog_outdata, tabledata...)

	if a.catalogWriteCB != nil {
		a.catalogWriteCB(catalog_outdata)

	}

	a.catalog_pos += uint64(len(catalog_outdata))

	a.Flush()

	//Sort goodbyeitems by sip hash to build later kinda of heap

	sort.Slice(goodbyteitems, func(i, j int) bool {
		return goodbyteitems[i].hash < goodbyteitems[j].hash
	})

	goodbyteitemsnew := make([]GoodByeItem, len(goodbyteitems))

	//Make casync binary search tree structure out of the sorted array

	ca_make_bst(goodbyteitems, &goodbyteitemsnew)

	goodbyteitems = goodbyteitemsnew

	a.Flush()
	goodbye_start := a.pos

	binary.Write(&a.buffer, binary.LittleEndian, PXAR_GOODBYE)
	goodbyelen := uint64(16 + 24*(len(goodbyteitems)+1))
	binary.Write(&a.buffer, binary.LittleEndian, goodbyelen)

	for _, gi := range goodbyteitems {
		gi.offset = a.pos - gi.offset
		binary.Write(&a.buffer, binary.LittleEndian, gi)
	}

	gi := &GoodByeItem{
		offset: goodbye_start - dir_start_pos,
		len:    goodbyelen,
		hash:   0xef5eed5b753e1555,
	}

	binary.Write(&a.buffer, binary.LittleEndian, gi)

	a.Flush()

	if toplevel {
		//We write special pointer to root dir here

		tabledata := make([]byte, 0)
		tabledata = append_u64_7bit(tabledata, uint64(1))
		tabledata = append(tabledata, 'd')
		tabledata = append_u64_7bit(tabledata, uint64(len(a.archivename)))
		tabledata = append(tabledata, []byte(a.archivename)...)
		tabledata = append_u64_7bit(tabledata, a.catalog_pos-oldpos)
		catalog_outdata := make([]byte, 0)
		catalog_outdata = append_u64_7bit(catalog_outdata, uint64(len(tabledata)))
		catalog_outdata = append(catalog_outdata, tabledata...)
		ptr := make([]byte, 0)
		ptr = binary.LittleEndian.AppendUint64(ptr, a.catalog_pos)
		if a.catalogWriteCB != nil {
			a.catalogWriteCB(catalog_outdata)
			a.catalogWriteCB(ptr)
		}
	}

	return CatalogDir{
		Name: dirname,
		Pos:  oldpos,
	}
}

// On pxar first item and consquently entry point must always be WriteDir , because toplevel is always a directory
// So backing up single file is not possible
func (a *PXARArchive) WriteFile(path string, basename string) CatalogFile {
	//fmt.Printf("Write file %s at %d\n", path, a.pos)
	fileInfo, err := os.Stat(path)
	if err != nil {
		fmt.Printf("Failed to stat %s\n", path)
		return CatalogFile{}
	}

	file, err := os.Open(path)

	if err != nil {
		fmt.Printf("Failed to open %s\n", path)
		return CatalogFile{}
	}

	defer file.Close()

	fname_entry := &PXARFilenameEntry{
		hdr: PXAR_FILENAME,
		len: uint64(16) + uint64(len(basename)) + 1,
	}

	binary.Write(&a.buffer, binary.LittleEndian, fname_entry)

	a.buffer.WriteString(basename)
	a.buffer.WriteByte(0x00)

	entry := &PXARFileEntry{
		hdr:   PXAR_ENTRY,
		len:   56,
		mode:  IFREG | 0o777,
		flags: 0,
		uid:   1000,
		gid:   1000,
		mtime: MTime{
			secs:    uint64(fileInfo.ModTime().Unix()),
			nanos:   0,
			padding: 0,
		},
	}
	binary.Write(&a.buffer, binary.LittleEndian, entry)

	binary.Write(&a.buffer, binary.LittleEndian, PXAR_PAYLOAD)
	filesize := uint64(fileInfo.Size()) + 16 //File size + header size
	binary.Write(&a.buffer, binary.LittleEndian, filesize)

	a.Flush()

	readbuffer := make([]byte, 1024*64)

	for {
		nread, err := file.Read(readbuffer)
		if nread <= 0 {
			break
		}
		if err != nil {
			panic(err.Error())
		}
		a.buffer.Write(readbuffer[:nread])
		a.Flush()
	}

	a.Flush()

	return CatalogFile{
		Name:  basename,
		MTime: uint64(fileInfo.ModTime().Unix()),
		Size:  uint64(fileInfo.Size()),
	}
}

// ExtractPXAR extracts a PXAR archive to the specified directory
func ExtractPXAR(pxarFile string, outputDir string) error {
	// Open PXAR file
	file, err := os.Open(pxarFile)
	if err != nil {
		return fmt.Errorf("failed to open PXAR file: %v", err)
	}
	defer file.Close()
	
	return ExtractPXARFromReader(file, outputDir)
}

// ExtractPXARFromReader extracts a PXAR archive from an io.ReadSeeker to the specified directory
func ExtractPXARFromReader(reader io.ReadSeeker, outputDir string) error {
	// Create output directory if it doesn't exist
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}
	
	// Extract the entire archive using directory stack approach like Rust implementation
	return extractPXARWithDirectoryStack(reader, outputDir)
}


// Directory stack entry for tracking PXAR directory context
type DirectoryStackEntry struct {
	path     string
	baseDir  string
	filename string
}

// extractPXARWithDirectoryStack extracts PXAR using directory stack management like Rust implementation
func extractPXARWithDirectoryStack(reader io.ReadSeeker, baseDir string) error {
	// Initialize directory stack with root entry
	directoryStack := []DirectoryStackEntry{{
		path:     "",
		baseDir:  baseDir,
		filename: "",
	}}
	
	var currentFilename string
	
	for {
		// Read PXAR header
		var header PXARHeader
		err := binary.Read(reader, binary.LittleEndian, &header)
		if err != nil {
			if err == io.EOF || err.Error() == "EOF" {
				return nil // Normal end of archive
			}
			return fmt.Errorf("failed to read PXAR header: %v", err)
		}
		
		// Validate header length
		if header.Length < 16 || header.Length > 0x10000000000 { // 1TB max
			return fmt.Errorf("invalid PXAR header length: %d (type: 0x%x)", header.Length, header.Type)
		}
		
		currentDir := directoryStack[len(directoryStack)-1]
		
		// Handle different PXAR entry types
		switch header.Type {
		case PXAR_ENTRY, PXAR_ENTRY_V1:
			// Read entry metadata
			entryDataLength := header.Length - 16
			
			var entry PXAREntry
			err = binary.Read(reader, binary.LittleEndian, &entry)
			if err != nil {
				return fmt.Errorf("failed to read PXAR entry: %v", err)
			}
			
			// Skip any remaining entry data
			structSize := int64(40)
			remaining := int64(entryDataLength) - structSize
			if remaining > 0 {
				_, err = reader.Seek(remaining, 1)
				if err != nil {
					return fmt.Errorf("failed to skip remaining PXAR_ENTRY data: %v", err)
				}
			}
			
		case PXAR_FILENAME:
			// Read filename
			nameLength := header.Length - 16
			nameBytes := make([]byte, nameLength)
			_, err = reader.Read(nameBytes)
			if err != nil {
				return fmt.Errorf("failed to read filename: %v", err)
			}
			
			// Remove null terminator
			currentFilename = string(bytes.TrimRight(nameBytes, "\x00"))
			
		case PXAR_PAYLOAD:
			// File content - this means currentFilename is a file
			payloadLength := header.Length - 16
			
			if currentFilename != "" {
				// Build full file path using directory stack
				var filePath string
				if currentDir.path == "" {
					filePath = filepath.Join(currentDir.baseDir, currentFilename)
				} else {
					filePath = filepath.Join(currentDir.baseDir, currentDir.path, currentFilename)
				}
				
				// Create parent directory if needed
				err = os.MkdirAll(filepath.Dir(filePath), 0755)
				if err != nil {
					return fmt.Errorf("failed to create parent directory for %s: %v", filePath, err)
				}
				
				// Create and write file
				outFile, err := os.Create(filePath)
				if err != nil {
					return fmt.Errorf("failed to create file %s: %v", filePath, err)
				}
				
				// Copy payload data to file
				_, err = copyN(outFile, reader, int64(payloadLength))
				outFile.Close()
				if err != nil {
					return fmt.Errorf("failed to write file content: %v", err)
				}
				
				if currentDir.path == "" {
					fmt.Printf("Extracted file: %s (%d bytes)\n", currentFilename, payloadLength)
				} else {
					fmt.Printf("Extracted file: %s/%s (%d bytes)\n", currentDir.path, currentFilename, payloadLength)
				}
				currentFilename = "" // Reset after extracting file
			} else {
				_, err = reader.Seek(int64(payloadLength), 1)
				if err != nil {
					return fmt.Errorf("failed to skip payload: %v", err)
				}
			}
			
		case PXAR_SYMLINK:
			// Symbolic link target
			linkLength := header.Length - 16
			linkBytes := make([]byte, linkLength)
			_, err = reader.Read(linkBytes)
			if err != nil {
				return fmt.Errorf("failed to read symlink target: %v", err)
			}
			
			if currentFilename != "" {
				// Build full symlink path using directory stack
				var linkPath string
				if currentDir.path == "" {
					linkPath = filepath.Join(currentDir.baseDir, currentFilename)
				} else {
					linkPath = filepath.Join(currentDir.baseDir, currentDir.path, currentFilename)
				}
				linkTarget := string(bytes.TrimRight(linkBytes, "\x00"))
				
				err = os.Symlink(linkTarget, linkPath)
				if err != nil {
					fmt.Printf("Warning: failed to create symlink %s -> %s: %v\n", linkPath, linkTarget, err)
				} else {
					if currentDir.path == "" {
						fmt.Printf("Extracted symlink: %s -> %s\n", currentFilename, linkTarget)
					} else {
						fmt.Printf("Extracted symlink: %s/%s -> %s\n", currentDir.path, currentFilename, linkTarget)
					}
				}
				currentFilename = "" // Reset after creating symlink
			}
			
		case PXAR_GOODBYE:
			// Skip any payload bytes for PXAR_GOODBYE
			payloadLength := header.Length - 16
			if payloadLength > 0 {
				_, err = reader.Seek(int64(payloadLength), 1)
				if err != nil {
					return fmt.Errorf("failed to skip PXAR_GOODBYE payload: %v", err)
				}
			}
			
			// This means "leave current directory" like in Rust implementation
			if len(directoryStack) > 1 {
				// Pop from directory stack
				directoryStack = directoryStack[:len(directoryStack)-1]
				currentFilename = "" // Reset filename when leaving directory
			} else {
				// We're at the root, this might be end of archive
				// Continue processing to see if there are more entries
			}
			
		default:
			// Skip unknown entry types
			skipLength := header.Length - 16
			if skipLength > 0 {
				_, err := reader.Seek(int64(skipLength), 1)
				if err != nil {
					return fmt.Errorf("failed to skip unknown entry type 0x%x (length %d): %v", header.Type, skipLength, err)
				}
			}
		}
		
		// Check if we need to enter a directory (after processing PXAR_FILENAME for a directory)
		// This happens when we have a filename that represents a directory
		if currentFilename != "" {
			// We need to check if this will be a directory by looking ahead for nested entries
			// For now, we'll handle directory entry when we encounter the directory structure
			// If the next entry is another PXAR_FILENAME, then currentFilename is a directory
			
			// Peek ahead to see if we're about to enter a directory
			currentPos, _ := reader.Seek(0, 1)
			var peekHeader PXARHeader
			peekErr := binary.Read(reader, binary.LittleEndian, &peekHeader)
			_, _ = reader.Seek(currentPos, 0) // Reset position
			
			if peekErr == nil && (peekHeader.Type == PXAR_FILENAME || peekHeader.Type == PXAR_GOODBYE) {
				// This suggests currentFilename is a directory - push it onto stack
				var newDirPath string
				if currentDir.path == "" {
					newDirPath = currentFilename
				} else {
					newDirPath = filepath.Join(currentDir.path, currentFilename)
				}
				
				// Create the directory
				fullDirPath := filepath.Join(currentDir.baseDir, newDirPath)
				err = os.MkdirAll(fullDirPath, 0755)
				if err != nil {
					return fmt.Errorf("failed to create directory %s: %v", fullDirPath, err)
				}
				
				// Push new directory onto stack
				directoryStack = append(directoryStack, DirectoryStackEntry{
					path:     newDirPath,
					baseDir:  currentDir.baseDir,
					filename: currentFilename,
				})
				fmt.Printf("Created directory: %s\n", newDirPath)
				currentFilename = "" // Reset after entering directory
			}
		}
	}
}


// Helper function to copy N bytes (like io.CopyN but with better error handling)
func copyN(dst *os.File, src io.Reader, n int64) (int64, error) {
	buf := make([]byte, 32*1024) // 32KB buffer
	var written int64
	
	for written < n {
		remaining := n - written
		toRead := int64(len(buf))
		if remaining < toRead {
			toRead = remaining
		}
		
		nr, err := src.Read(buf[:toRead])
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, fmt.Errorf("short write")
			}
		}
		if err != nil {
			if err.Error() == "EOF" && written == n {
				break
			}
			return written, err
		}
	}
	return written, nil
}
