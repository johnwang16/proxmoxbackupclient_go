package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"os"
	"sort"
	"strings"
	"time"

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

// Magic bytes moved to constants.go

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
	perfConfig     *PerformanceConfig

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
			a.catalogWriteCB(CATALOG_MAGIC)
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

	// Use configurable buffer for file reading
	bufferSize := DEFAULT_BUFFER_SIZE // Default fallback
	if a.perfConfig != nil {
		bufferSize = a.perfConfig.GetBufferSizes().ReadBuffer
	}
	readbuffer := make([]byte, bufferSize)

	// Track async processing for synchronization
	readCount := 0
	streamCount := 0
	
	// File processing started

	// Create async pipeline channel with buffer depth for optimal overlap
	pipelineDepth := 4 // Allow 4 buffers in pipeline
	streamChan := make(chan []byte, pipelineDepth)
	
	// Start async streaming goroutine
	go func() {
		for data := range streamChan {
			a.writeCB(data)
			streamCount++
		}
	}()

	for {
		nread, err := file.Read(readbuffer)
		
		if nread <= 0 {
			break
		}
		if err != nil {
			panic(err.Error())
		}
		
		// Track read count for async synchronization
		readCount++
		a.pos += uint64(nread)
		
		// Send data to async streaming pipeline (non-blocking with buffer)
		// Make a copy since we're reusing readbuffer
		data := make([]byte, nread)
		copy(data, readbuffer[:nread])
		streamChan <- data
	}
	
	// Close channel and wait for streaming to complete
	close(streamChan)
	
	// Give streaming goroutine time to finish processing
	for streamCount < readCount {
		time.Sleep(1 * time.Millisecond)
	}

	// File processing complete

	// No flush needed - data was streamed asynchronously

	return CatalogFile{
		Name:  basename,
		MTime: uint64(fileInfo.ModTime().Unix()),
		Size:  uint64(fileInfo.Size()),
	}
}

const (
	PXAR_HEADER_MIN_SIZE   = 16
	PXAR_ENTRY_STRUCT_SIZE = 40
)

// PXARExtractor encapsulates all extraction state
type PXARExtractor struct {
	reader       io.ReadSeeker
	outputDir    string
	filterPath   string
	dirStack     []DirectoryStackEntry
	currentFile  string
	currentEntry *PXAREntry
}

// ExtractPXAR extracts a PXAR archive to the specified directory
func ExtractPXAR(pxarFile string, outputDir string) error {
	file, err := os.Open(pxarFile)
	if err != nil {
		return fmt.Errorf("failed to open PXAR file: %w", err)
	}
	defer file.Close()

	return ExtractPXARFromReader(file, outputDir, "")
}

// ExtractPXARFromReader extracts a PXAR archive from an io.ReadSeeker to the specified directory
func ExtractPXARFromReader(reader io.ReadSeeker, outputDir string, filterPath string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create extractor with all state encapsulated
	extractor := &PXARExtractor{
		reader:     reader,
		outputDir:  outputDir,
		filterPath: normalizeFilterPath(filterPath),
		dirStack: []DirectoryStackEntry{{
			path:     "",
			baseDir:  outputDir,
			filename: "",
		}},
	}

	return extractor.Extract()
}


// Directory stack entry for tracking PXAR directory context
type DirectoryStackEntry struct {
	path     string
	baseDir  string
	filename string
}

// shouldExtractPath determines if a path should be extracted based on the filter
func shouldExtractPath(fullPath string, filterPath string) bool {
	if filterPath == "" {
		return true // No filter, extract everything
	}
	
	// Normalize paths for case-insensitive comparison
	fullPath = strings.ToLower(filepath.Clean(fullPath))
	filterPath = strings.ToLower(filepath.Clean(filterPath))
	
	// Check if the path matches or is under the filter path
	return fullPath == filterPath || strings.HasPrefix(fullPath, filterPath+string(filepath.Separator))
}

// Extract performs the extraction with preserved directory timing
func (e *PXARExtractor) Extract() error {
	for {
		header, err := e.readHeader()
		if err != nil {
			if err == io.EOF {
				return nil // Normal termination
			}
			return err
		}

		if err := e.processEntry(header); err != nil {
			return err
		}

		// Directory entry check at END of loop
		if e.currentFile != "" && e.isDirectory() {
			e.enterDirectory()
		}
	}
}

// readHeader reads and validates a PXAR header
func (e *PXARExtractor) readHeader() (*PXARHeader, error) {
	var header PXARHeader
	err := binary.Read(e.reader, binary.LittleEndian, &header)
	if err != nil {
		return nil, err
	}

	// Validate header
	if header.Length < PXAR_HEADER_MIN_SIZE {
		return nil, fmt.Errorf("invalid header length: %d (type: 0x%x)", header.Length, header.Type)
	}

	return &header, nil
}

// processEntry routes to appropriate handler based on entry type
func (e *PXARExtractor) processEntry(header *PXARHeader) error {
	switch header.Type {
	case PXAR_ENTRY, PXAR_ENTRY_V1:
		return e.processMetadata(header)
	case PXAR_FILENAME:
		return e.processFilename(header)
	case PXAR_PAYLOAD:
		return e.processPayload(header)
	case PXAR_SYMLINK:
		return e.processSymlink(header)
	case PXAR_GOODBYE:
		return e.processGoodbye(header)
	default:
		// Skip unknown entry types
		return e.skipBytes(int64(header.Length - PXAR_HEADER_MIN_SIZE))
	}
}

// processMetadata handles entry metadata
func (e *PXARExtractor) processMetadata(header *PXARHeader) error {
	var entry PXAREntry
	if err := binary.Read(e.reader, binary.LittleEndian, &entry); err != nil {
		return fmt.Errorf("failed to read PXAR entry: %w", err)
	}
	// Store entry metadata for later use when creating file/directory
	e.currentEntry = &entry

	// Skip any remaining data in the entry
	remaining := int64(header.Length) - PXAR_HEADER_MIN_SIZE - PXAR_ENTRY_STRUCT_SIZE
	if remaining > 0 {
		return e.skipBytes(remaining)
	}

	return nil
}

// processFilename handles filename entries
func (e *PXARExtractor) processFilename(header *PXARHeader) error {
	// Read filename
	nameLength := header.Length - PXAR_HEADER_MIN_SIZE
	nameBytes := make([]byte, nameLength)

	if _, err := io.ReadFull(e.reader, nameBytes); err != nil {
		return fmt.Errorf("failed to read filename: %w", err)
	}
	// Remove null terminator
	e.currentFile = string(bytes.TrimRight(nameBytes, "\x00"))
	return nil
}

// processPayload handles file content extraction
func (e *PXARExtractor) processPayload(header *PXARHeader) error {
	payloadLength := header.Length - PXAR_HEADER_MIN_SIZE

	// No current file means orphaned payload - skip it
	if e.currentFile == "" {
		return e.skipBytes(int64(payloadLength))
	}

	// Build the relative path for this file
	relativePath := e.buildRelativePath()

	// Check if we should extract this file based on filter
	if !e.shouldExtract(relativePath) {
		e.currentFile = ""
		e.currentEntry = nil
		return e.skipBytes(int64(payloadLength))
	}

	// Extract the file
	if err := e.extractFile(relativePath, payloadLength); err != nil {
		return err
	}

	// Reset state for next file
	e.currentFile = ""
	e.currentEntry = nil

	return nil
}

// processSymlink handles symbolic link creation
func (e *PXARExtractor) processSymlink(header *PXARHeader) error {
	linkLength := header.Length - PXAR_HEADER_MIN_SIZE
	linkBytes := make([]byte, linkLength)

	if _, err := io.ReadFull(e.reader, linkBytes); err != nil {
		return fmt.Errorf("failed to read symlink target: %w", err)
	}

	if e.currentFile == "" {
		return nil // Orphaned symlink data
	}

	relativePath := e.buildRelativePath()

	if !e.shouldExtract(relativePath) {
		e.currentFile = ""
		e.currentEntry = nil
		return nil
	}

	target := string(bytes.TrimRight(linkBytes, "\x00"))
	if err := e.createSymlink(relativePath, target); err != nil {
		// Log warning but don't fail extraction
		fmt.Printf("Warning: %v\n", err)
	}

	e.currentFile = ""
	e.currentEntry = nil

	return nil
}

// processGoodbye handles directory exit
func (e *PXARExtractor) processGoodbye(header *PXARHeader) error {
	// Skip goodbye payload
	payloadLength := header.Length - PXAR_HEADER_MIN_SIZE
	if payloadLength > 0 {
		if err := e.skipBytes(int64(payloadLength)); err != nil {
			return err
		}
	}

	// Pop directory from stack if not at root
	if len(e.dirStack) > 1 {
		e.dirStack = e.dirStack[:len(e.dirStack)-1]
		e.currentFile = ""
	}

	return nil
}

// Helper methods

// isDirectory checks if current entry is a directory by peeking ahead
func (e *PXARExtractor) isDirectory() bool {
	currentPos, _ := e.reader.Seek(0, io.SeekCurrent)
	defer e.reader.Seek(currentPos, io.SeekStart)

	var peekHeader PXARHeader
	err := binary.Read(e.reader, binary.LittleEndian, &peekHeader)

	return err == nil && (peekHeader.Type == PXAR_FILENAME || peekHeader.Type == PXAR_GOODBYE)
}

// enterDirectory handles directory entry and stack management
func (e *PXARExtractor) enterDirectory() {
	relativePath := e.buildRelativePath()

	// Create directory if it should be extracted
	if e.shouldExtract(relativePath) {
		fullPath := filepath.Join(e.outputDir, relativePath)

		if err := os.MkdirAll(fullPath, 0755); err != nil {
			fmt.Printf("Warning: failed to create directory %s: %v\n", fullPath, err)
		} else {
			e.applyFileAttributes(fullPath)
			fmt.Printf("Created directory: %s\n", relativePath)
		}
	}

	// Update directory stack
	currentDir := e.dirStack[len(e.dirStack)-1]
	e.dirStack = append(e.dirStack, DirectoryStackEntry{
		path:     relativePath,
		baseDir:  currentDir.baseDir,
		filename: e.currentFile,
	})

	e.currentFile = ""
	e.currentEntry = nil
}

// buildRelativePath constructs the current relative path
func (e *PXARExtractor) buildRelativePath() string {
	currentDir := e.dirStack[len(e.dirStack)-1]
	if currentDir.path == "" {
		return e.currentFile
	}
	return filepath.Join(currentDir.path, e.currentFile)
}

// shouldExtract determines if a path matches the filter
func (e *PXARExtractor) shouldExtract(relativePath string) bool {
	if e.filterPath == "" {
		return true // No filter, extract everything
	}

	normalizedPath := strings.ToLower(filepath.Clean(relativePath))
	return normalizedPath == e.filterPath ||
	       strings.HasPrefix(normalizedPath, e.filterPath+string(filepath.Separator))
}

// extractFile extracts file content to disk
func (e *PXARExtractor) extractFile(relativePath string, size uint64) error {
	// Print file name before starting extraction (no newline)
	fmt.Printf("Extracting file: %s", relativePath)

	fullPath := filepath.Join(e.outputDir, relativePath)

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory for %s: %w", fullPath, err)
	}

	// Create the file
	file, err := os.Create(fullPath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", fullPath, err)
	}
	defer file.Close()

	written, err := io.CopyN(file, e.reader, int64(size))
	if err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}

	// Apply file attributes
	e.applyFileAttributes(fullPath)

	// Complete the line with done message
	fmt.Printf(" - done (%d bytes)\n", written)
	return nil
}

// createSymlink creates a symbolic link
func (e *PXARExtractor) createSymlink(relativePath, target string) error {
	fullPath := filepath.Join(e.outputDir, relativePath)

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory for symlink: %w", err)
	}

	if err := os.Symlink(target, fullPath); err != nil {
		return fmt.Errorf("failed to create symlink %s -> %s: %w", fullPath, target, err)
	}

	fmt.Printf("Extracted symlink: %s -> %s\n", relativePath, target)
	return nil
}

// applyFileAttributes applies metadata to extracted files
func (e *PXARExtractor) applyFileAttributes(path string) {
	if e.currentEntry == nil {
		return
	}

	// Apply permissions
	mode := os.FileMode(e.currentEntry.Mode & 0777)
	if err := os.Chmod(path, mode); err != nil {
		// Non-fatal, just log
		fmt.Printf("Warning: failed to set permissions for %s: %v\n", path, err)
	}

	// Apply timestamps
	mtime := time.Unix(int64(e.currentEntry.MTime), int64(e.currentEntry.MTimeNs))
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		// Non-fatal, just log
		fmt.Printf("Warning: failed to set timestamps for %s: %v\n", path, err)
	}

	// Try to apply ownership (usually fails for non-root)
	_ = os.Chown(path, int(e.currentEntry.UID), int(e.currentEntry.GID))
}

// Helper functions

// skipBytes skips n bytes in the reader
func (e *PXARExtractor) skipBytes(n int64) error {
	_, err := e.reader.Seek(n, io.SeekCurrent)
	if err != nil {
		// Fallback to reading if seek fails
		_, err = io.CopyN(io.Discard, e.reader, n)
	}
	return err
}


// normalize filter paths
func normalizeFilterPath(path string) string {
	if path == "" {
		return ""
	}
	return strings.ToLower(filepath.Clean(path))
}
