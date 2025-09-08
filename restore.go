package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
)

// restoreBackup restores a generic PBS archive to a file
func restoreBackup(client *PBSClient, archiveName string, outputPath string, cryptConfig *CryptConfig, snapshotTime string) error {
	fmt.Printf("Starting restore of %s to %s\n", archiveName, outputPath)
	
	// First connect with standard HTTP client to list snapshots
	client.ConnectRestore()
	
	// Resolve snapshot
	snapshots, err := client.ListSnapshots()
	if err != nil {
		return fmt.Errorf("failed to list snapshots: %v", err)
	}
	
	var selectedSnapshot *BackupSnapshot
	
	if snapshotTime == "latest" || snapshotTime == "" {
		// Find the latest snapshot for this backup ID
		var latestTime int64 = 0
		for _, snapshot := range snapshots {
			if snapshot.BackupID == client.manifest.BackupID && snapshot.BackupTime > latestTime {
				latestTime = snapshot.BackupTime
				selectedSnapshot = &snapshot
			}
		}
	} else {
		// Parse timestamp - expecting Unix timestamp as string (e.g., "1704110400")
		var targetTime int64
		_, err := fmt.Sscanf(snapshotTime, "%d", &targetTime)
		if err != nil {
			// Try parsing as RFC3339 time format
			parsedTime, err2 := time.Parse(time.RFC3339, snapshotTime)
			if err2 != nil {
				return fmt.Errorf("invalid snapshot time format: %s (expected Unix timestamp or RFC3339)", snapshotTime)
			}
			targetTime = parsedTime.Unix()
		}
		
		// Find exact matching snapshot
		for _, snapshot := range snapshots {
			if snapshot.BackupID == client.manifest.BackupID && snapshot.BackupTime == targetTime {
				selectedSnapshot = &snapshot
				break
			}
		}
	}
	
	if selectedSnapshot == nil {
		return fmt.Errorf("no matching snapshot found for backup ID: %s", client.manifest.BackupID)
	}
	
	fmt.Printf("Selected snapshot: %s at %d\n", selectedSnapshot.BackupID, selectedSnapshot.BackupTime)
	
	// Switch to reader protocol for data access
	err = client.ConnectReader(selectedSnapshot.BackupType, selectedSnapshot.BackupID, selectedSnapshot.BackupTime)
	if err != nil {
		return fmt.Errorf("failed to establish reader connection: %v", err)
	}
	
	// Download the dynamic index using reader protocol
	didxData, err := client.DownloadFile(archiveName)
	if err != nil {
		return fmt.Errorf("failed to download archive index: %v", err)
	}
	
	fmt.Printf("Downloaded DIDX: %d bytes\n", len(didxData))
	
	if !bytes.HasPrefix(didxData, didxMagic) {
		return fmt.Errorf("invalid DIDX magic bytes")
	}
	
	// Parse the DIDX entries (skip 4096 byte header)
	didxEntries := didxData[4096:]
	var chunks []DidxEntry
	
	for i := 0; i*40 < len(didxEntries); i++ {
		entry := DidxEntry{
			offset: binary.LittleEndian.Uint64(didxEntries[i*40 : i*40+8]),
			digest: make([]byte, 32),
		}
		copy(entry.digest, didxEntries[i*40+8:i*40+40])
		chunks = append(chunks, entry)
	}
	
	fmt.Printf("Found %d chunks to restore\n", len(chunks))
	
	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()
	
	// Download and reconstruct chunks
	var totalBytes int64
	for i, chunk := range chunks {
		digestHex := hex.EncodeToString(chunk.digest)
		fmt.Printf("Restoring chunk %d/%d: %s (offset: %d)\n", i+1, len(chunks), digestHex, chunk.offset)
		
		// Download chunk data (DataBlob format) using backup protocol
		chunkDataBlob, err := client.DownloadChunk(digestHex)
		if err != nil {
			return fmt.Errorf("failed to download chunk %s: %v", digestHex, err)
		}
		
		// Decode DataBlob with digest validation for data integrity
		plaintext, err := DecodeDataBlobWithDigest(chunkDataBlob, cryptConfig, chunk.digest)
		if err != nil {
			return fmt.Errorf("failed to decode chunk %s: %v", digestHex, err)
		}
		
		fmt.Printf("Writing %d bytes to file (total so far: %d)\n", len(plaintext), totalBytes+int64(len(plaintext)))
		
		// Write to output file
		n, err := outFile.Write(plaintext)
		if err != nil {
			return fmt.Errorf("failed to write chunk data: %v", err)
		}
		if n != len(plaintext) {
			return fmt.Errorf("incomplete write: wrote %d bytes, expected %d", n, len(plaintext))
		}
		totalBytes += int64(n)
		
		// Flush after each chunk for large files
		err = outFile.Sync()
		if err != nil {
			return fmt.Errorf("failed to sync chunk data: %v", err)
		}
	}
	
	fmt.Printf("Successfully restored %s\n", archiveName)
	return nil
}

// restorePXAR restores a PXAR archive and extracts it to a directory
func restorePXAR(client *PBSClient, outputDir string, cryptConfig *CryptConfig, snapshotTime string) error {
	archiveName := "backup.pxar.didx"
	
	// Create output directory if it doesn't exist
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}
	
	fmt.Printf("Extracting PXAR archive to: %s\n", outputDir)
	
	// Create streaming restore reader
	pxarReader, err := createRestoreReader(client, archiveName, cryptConfig, snapshotTime)
	if err != nil {
		return fmt.Errorf("failed to create restore stream: %v", err)
	}
	defer pxarReader.Close()
	
	// Use native PXAR extraction directly from stream
	err = ExtractPXARFromReader(pxarReader, outputDir)
	if err != nil {
		return fmt.Errorf("PXAR extraction failed: %v", err)
	}
	
	fmt.Printf("Files extracted to: %s\n", outputDir)
	return nil
}

// RestoreReader provides streaming access to restored PBS archive data
type RestoreReader struct {
	client      *PBSClient
	cryptConfig *CryptConfig
	chunks      []DidxEntry
	currentPos  int64
	data        []byte // Buffer for current chunk data
	dataOffset  int64  // Offset of buffered data in the stream
	totalSize   int64  // Cached total size (-1 if not calculated yet)
	totalChunks int    // Total number of chunks for progress reporting
}

func (r *RestoreReader) Read(p []byte) (n int, err error) {
	if r.currentPos >= r.getTotalSize() {
		return 0, io.EOF
	}
	
	// Ensure we have the right chunk data loaded
	err = r.loadDataForPosition(r.currentPos)
	if err != nil {
		return 0, err
	}
	
	// Calculate how much we can read from current buffer
	bufferPos := r.currentPos - r.dataOffset
	if bufferPos < 0 {
		return 0, fmt.Errorf("invalid buffer position: currentPos=%d, dataOffset=%d, bufferPos=%d", r.currentPos, r.dataOffset, bufferPos)
	}
	availableInBuffer := int64(len(r.data)) - bufferPos
	if availableInBuffer <= 0 {
		// We've consumed all data in this chunk, need to load next one
		r.currentPos = r.dataOffset + int64(len(r.data))
		return r.Read(p) // Recursive call to load next chunk
	}
	
	toRead := min(int64(len(p)), availableInBuffer)
	if toRead == 0 {
		return 0, nil
	}
	
	// Copy data to output buffer
	copy(p, r.data[bufferPos:bufferPos+toRead])
	r.currentPos += toRead
	
	return int(toRead), nil
}

func (r *RestoreReader) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = r.currentPos + offset
	case io.SeekEnd:
		newPos = r.getTotalSize() + offset
	default:
		return 0, fmt.Errorf("invalid whence value")
	}
	
	if newPos < 0 {
		return 0, fmt.Errorf("seek before start of stream")
	}
	if newPos > r.getTotalSize() {
		return 0, fmt.Errorf("seek beyond end of stream")
	}
	
	r.currentPos = newPos
	return newPos, nil
}

func (r *RestoreReader) Close() error {
	// No cleanup needed for now
	return nil
}

func (r *RestoreReader) getTotalSize() int64 {
	if len(r.chunks) == 0 {
		return 0
	}
	
	// Return cached value if already calculated
	if r.totalSize >= 0 {
		return r.totalSize
	}
	
	// In DIDX, the offset of each chunk is the END position of that chunk
	// So the total size is simply the last chunk's offset
	lastChunkIndex := len(r.chunks) - 1
	r.totalSize = int64(r.chunks[lastChunkIndex].offset)
	return r.totalSize
}

func (r *RestoreReader) loadDataForPosition(pos int64) error {
	// Find which chunk contains this position
	// In DIDX: chunk[i] contains bytes from (chunk[i-1].offset) to (chunk[i].offset - 1)
	chunkIndex := -1
	for i := range r.chunks {
		chunkEnd := int64(r.chunks[i].offset)
		if pos < chunkEnd {
			chunkIndex = i
			break
		}
	}
	
	if chunkIndex == -1 {
		return fmt.Errorf("position %d is beyond available data", pos)
	}
	
	// Check if we already have this chunk loaded
	if r.data != nil && pos >= r.dataOffset && pos < r.dataOffset+int64(len(r.data)) {
		return nil // Already have the right data
	}
	
	// Download and decrypt the chunk
	digestHex := hex.EncodeToString(r.chunks[chunkIndex].digest)
	chunkDataBlob, err := r.client.DownloadChunk(digestHex)
	if err != nil {
		return fmt.Errorf("failed to download chunk %s: %v", digestHex, err)
	}
	
	// Decode DataBlob with digest validation for data integrity
	plaintext, err := DecodeDataBlobWithDigest(chunkDataBlob, r.cryptConfig, r.chunks[chunkIndex].digest)
	if err != nil {
		return fmt.Errorf("failed to decode chunk %s: %v", digestHex, err)
	}
	
	// Store the chunk data and its offset
	r.data = plaintext
	// In DIDX, chunk offset is the END position of the chunk
	// So the START position is the previous chunk's offset (or 0 for first chunk)
	if chunkIndex == 0 {
		r.dataOffset = 0
	} else {
		r.dataOffset = int64(r.chunks[chunkIndex-1].offset)
	}
	fmt.Printf("Restoring chunk %d/%d: %s\n", chunkIndex+1, r.totalChunks, digestHex)
	
	return nil
}

// createRestoreReader creates a streaming reader for PBS archive data
func createRestoreReader(client *PBSClient, archiveName string, cryptConfig *CryptConfig, snapshotTime string) (*RestoreReader, error) {
	// First connect with standard HTTP client to list snapshots
	client.ConnectRestore()
	
	// Resolve snapshot
	snapshots, err := client.ListSnapshots()
	if err != nil {
		return nil, fmt.Errorf("failed to list snapshots: %v", err)
	}
	
	var selectedSnapshot *BackupSnapshot
	
	if snapshotTime == "latest" || snapshotTime == "" {
		// Find the latest snapshot for this backup ID
		var latestTime int64 = 0
		for _, snapshot := range snapshots {
			if snapshot.BackupID == client.manifest.BackupID && snapshot.BackupTime > latestTime {
				latestTime = snapshot.BackupTime
				selectedSnapshot = &snapshot
			}
		}
	} else {
		// Parse timestamp - expecting Unix timestamp as string (e.g., "1704110400")
		var targetTime int64
		_, err := fmt.Sscanf(snapshotTime, "%d", &targetTime)
		if err != nil {
			// Try parsing as RFC3339 time format
			parsedTime, err2 := time.Parse(time.RFC3339, snapshotTime)
			if err2 != nil {
				return nil, fmt.Errorf("invalid snapshot time format: %s (expected Unix timestamp or RFC3339)", snapshotTime)
			}
			targetTime = parsedTime.Unix()
		}
		
		// Find exact matching snapshot
		for _, snapshot := range snapshots {
			if snapshot.BackupID == client.manifest.BackupID && snapshot.BackupTime == targetTime {
				selectedSnapshot = &snapshot
				break
			}
		}
	}
	
	if selectedSnapshot == nil {
		return nil, fmt.Errorf("no matching snapshot found for backup ID: %s", client.manifest.BackupID)
	}
	
	fmt.Printf("Selected snapshot: %s at %d\n", selectedSnapshot.BackupID, selectedSnapshot.BackupTime)
	
	// Switch to reader protocol for data access
	err = client.ConnectReader(selectedSnapshot.BackupType, selectedSnapshot.BackupID, selectedSnapshot.BackupTime)
	if err != nil {
		return nil, fmt.Errorf("failed to establish reader connection: %v", err)
	}
	
	// Download the dynamic index using reader protocol
	didxData, err := client.DownloadFile(archiveName)
	if err != nil {
		return nil, fmt.Errorf("failed to download archive index: %v", err)
	}
	
	fmt.Printf("Downloaded DIDX: %d bytes\n", len(didxData))
	
	if !bytes.HasPrefix(didxData, didxMagic) {
		return nil, fmt.Errorf("invalid DIDX magic bytes")
	}
	
	// Parse the DIDX entries (skip 4096 byte header)
	didxEntries := didxData[4096:]
	var chunks []DidxEntry
	
	for i := 0; i*40 < len(didxEntries); i++ {
		entry := DidxEntry{
			offset: binary.LittleEndian.Uint64(didxEntries[i*40 : i*40+8]),
			digest: make([]byte, 32),
		}
		copy(entry.digest, didxEntries[i*40+8:i*40+40])
		chunks = append(chunks, entry)
	}
	
	fmt.Printf("Found %d chunks to restore\n", len(chunks))
	
	return &RestoreReader{
		client:      client,
		cryptConfig: cryptConfig,
		chunks:      chunks,
		currentPos:  0,
		totalSize:   -1, // Initialize as uncalculated
		totalChunks: len(chunks),
	}, nil
}