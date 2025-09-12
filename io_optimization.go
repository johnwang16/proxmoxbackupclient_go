package main

import (
	"bufio"
	"io"
	"os"
)

// BufferedFileReader provides optimized file reading with configurable buffer size
type BufferedFileReader struct {
	file     *os.File
	reader   *bufio.Reader
	bufSize  int
}

// NewBufferedFileReader creates a new buffered file reader with specified buffer size
func NewBufferedFileReader(path string, bufferSizeMB int) (*BufferedFileReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	
	bufSize := bufferSizeMB * 1024 * 1024
	reader := bufio.NewReaderSize(file, bufSize)
	
	return &BufferedFileReader{
		file:    file,
		reader:  reader,
		bufSize: bufSize,
	}, nil
}

// Read implements io.Reader interface
func (r *BufferedFileReader) Read(p []byte) (n int, err error) {
	return r.reader.Read(p)
}

// Close closes the underlying file
func (r *BufferedFileReader) Close() error {
	return r.file.Close()
}

// OptimizedStreamReader wraps an io.Reader with buffering for better performance
type OptimizedStreamReader struct {
	source   io.Reader
	buffer   []byte
	buffered int
	offset   int
}

// NewOptimizedStreamReader creates a new optimized stream reader
func NewOptimizedStreamReader(source io.Reader, bufferSizeMB int) *OptimizedStreamReader {
	bufSize := bufferSizeMB * 1024 * 1024
	return &OptimizedStreamReader{
		source: source,
		buffer: make([]byte, bufSize),
	}
}

// Read implements io.Reader with internal buffering
func (r *OptimizedStreamReader) Read(p []byte) (n int, err error) {
	// If we have buffered data, serve from buffer first
	if r.buffered > r.offset {
		n = copy(p, r.buffer[r.offset:r.buffered])
		r.offset += n
		return n, nil
	}
	
	// Buffer is empty, refill it
	r.buffered, err = r.source.Read(r.buffer)
	r.offset = 0
	
	if r.buffered == 0 {
		return 0, err
	}
	
	// Serve from newly filled buffer
	n = copy(p, r.buffer[r.offset:r.buffered])
	r.offset += n
	return n, err
}

// ReadOptimizationConfig provides tuning parameters for I/O optimization
type ReadOptimizationConfig struct {
	// FileReadBufferMB is the buffer size in MB for file reading
	FileReadBufferMB int
	
	// StreamReadBufferMB is the buffer size in MB for stream reading
	StreamReadBufferMB int
	
	// ChunkQueueDepth is the depth of chunk processing queues
	ChunkQueueDepth int
	
	// UseDirectIO enables O_DIRECT flag for bypassing OS cache (Linux only)
	UseDirectIO bool
}

// DefaultReadOptimizationConfig returns sensible defaults for I/O optimization
func DefaultReadOptimizationConfig() ReadOptimizationConfig {
	return ReadOptimizationConfig{
		FileReadBufferMB:   16,  // 16MB buffer for file reads
		StreamReadBufferMB: 8,   // 8MB buffer for stream reads
		ChunkQueueDepth:    32,  // Deeper queues for better pipelining
		UseDirectIO:        false, // O_DIRECT can be problematic, disabled by default
	}
}