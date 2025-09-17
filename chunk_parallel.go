package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cornelk/hashmap"
)

// No mutex needed - cornelk/hashmap is lock-free and thread-safe!
// This was a major bottleneck that limited us to single-threaded deduplication

// ChunkProcessJob represents a job for parallel chunk processing
type ChunkProcessJob struct {
	chunkData  []byte
	chunkIndex int64
	offset     uint64
}

// ChunkProcessResult represents the result of chunk processing
type ChunkProcessResult struct {
	chunkIndex   int64
	shahash      string
	bindigest    []byte
	chunkData    []byte // Processed data (compressed/encrypted)
	originalSize int
	isNew        bool
	offset       uint64
	err          error
}

// ParallelChunkState extends ChunkState with parallel processing capabilities
type ParallelChunkState struct {
	assignments        []string
	assignments_offset []uint64
	pos                uint64
	wrid               uint64
	chunkcount         uint64
	chunkdigests       hash.Hash
	current_chunk      []byte
	C                  Chunker
	newchunk           *atomic.Uint64
	reusechunk         *atomic.Uint64
	knownChunks        *hashmap.Map[string, bool]
	cryptConfig        *CryptConfig
	config             *Config
	perfConfig         *PerformanceConfig

	// Parallel processing channels and state
	processQueue      chan ChunkProcessJob
	processResult     chan ChunkProcessResult
	uploadQueue       chan ChunkProcessResult
	workerWg          sync.WaitGroup
	uploadWg          sync.WaitGroup
	resultCollectorWg sync.WaitGroup

	// Result ordering management
	pendingResults map[int64]ChunkProcessResult
	nextChunkIndex int64
	resultMutex    sync.Mutex

	// Parallel mode configuration
	numWorkers int
	client     *PBSClient

	// Current chunk tracking for streaming data
	currentChunkIndex int64
}


// InitWithConfig initializes the parallel chunk state with full configuration
func (c *ParallelChunkState) InitWithConfig(newchunk *atomic.Uint64, reusechunk *atomic.Uint64, knownChunks *hashmap.Map[string, bool], cryptConfig *CryptConfig, config *Config) {
	c.assignments = make([]string, 0)
	c.assignments_offset = make([]uint64, 0)
	c.pos = 0
	c.chunkcount = 0
	c.chunkdigests = sha256.New()
	c.current_chunk = make([]byte, 0)
	c.cryptConfig = cryptConfig
	c.config = config

	chunkAvgSize := uint64(1024 * 1024 * 4) // 4MB average
	if cryptConfig != nil {
		// Reduce chunk size to account for encryption overhead (28 bytes for AES-GCM)
		// Use safety margin to ensure max chunks stay under PBS 16MB limit
		chunkAvgSize = uint64((1024 * 1024 * 4) - 100)
	}
	c.C = Chunker{}
	c.C.New(chunkAvgSize)
	c.reusechunk = reusechunk
	c.newchunk = newchunk
	c.knownChunks = knownChunks

	// Initialize parallel processing state
	// Set performance configuration from main config
	if config != nil && config.Performance != nil {
		c.perfConfig = config.Performance
	} else {
		defaultConfig := DefaultPerformanceConfig()
		c.perfConfig = &defaultConfig
	}
	
	c.numWorkers = c.perfConfig.WorkerCount
	c.pendingResults = make(map[int64]ChunkProcessResult)
	c.nextChunkIndex = 0
	c.currentChunkIndex = 0
}

// StartParallel starts the parallel processing pipeline
func (c *ParallelChunkState) StartParallel(client *PBSClient) {
	c.client = client

	// Create channels with configurable buffer sizes for better pipelining
	// This allows more chunks to be queued, reducing blocking on I/O
	queueDepth := c.perfConfig.ChunkQueueDepth
	c.processQueue = make(chan ChunkProcessJob, queueDepth)
	c.processResult = make(chan ChunkProcessResult, queueDepth)
	c.uploadQueue = make(chan ChunkProcessResult, queueDepth)

	// Start worker goroutines for chunk processing
	for i := 0; i < c.numWorkers; i++ {
		c.workerWg.Add(1)
		go c.processWorker()
	}

	// Start result collector goroutine
	c.resultCollectorWg.Add(1)
	go c.resultCollector()

	// Start single upload worker
	c.uploadWg.Add(1)
	go c.uploadWorker()

	if c.config != nil && c.config.ShouldLogPerformance() {
		fmt.Printf("Started parallel processing with %d workers\n", c.numWorkers)
	}
}

// processWorker performs CPU-intensive chunk processing in parallel
func (c *ParallelChunkState) processWorker() {
	defer c.workerWg.Done()

	for job := range c.processQueue {
		// First check if chunk already exists (lock-free read check)
		// The cornelk/hashmap is concurrent-safe for reads, no mutex needed!
		// This is an optimization to skip processing known chunks
		preliminaryDigest := c.computePreliminaryDigest(job.chunkData)
		
		// Lock-free read from concurrent hashmap - this is the key performance fix!
		_, exists := c.knownChunks.Get(preliminaryDigest)

		if exists {
			// Skip processing for known chunks but still compute digest for DIDX
			bindigest, shahash := c.computeChunkDigestThreadSafe(job.chunkData, c.cryptConfig)
			result := ChunkProcessResult{
				chunkIndex:   job.chunkIndex,
				shahash:      shahash,
				bindigest:    bindigest,
				originalSize: len(job.chunkData),
				offset:       job.offset,
				isNew:        false,
				chunkData:    nil, // No need to process/upload
			}
			c.processResult <- result
			continue
		}

		// Process new chunk
		result := ChunkProcessResult{
			chunkIndex:   job.chunkIndex,
			originalSize: len(job.chunkData),
			offset:       job.offset,
		}

		chunkData := job.chunkData
		var bindigest []byte
		var shahash string

		if c.cryptConfig != nil {
			var err error
			// Create encrypted DataBlob - thread-safe version
			chunkData, err = c.encodeDataBlobThreadSafe(job.chunkData)
			if err != nil {
				result.err = err
				c.processResult <- result
				continue
			}
			// Calculate digest on original data (PBS spec)
			bindigest, shahash = c.computeChunkDigestThreadSafe(job.chunkData, c.cryptConfig)
		} else {
			// Unencrypted chunks
			bindigest, shahash = c.computeChunkDigestThreadSafe(job.chunkData, nil)
		}

		result.chunkData = chunkData
		result.shahash = shahash
		result.bindigest = bindigest

		// Mark as potentially new (will be verified at upload time)
		result.isNew = true

		c.processResult <- result
	}
}

// computePreliminaryDigest computes a quick digest for dedup checking
func (c *ParallelChunkState) computePreliminaryDigest(data []byte) string {
	if c.cryptConfig != nil {
		// For encrypted chunks: hash plaintext + encryption key
		digest := c.cryptConfig.ComputeDigest(data)
		return hex.EncodeToString(digest[:])
	} else {
		// For unencrypted chunks: hash plaintext only
		h := sha256.New()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}
}

// encodeDataBlobThreadSafe creates encrypted DataBlob without race conditions
func (c *ParallelChunkState) encodeDataBlobThreadSafe(plaintext []byte) ([]byte, error) {
	// Create a local copy of the crypto config to avoid shared state issues
	// The actual encryption operation is thread-safe in the Go crypto library
	return c.cryptConfig.EncodeDataBlob(plaintext, true)
}

// computeChunkDigestThreadSafe computes digest in a thread-safe manner
func (c *ParallelChunkState) computeChunkDigestThreadSafe(data []byte, cryptConfig *CryptConfig) ([]byte, string) {
	if cryptConfig != nil {
		// For encrypted chunks: hash plaintext + encryption key
		digest := cryptConfig.ComputeDigest(data)
		return digest[:], hex.EncodeToString(digest[:])
	} else {
		// For unencrypted chunks: hash plaintext only
		h := sha256.New()
		h.Write(data)
		bindigest := h.Sum(nil)
		return bindigest, hex.EncodeToString(bindigest)
	}
}

// resultCollector maintains DIDX ordering despite parallel processing
func (c *ParallelChunkState) resultCollector() {
	defer c.resultCollectorWg.Done()

	for result := range c.processResult {
		c.resultMutex.Lock()
		c.pendingResults[result.chunkIndex] = result

		// Process any results that are ready in sequence
		for {
			nextResult, ok := c.pendingResults[c.nextChunkIndex]
			if !ok {
				break
			}

			if nextResult.err != nil {
				fmt.Printf("Chunk processing error: %v\n", nextResult.err)
				c.resultMutex.Unlock()
				return
			}

			// Update DIDX data
			binary.Write(c.chunkdigests, binary.LittleEndian, (nextResult.offset + uint64(nextResult.originalSize)))
			c.chunkdigests.Write(nextResult.bindigest)
			
			c.assignments_offset = append(c.assignments_offset, nextResult.offset)
			c.assignments = append(c.assignments, nextResult.shahash)
			c.chunkcount++

			// Queue for upload (even if not new, for final verification)
			c.uploadQueue <- nextResult

			delete(c.pendingResults, c.nextChunkIndex)
			c.nextChunkIndex++
		}
		c.resultMutex.Unlock()
	}

	// Process any remaining pending results after channel closes
	c.resultMutex.Lock()
	for c.nextChunkIndex < c.currentChunkIndex {
		if nextResult, ok := c.pendingResults[c.nextChunkIndex]; ok {
			// Update DIDX data
			binary.Write(c.chunkdigests, binary.LittleEndian, (nextResult.offset + uint64(nextResult.originalSize)))
			c.chunkdigests.Write(nextResult.bindigest)
			
			c.assignments_offset = append(c.assignments_offset, nextResult.offset)
			c.assignments = append(c.assignments, nextResult.shahash)
			c.chunkcount++

			// Queue for upload
			c.uploadQueue <- nextResult

			delete(c.pendingResults, c.nextChunkIndex)
		}
		c.nextChunkIndex++
	}
	c.resultMutex.Unlock()
}

// uploadWorker performs sequential uploads with final deduplication check
func (c *ParallelChunkState) uploadWorker() {
	defer c.uploadWg.Done()

	for result := range c.uploadQueue {
		if result.isNew && result.chunkData != nil {
			// Final atomic check-and-set before upload using lock-free GetOrInsert
			// cornelk/hashmap GetOrInsert is atomic and lock-free - no mutex needed!
			_, alreadyExists := c.knownChunks.GetOrInsert(result.shahash, true)

			if !alreadyExists {
				if c.config != nil && c.config.ShouldLogDebug() {
					fmt.Printf("New chunk[%s] %d bytes\n", result.shahash, len(result.chunkData))
				}

				var err error
				if c.cryptConfig != nil {
					// For encrypted chunks, upload as raw blob
					err = c.client.UploadRawChunk(c.wrid, result.shahash, result.chunkData, result.originalSize)
				} else {
					err = c.client.UploadCompressedChunk(c.wrid, result.shahash, result.chunkData, result.originalSize)
				}

				if err != nil {
					// Handle "already exists" as edge case recovery
					if strings.Contains(err.Error(), "Overwriting existing") || 
					   strings.Contains(err.Error(), "already exists") ||
					   strings.Contains(err.Error(), "already exist") {
						if c.config != nil && c.config.ShouldLogDebug() {
							fmt.Printf("Chunk already exists on server (race recovery): %s\n", result.shahash)
						}
						c.reusechunk.Add(1)
					} else {
						fmt.Printf("Upload error for chunk %s: %v\n", result.shahash, err)
					}
				} else {
					c.newchunk.Add(1)
				}
			} else {
				if c.config != nil && c.config.ShouldLogDebug() {
					fmt.Printf("Reuse chunk[%s] %d bytes (detected at upload)\n", result.shahash, result.originalSize)
				}
				c.reusechunk.Add(1)
			}
		} else {
			if c.config != nil && c.config.ShouldLogDebug() {
				fmt.Printf("Reuse chunk[%s] %d bytes\n", result.shahash, result.originalSize)
			}
			c.reusechunk.Add(1)
		}
	}
}

// HandleData processes incoming data through the parallel pipeline
func (c *ParallelChunkState) HandleData(b []byte) {
	chunkpos := c.C.Scan(b)

	if chunkpos == 0 {
		// No break happened, just append data
		c.current_chunk = append(c.current_chunk, b...)
	} else {
		for chunkpos > 0 {
			// Append data until break position
			c.current_chunk = append(c.current_chunk, b[:chunkpos]...)

			// Submit chunk for parallel processing
			job := ChunkProcessJob{
				chunkData:  make([]byte, len(c.current_chunk)),
				chunkIndex: c.currentChunkIndex,
				offset:     c.pos,
			}
			copy(job.chunkData, c.current_chunk)

			c.processQueue <- job

			c.pos += uint64(len(c.current_chunk))
			c.currentChunkIndex++

			c.current_chunk = make([]byte, 0)
			b = b[chunkpos:] // Take remainder of data
			chunkpos = c.C.Scan(b)
		}

		// No further break happened, append remaining data
		c.current_chunk = append(c.current_chunk, b...)
	}
}

// Eof processes the final chunk and closes the pipeline
func (c *ParallelChunkState) Eof() {
	// Process any remaining data
	if len(c.current_chunk) > 0 {
		job := ChunkProcessJob{
			chunkData:  make([]byte, len(c.current_chunk)),
			chunkIndex: c.currentChunkIndex,
			offset:     c.pos,
		}
		copy(job.chunkData, c.current_chunk)
		c.processQueue <- job
		c.pos += uint64(len(c.current_chunk))
		c.currentChunkIndex++
	}

	// Close process queue and wait for workers to finish
	close(c.processQueue)
	c.workerWg.Wait()

	// Signal result collector to finish
	close(c.processResult)
	c.resultCollectorWg.Wait()

	// Close upload queue and wait for uploads to finish
	close(c.uploadQueue)
	c.uploadWg.Wait()

	// Send chunk assignments to server
	// Avoid incurring in request entity too large by chunking assignment PUT requests
	for k := 0; k < len(c.assignments); k += 128 {
		k2 := k + 128
		if k2 > len(c.assignments) {
			k2 = len(c.assignments)
		}
		c.client.AssignChunks(c.wrid, c.assignments[k:k2], c.assignments_offset[k:k2])
	}

	// Close the dynamic index
	digest := hex.EncodeToString(c.chunkdigests.Sum(nil))
	c.client.CloseDynamicIndex(c.wrid, digest, c.pos, c.chunkcount)
}