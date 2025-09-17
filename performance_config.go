package main

import (
	"fmt"
	"runtime"
)

// PerformanceConfig contains all performance-related configuration options
type PerformanceConfig struct {
	// I/O Buffer sizes (in MB)
	FileReadBufferMB     int `json:"file-read-buffer-mb"`     // Buffer for reading files during backup
	StreamReadBufferMB   int `json:"stream-read-buffer-mb"`   // Buffer for stream input
	PXARFlushBufferMB    int `json:"pxar-flush-buffer-mb"`    // Buffer for PXAR archive flushing
	PXARThresholdMB      int `json:"pxar-threshold-mb"`       // Threshold before flushing PXAR buffer
	
	// Parallel processing configuration
	WorkerCount         int `json:"worker-count"`            // Number of parallel workers (0 = auto)
	ChunkQueueDepth     int `json:"chunk-queue-depth"`       // Depth of chunk processing queues
	
	// Chunking configuration
	ChunkSizeMB         int `json:"chunk-size-mb"`           // Average chunk size for deduplication
	
	// Memory optimization
	EnableZeroCopy      bool `json:"enable-zero-copy"`       // Enable zero-copy optimizations where possible
}

// DefaultPerformanceConfig returns sensible defaults based on system capabilities
func DefaultPerformanceConfig() PerformanceConfig {
	// Auto-detect optimal settings based on available memory and CPU
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8 // Cap at 8 workers to avoid excessive memory usage
	}
	
	return PerformanceConfig{
		// I/O Buffer sizes - balance between memory usage and throughput
		FileReadBufferMB:     8,   // 8MB for file reading (good for most SSDs)
		StreamReadBufferMB:   8,   // 8MB for stream processing
		PXARFlushBufferMB:    8,   // 8MB for PXAR flushing
		PXARThresholdMB:      16,  // Flush when buffer reaches 16MB
		
		// Parallel processing
		WorkerCount:         workers,        // Use all available cores (capped)
		ChunkQueueDepth:     workers * 8,    // Deep queues for better pipelining
		
		// Chunking
		ChunkSizeMB:         4,   // 4MB average chunk size (PBS default)
		
		// Memory optimization
		EnableZeroCopy:      false,  // Conservative default
	}
}

// HighPerformanceConfig returns settings optimized for high-end systems with fast SSDs
func HighPerformanceConfig() PerformanceConfig {
	config := DefaultPerformanceConfig()
	
	// Increase buffer sizes for maximum throughput
	config.FileReadBufferMB = 32     // 32MB buffers for very fast SSDs
	config.StreamReadBufferMB = 32
	config.PXARFlushBufferMB = 32
	config.PXARThresholdMB = 64      // Larger threshold for fewer flushes
	config.ChunkQueueDepth *= 2     // Even deeper queues
	
	return config
}

// LowMemoryConfig returns settings optimized for systems with limited RAM
func LowMemoryConfig() PerformanceConfig {
	config := DefaultPerformanceConfig()
	
	// Reduce buffer sizes to conserve memory
	config.FileReadBufferMB = 2      // 2MB buffers
	config.StreamReadBufferMB = 2
	config.PXARFlushBufferMB = 2
	config.PXARThresholdMB = 4       // Flush more frequently
	config.ChunkQueueDepth /= 2      // Shallower queues
	config.WorkerCount /= 2          // Fewer workers
	if config.WorkerCount < 1 {
		config.WorkerCount = 1
	}
	
	return config
}

// GetBufferSizes returns buffer sizes in bytes for easy use
func (p *PerformanceConfig) GetBufferSizes() BufferSizes {
	return BufferSizes{
		FileReadBuffer:   p.FileReadBufferMB * 1024 * 1024,
		StreamReadBuffer: p.StreamReadBufferMB * 1024 * 1024,
		PXARFlushBuffer:  p.PXARFlushBufferMB * 1024 * 1024,
		PXARThreshold:    p.PXARThresholdMB * 1024 * 1024,
	}
}

// BufferSizes contains buffer sizes in bytes for runtime use
type BufferSizes struct {
	FileReadBuffer   int
	StreamReadBuffer int
	PXARFlushBuffer  int
	PXARThreshold    int
}

// GetOptimizationSummary returns a summary of active performance optimizations
func (p *PerformanceConfig) GetOptimizationSummary() string {
	summary := fmt.Sprintf("Performance optimizations active:\n")
	summary += fmt.Sprintf("  - %d parallel workers for chunk processing\n", p.WorkerCount)
	summary += fmt.Sprintf("  - Lock-free concurrent deduplication\n")
	summary += fmt.Sprintf("  - Optimized I/O buffers: %dMB read, %dMB PXAR flush\n", 
		p.FileReadBufferMB, p.PXARFlushBufferMB)
	summary += fmt.Sprintf("  - Deep processing queues: %d chunk capacity\n", p.ChunkQueueDepth)
	summary += fmt.Sprintf("  - Sequential upload pipeline for race-free operation")
	
	return summary
}

// ValidateConfig ensures configuration values are reasonable
func (p *PerformanceConfig) ValidateConfig() {
	// Ensure minimum values
	if p.FileReadBufferMB < 1 {
		p.FileReadBufferMB = 1
	}
	if p.StreamReadBufferMB < 1 {
		p.StreamReadBufferMB = 1
	}
	if p.PXARFlushBufferMB < 1 {
		p.PXARFlushBufferMB = 1
	}
	if p.PXARThresholdMB < p.PXARFlushBufferMB {
		p.PXARThresholdMB = p.PXARFlushBufferMB * 2
	}
	if p.WorkerCount < 1 {
		p.WorkerCount = 1
	}
	if p.ChunkQueueDepth < 1 {
		p.ChunkQueueDepth = 8
	}
	if p.ChunkSizeMB < 1 {
		p.ChunkSizeMB = 4
	}
	
	// Warn about excessive memory usage
	estimatedMemoryMB := p.FileReadBufferMB + p.StreamReadBufferMB + p.PXARFlushBufferMB + 
		(p.WorkerCount * p.ChunkSizeMB * 2) // Rough estimate for worker buffers
	
	if estimatedMemoryMB > 2048 { // More than 2GB (increased for high-performance mode)
		// Could add logging here if we had a logger
		// fmt.Printf("Warning: High memory usage estimated: ~%dMB\n", estimatedMemoryMB)
	}
}