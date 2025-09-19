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
	
	// Chunking configuration
	ChunkSizeMB         int `json:"chunk-size-mb"`           // Average chunk size for deduplication
	
	// Memory optimization
	EnableZeroCopy      bool `json:"enable-zero-copy"`       // Enable zero-copy optimizations where possible
}

// DefaultPerformanceConfig returns sensible defaults based on system capabilities
func DefaultPerformanceConfig() PerformanceConfig {
	// Auto-detect optimal settings will happen in GetWorkerCount() if WorkerCount is 0
	
	return PerformanceConfig{
		// I/O Buffer sizes - balance between memory usage and throughput
		FileReadBufferMB:     8,   // 8MB for file reading (good for most SSDs)
		StreamReadBufferMB:   8,   // 8MB for stream processing
		PXARFlushBufferMB:    8,   // 8MB for PXAR flushing
		PXARThresholdMB:      16,  // Flush when buffer reaches 16MB
		
		// Parallel processing
		WorkerCount:         0,              // 0 = auto-detect (will use CPU count, capped at 8)
		
		// Chunking
		ChunkSizeMB:         DEFAULT_CHUNK_AVG_SIZE_MB,   // 4MB average chunk size (PBS default)
		
		// Memory optimization
		EnableZeroCopy:      false,  // Conservative default
	}
}



// GetWorkerCount returns the effective worker count, auto-detecting if needed
func (p *PerformanceConfig) GetWorkerCount() int {
	if p.WorkerCount > 0 {
		return p.WorkerCount
	}
	
	// Auto-detect based on logical cores, using half as default
	workers := runtime.NumCPU() / 2
	if workers < 1 {
		workers = 1 // Ensure at least 1 worker
	}
	return workers
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
	if p.WorkerCount < 0 {
		p.WorkerCount = 0  // 0 means auto-detect
	}
	if p.ChunkSizeMB < 1 {
		p.ChunkSizeMB = 4
	}
}