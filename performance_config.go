package main

import (
	"fmt"
	"runtime"
)

// PerformanceConfig contains all performance-related configuration options
type PerformanceConfig struct {
	// I/O Buffer size (in MB)
	ReadBufferMB         int `json:"read-buffer-mb"`           // Buffer for reading files and streams
	
	// Parallel processing configuration
	WorkerCount         int `json:"worker-count"`            // Number of parallel workers (0 = auto)

	// Chunking configuration
	ChunkSizeMB         int `json:"chunk-size-mb"`           // Average chunk size for deduplication
}

// DefaultPerformanceConfig returns sensible defaults based on system capabilities
func DefaultPerformanceConfig() PerformanceConfig {
	// Auto-detect optimal settings will happen in GetWorkerCount() if WorkerCount is 0
	
	return PerformanceConfig{
		// I/O Buffer size - balance between memory usage and throughput
		ReadBufferMB:         8,   // 8MB for file and stream reading (good for most SSDs)
		
		// Parallel processing
		WorkerCount:         0,              // 0 = auto-detect (will use CPU count, capped at 8)
		
		// Chunking
		ChunkSizeMB:         DEFAULT_CHUNK_AVG_SIZE_MB,   // 4MB average chunk size (PBS default)
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
		ReadBuffer: p.ReadBufferMB * 1024 * 1024,
	}
}

// BufferSizes contains buffer sizes in bytes for runtime use
type BufferSizes struct {
	ReadBuffer int
}

// GetOptimizationSummary returns a summary of active performance optimizations
func (p *PerformanceConfig) GetOptimizationSummary() string {
	summary := fmt.Sprintf("Performance optimizations active:\n")
	summary += fmt.Sprintf("  - %d parallel workers for chunk processing\n", p.WorkerCount)
	summary += fmt.Sprintf("  - Lock-free concurrent deduplication\n")
	summary += fmt.Sprintf("  - Optimized I/O buffer: %dMB for file and stream reading\n",
		p.ReadBufferMB)
	summary += fmt.Sprintf("  - Sequential upload pipeline for race-free operation")
	
	return summary
}

// ValidateConfig ensures configuration values are reasonable
func (p *PerformanceConfig) ValidateConfig() {
	// Ensure minimum values
	if p.ReadBufferMB < 1 {
		fmt.Printf("Warning: read-buffer-mb too small (%d), setting to minimum 1MB\n", p.ReadBufferMB)
		p.ReadBufferMB = 1
	}
	if p.WorkerCount < 0 {
		p.WorkerCount = 0  // 0 means auto-detect
	}
	if p.ChunkSizeMB < 1 {
		p.ChunkSizeMB = 4
	}
}