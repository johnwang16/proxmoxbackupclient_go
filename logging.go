package main

import "fmt"

// Log levels
const (
	LogLevelInfo        = "info"
	LogLevelPerformance = "performance" 
	LogLevelDebug       = "debug"
)

// Helper functions for different log levels
func (c *Config) ShouldLogInfo() bool {
	return c.LogLevel == LogLevelInfo || c.LogLevel == LogLevelPerformance || c.LogLevel == LogLevelDebug
}

func (c *Config) ShouldLogPerformance() bool {
	return c.LogLevel == LogLevelPerformance || c.LogLevel == LogLevelDebug
}

func (c *Config) ShouldLogDebug() bool {
	return c.LogLevel == LogLevelDebug
}

// Convenience logging functions
func (c *Config) LogInfo(format string, args ...interface{}) {
	if c.ShouldLogInfo() {
		fmt.Printf("[INFO] "+format+"\n", args...)
	}
}

func (c *Config) LogPerformance(format string, args ...interface{}) {
	if c.ShouldLogPerformance() {
		fmt.Printf("[PERF] "+format+"\n", args...)
	}
}

func (c *Config) LogDebug(format string, args ...interface{}) {
	if c.ShouldLogDebug() {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

// Initialize default log level if not set
func (c *Config) InitializeLogLevel() {
	if c.LogLevel == "" {
		c.LogLevel = LogLevelInfo
	}
}