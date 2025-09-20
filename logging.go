package main

import "fmt"

// Log levels

// Helper functions for different log levels
func (c *Config) ShouldLogInfo() bool {
	return c.LogLevel == LOG_LEVEL_INFO || c.LogLevel == LOG_LEVEL_PERFORMANCE || c.LogLevel == LOG_LEVEL_DEBUG
}

func (c *Config) ShouldLogPerformance() bool {
	return c.LogLevel == LOG_LEVEL_PERFORMANCE || c.LogLevel == LOG_LEVEL_DEBUG
}

func (c *Config) ShouldLogDebug() bool {
	return c.LogLevel == LOG_LEVEL_DEBUG
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
		c.LogLevel = LOG_LEVEL_INFO
	}
}