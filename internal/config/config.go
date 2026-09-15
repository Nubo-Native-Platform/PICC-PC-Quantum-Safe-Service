// Package config centralizes environment-driven configuration for the
// service so main.go and other packages don't read os.Getenv directly.
package config

import "os"

// Config holds runtime configuration for the service.
type Config struct {
	Port    string // HTTP port to listen on
	GinMode string // "debug" or "release"
	KeyPath string // path to the persisted ML-KEM private key file
	KeyJSON string // direct JSON string of the keypair (from env var)
}

// Load reads configuration from environment variables, applying sane
// defaults for local development.
func Load() Config {
	return Config{
		Port:    getEnv("PORT", "8080"),
		GinMode: getEnv("GIN_MODE", "debug"),
		KeyPath: getEnv("MLKEM_KEY_PATH", "keys/mlkem_private.key"),
		KeyJSON: getFirstEnv([]string{"MLKEM_KEY_JSON", "KEY_JSON"}, ""),
	}
}

func getFirstEnv(keys []string, fallback string) string {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return fallback
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
