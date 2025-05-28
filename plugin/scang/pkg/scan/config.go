package scan

// Config holds the configuration for scang library operations.
type Config struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Engines []ScaEngine `json:"engines"`
}
