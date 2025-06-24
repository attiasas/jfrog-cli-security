package scang

// Config holds the configuration for scang library operations.
type Config struct {
	BomRef         string   `json:"bom-ref,omitempty"`
	Type           string   `json:"type,omitempty"`
	Name           string   `json:"name,omitempty"`
	Version        string   `json:"version,omitempty"`
	IgnorePatterns []string `json:"ignorePatterns,omitempty"`
}
