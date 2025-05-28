package scan

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type PackageInfo struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	PURL     string   `json:"purl"`
	Type     string   `json:"type"`
	Location string   `json:"location"`
	Licenses []string `json:"licenses"`
}

type ScaEngine interface {
	Scan(ctx context.Context, path string) ([]*PackageInfo, error)
	Name() string
}

type Scanner interface {
	Scan(path string, config Config) (*cdx.BOM, error)
}
