package bom

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

// SbomGenerator is an interface for generating SBOMs from different sources.
type SbomGenerator interface {
	// Parallel creates a new instance of the generator for parallel execution.
	Parallel(threadId int) SbomGenerator
	// GenerateSbom generates a CycloneDX SBOM for the given target.
	GenerateSbom(target results.ScanTarget) (*cyclonedx.BOM, error)
}
