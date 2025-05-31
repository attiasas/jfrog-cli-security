package bom

import (
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"jfrog.com/scang/pkg/scan"
	"path/filepath"
	"runtime"
)

type JfrogNewBomGenerator struct {
}

func (jbg *JfrogNewBomGenerator) Parallel(threadId int) SbomGenerator {
	return jbg
}

func (jbg *JfrogNewBomGenerator) GenerateSbom(target results.ScanTarget) (*cyclonedx.BOM, error) {
	projectRoot := "/Users/talz/workspace/src/jfrog.com/scang/"
	pluginBinaryName := "scangplugin"
	pluginBinaryPath := filepath.Join(projectRoot, "build", "plugin", fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH), pluginBinaryName)
	scanner, err := scan.CreateScannerPluginClient(pluginBinaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner plugin client: %w", err)
	}

	scanConfig := scan.Config{
		Name:    "test-cli-direct-scan", // Match name
		Version: "0.0.8",                // Match version
	}

	bom, err := scanner.Scan(target.Target, scanConfig) // Updated to use new alias
	if err != nil {
		return nil, fmt.Errorf("failed to scan target %s: %w", target.Target, err)
	}
	return bom, nil
}
