package scang

import (
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdx"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

const PluginName = "scangplugin"

type ScangBomGenerator struct {
	BinaryPath string
	theadId    int
}

func (sbg *ScangBomGenerator) Parallel(threadId int) bom.SbomGenerator {
	sbgCopy := &ScangBomGenerator{
		BinaryPath: sbg.BinaryPath,
		theadId:    threadId,
	}
	return sbgCopy
}

func GetScangExecutableName() string {
	if coreutils.IsWindows() {
		return PluginName + ".exe"
	}
	return PluginName
}

func GetDefaultScangExecutable() (scangPath string, err error) {
	jfrogDir, err := config.GetJfrogDependenciesPath()
	if err != nil {
		return "", err
	}
	scangPath = filepath.Join(jfrogDir, pluginName, GetScangExecutableName())
	exists, err := fileutils.IsFileExists(scangPath, false)
	if err != nil || exists {
		return
	}
	return exec.LookPath(PluginName)
}

func (sbg *ScangBomGenerator) GenerateSbom(target results.ScanTarget) (sbom *cyclonedx.BOM, err error) {
	log.Info(clientUtils.GetLogMsgPrefix(sbg.theadId, false) + fmt.Sprintf("Generating SBOM for target: %s", target.Target))
	// Get the path to the scang executable
	if sbg.BinaryPath == "" {
		sbg.BinaryPath, err = GetDefaultScangExecutable()
		if err != nil {
			return nil, fmt.Errorf("failed to get scang executable: %w", err)
		}
	}
	exists, err := fileutils.IsFileExists(sbg.BinaryPath, false)
	if err != nil {
		return
	} else if !exists {
		err = fmt.Errorf("unable to locate the scang executable at %s.", sbg.BinaryPath)
	}
	// Run the scang command to generate the SBOM
	if sbom, err = sbg.executeScanner(sbg.BinaryPath, target); err != nil {
		return nil, fmt.Errorf("failed to execute scang command: %w", err)
	}
	sbg.logScannerOutput(sbom, target.Target)
	return
}

func (sbg *ScangBomGenerator) executeScanner(scangBinary string, target results.ScanTarget) (output *cyclonedx.BOM, err error) {
	log.Debug(fmt.Sprintf("%sExecuting command: %s %q", clientUtils.GetLogMsgPrefix(sbg.theadId, false), scangBinary, target.Target))

	// Create a new plugin client
	scanner, err := CreateScannerPluginClient(scangBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to create scang plugin client: %w", err)
	}
	scanConfig := Config{
		Name:    target.Name,
		Version: "0.0.8",
	}
	return scanner.Scan(target.Target, scanConfig)
}

func (sbg *ScangBomGenerator) logScannerOutput(output *cyclonedx.BOM, target string) {
	libComponents := cdx.GetLibraryComponentRefs(output)
	log.Info(clientUtils.GetLogMsgPrefix(sbg.theadId, false) + fmt.Sprintf("SBOM generated for target '%s': (%d lib Components)", target, len(libComponents)))
	log.Debug(utils.GetAsJsonString(libComponents, false, true))
}
