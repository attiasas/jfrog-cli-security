package scang

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

type ScangBomGenerator struct {
	BinaryPath string
	theadId    int
}

func GetScangExecutableName() string {
	analyzerManager := "scang"
	if coreutils.IsWindows() {
		return analyzerManager + ".exe"
	}
	return analyzerManager
}

func (sbg *ScangBomGenerator) Parallel(threadId int) bom.SbomGenerator {
	sbgCopy := &ScangBomGenerator{
		BinaryPath: sbg.BinaryPath,
		theadId:    threadId,
	}
	return sbgCopy
}

func (sbg *ScangBomGenerator) GenerateSbom(target results.ScanTarget) (sbom *cyclonedx.BOM, err error) {
	log.Info(clientUtils.GetLogMsgPrefix(sbg.theadId, false) + fmt.Sprintf("Generating SBOM for target: %s", target.Target))
	if sbg.BinaryPath == "" {
		sbg.BinaryPath, err = GetDefaultScangExecutable()
		if err != nil {
			return nil, fmt.Errorf("failed to get scang executable: %w", err)
		}
	}
	sbomCmdResults, err := sbg.executeScang(sbg.BinaryPath, target)
	if err != nil {
		return nil, fmt.Errorf("failed to execute scang command: %w", err)
	}
	return decodeJsonBytes(sbomCmdResults)
}

func GetDefaultScangExecutable() (scangPath string, err error) {
	jfrogDir, err := config.GetJfrogDependenciesPath()
	if err != nil {
		return "", err
	}
	scangPath = filepath.Join(jfrogDir, "scang", GetScangExecutableName())
	var exists bool
	if exists, err = fileutils.IsFileExists(scangPath, false); err != nil {
		return
	}
	if !exists {
		err = fmt.Errorf("unable to locate the scang executable at %s.", scangPath)
	}
	return
}

func (sbg *ScangBomGenerator) executeScang(scangBinary string, target results.ScanTarget) (output []byte, err error) {
	log.Debug(fmt.Sprintf("%sExecuting command: %s %q", clientUtils.GetLogMsgPrefix(sbg.theadId, false), scangBinary, target.Target))
	cmd := exec.Command(scangBinary, target.Target)
	defer func() {
		if cmd.ProcessState != nil && !cmd.ProcessState.Exited() {
			// If the process is still running when the function returns, we attempt to kill it.
			if killProcessError := cmd.Process.Kill(); errorutils.CheckError(killProcessError) != nil {
				err = errors.Join(err, killProcessError)
			}
		}
	}()
	// Execute the command and capture its output
	if output, err = cmd.CombinedOutput(); err != nil {
		if len(output) > 0 {
			log.Debug(clientUtils.GetLogMsgPrefix(sbg.theadId, false) + fmt.Sprintf("%s %q output: %s", target.Target, strings.Join(cmd.Args, " "), string(output)))
		}
		return nil, fmt.Errorf("failed to execute scang command: %w", err)
	}
	// Check if the output is empty
	if len(output) == 0 {
		return nil, fmt.Errorf("scang command returned no output for target %s", target.Target)
	}
	return
}

func decodeJsonBytes(bomBytes []byte) (sbom *cyclonedx.BOM, err error) {
	reader := bytes.NewReader(bomBytes)
	// Decode the BOM
	decoder := cyclonedx.NewBOMDecoder(reader, cyclonedx.BOMFileFormatJSON)
	if err = decoder.Decode(sbom); err != nil {
		return nil, errorutils.CheckErrorf("failed to decode CycloneDX JSON BOM: %s", err.Error())
	}
	return sbom, nil
}
