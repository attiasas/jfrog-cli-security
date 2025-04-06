package scan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

type JfrogBinaryBomGenerator struct {
	indexerPath string
	indexerTempDir string
	bypassArchiveLimits bool
}

func (jbg *JfrogBinaryBomGenerator) GenerateSbom(target results.ScanTarget) (sbom *cyclonedx.BOM, err error) {
	// Create the CycloneDX BOM
	sbom = cyclonedx.NewBOM()
	binaryFileComponent := bom.CreateFileOrDirComponent(target.Target)
	sbom.Metadata = &cyclonedx.Metadata{Component: &binaryFileComponent}
	
	graph, err := jbg.indexFile(target.Target)
	if errorutils.CheckError(err) != nil || graph == nil {
		return nil, fmt.Errorf("failed to index file %s: %w", target.Target, err)
	}
	// In case of empty graph returned by the indexer,
	// for instance due to unsupported file format, continue without sending a
	// graph request to Xray.
	if graph.Id == "" {
		log.Debug(fmt.Sprintf("Empty graph returned for file %s", target.Target))
		return
	}
	sbom.Components, sbom.Dependencies = bom.CompTreeToSbom(graph)
	return
}

func (jbg *JfrogBinaryBomGenerator) indexFile(filePath string) (*xrayUtils.BinaryGraphNode, error) {
	var indexerResults xrayUtils.BinaryGraphNode
	indexerCmd := exec.Command(jbg.indexerPath, indexingCommand, filePath, "--temp-dir", jbg.indexerTempDir)
	if jbg.bypassArchiveLimits {
		indexerCmd.Args = append(indexerCmd.Args, "--bypass-archive-limits")
	}
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	indexerCmd.Stdout = &stdout
	indexerCmd.Stderr = &stderr
	err := indexerCmd.Run()
	if err != nil {
		var e *exec.ExitError
		if errors.As(err, &e) {
			if e.ExitCode() == fileNotSupportedExitCode {
				log.Debug(fmt.Sprintf("File %s is not supported by Xray indexer app.", filePath))
				return &indexerResults, nil
			}
		}
		return nil, errorutils.CheckErrorf("Xray indexer app failed indexing %s with %s: %s", filePath, err, stderr.String())
	}
	if stderr.String() != "" {
		log.Info(stderr.String())
	}
	err = json.Unmarshal(stdout.Bytes(), &indexerResults)
	return &indexerResults, errorutils.CheckError(err)
}