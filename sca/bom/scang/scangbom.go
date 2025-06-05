package scang

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

type ScangBomGenerator struct {
	BinaryPath string
}

func (sbg *ScangBomGenerator) Parallel(threadId int) bom.SbomGenerator {
	return sbg
}

func (sbg *ScangBomGenerator) GenerateSbom(target results.ScanTarget) (sbom *cyclonedx.BOM, err error) {
	// if sbg.BinaryPath == "" {
	// 	return nil, results.ErrNoScangBinary
	// }

	// scangCmd := results.NewScangCommand(sbg.BinaryPath, target)
	// scangCmd.SetThreadId(target.ThreadId)
	// scangCmd.SetOutputFormat(results.OutputFormatCycloneDX)

	// sbom, err = scangCmd.Run()
	// if err != nil {
	// 	return nil, err
	// }

	return sbom, nil
}
