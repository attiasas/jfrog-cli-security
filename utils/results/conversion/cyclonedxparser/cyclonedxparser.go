package cyclonedxparser

import (
	"fmt"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type CmdResultsCycloneDxConverter struct {
	bom     *cyclonedx.BOM
	cmdType utils.CommandType

	entitledForJas bool
	// Include vulnerabilities/violations in the output
	includeVulnerabilities bool
	hasViolationContext    bool
}

func NewCmdResultsCycloneDxConverter(includeVulnerabilities, hasViolationContext bool) *CmdResultsCycloneDxConverter {
	return &CmdResultsCycloneDxConverter{includeVulnerabilities: includeVulnerabilities, hasViolationContext: hasViolationContext}
}

func (cdc *CmdResultsCycloneDxConverter) Get() (*cyclonedx.BOM, error) {
	if cdc.bom == nil {
		return cyclonedx.NewBOM(), nil
	}
	return cdc.bom, nil
}

func (cdc *CmdResultsCycloneDxConverter) Reset(cmdType utils.CommandType, multiScanId, xrayVersion string, entitledForJas, multipleTargets bool, generalError error) (err error) {
	cdc.cmdType = cmdType
	cdc.entitledForJas = entitledForJas
	// Reset the BOM
	cdc.bom = cyclonedx.NewBOM()
	cdc.bom.SerialNumber = fmt.Sprintf("urn:uuid:%s", multiScanId)
	cdc.bom.Metadata = generateBomMetadata()
	return
}

func generateBomMetadata() *cyclonedx.Metadata {
	jfrogAuthor := &[]cyclonedx.OrganizationalContact{{Name: "JFrog"}}

	return &cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &cyclonedx.ToolsChoice{
			// TODO: what and how many components (JFrog? Xray?, JAS?)
			Components: &[]cyclonedx.Component{{
				Name:      "jfrog",
				Type:      cyclonedx.ComponentTypeApplication,
				Publisher: "JFrog",
				Authors:   jfrogAuthor,
			}},
		},
		// TODO: should we also input here?
		Authors: jfrogAuthor,
		// TODO: build ? should we include?
		Lifecycles: &[]cyclonedx.Lifecycle{{
			Phase: cyclonedx.LifecyclePhaseBuild,
		}},
	}
}

func (cdc *CmdResultsCycloneDxConverter) ParseNewTargetResults(_ results.ScanTarget, _ ...error) (err error) {
	// Not supported in CycloneDx format
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	err = results.ForEachScaVulnerabilities(target, scaResponse.Scan.Vulnerabilities, cdc.entitledForJas, results.ScanResultsToRuns(applicableScan), func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (e error) {
		if cdc.bom.Vulnerabilities == nil {
			cdc.bom.Vulnerabilities = &[]cyclonedx.Vulnerability{}
		}
		*cdc.bom.Vulnerabilities = append(*cdc.bom.Vulnerabilities, cyclonedx.Vulnerability{
			// BOMRef: ,
			ID: results.GetIssueIdentifier(cves, vulnerability.IssueId, ""),
		})

		return
	})
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseLicenses(_ results.ScanTarget, _ results.ScanResult[services.ScanResponse]) (err error) {
	// Not supported in CycloneDx format
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSbom(target results.ScanTarget, sbom *cyclonedx.BOM) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	if sbom.Metadata != nil && sbom.Metadata.Component != nil && sbom.Metadata.Component.Components != nil {
		// Append the base component and metadata from the sbom to the current BOM
		*cdc.bom.Metadata.Component.Components = append(*cdc.bom.Metadata.Component.Components, *sbom.Metadata.Component.Components...)
	}
	// Append the components and dependencies from the sbom to the current BOM
	if sbom.Components != nil {
		if cdc.bom.Components == nil {
			cdc.bom.Components = &[]cyclonedx.Component{}
		}
		*cdc.bom.Components = append(*cdc.bom.Components, *sbom.Components...)
	}
	if sbom.Dependencies != nil {
		if cdc.bom.Dependencies == nil {
			cdc.bom.Dependencies = &[]cyclonedx.Dependency{}
		}
		*cdc.bom.Dependencies = append(*cdc.bom.Dependencies, *sbom.Dependencies...)
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSecrets(target results.ScanTarget, violations bool, secrets []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseIacs(target results.ScanTarget, violations bool, iacs []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSast(target results.ScanTarget, violations bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	return
}
