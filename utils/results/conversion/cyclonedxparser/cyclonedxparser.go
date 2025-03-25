package cyclonedxparser

import (
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type CmdResultsCycloneDxConverter struct {
	bom *cyclonedx.BOM
	cmdType utils.CommandType

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
	// Reset the BOM
	cdc.bom = cyclonedx.NewBOM()
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
				Name:    "jfrog",
				Type:    cyclonedx.ComponentTypeApplication,
				Publisher: "JFrog",
				Authors: jfrogAuthor,
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

func (cdc *CmdResultsCycloneDxConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseLicenses(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSbom(target results.ScanTarget, sbom results.Sbom) (err error) {
	if cdc.bom.Dependencies == nil {
		cdc.bom.Dependencies = &[]cyclonedx.Dependency{}
	}
	for _, dep := range sbom.Dependencies {
		*cdc.bom.Dependencies = append(*cdc.bom.Dependencies, cyclonedx.Dependency{
			Ref:     dep.Id,
			Dependencies: &dep.DependsOn,
		})
	}
	if cdc.bom.Components == nil {
		cdc.bom.Components = &[]cyclonedx.Component{}
	}
	for _, comp := range sbom.Components {
		*cdc.bom.Components = append(*cdc.bom.Components, cyclonedx.Component{
			BOMRef: comp.Id,
		})
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSecrets(target results.ScanTarget, violations bool, secrets []results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseIacs(target results.ScanTarget, violations bool, iacs []results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSast(target results.ScanTarget, violations bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	return
}
