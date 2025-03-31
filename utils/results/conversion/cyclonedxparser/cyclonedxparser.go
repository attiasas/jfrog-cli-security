package cyclonedxparser

import (
	"fmt"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	xrayToolName = "JFrog Xray Scanner"
)

type CmdResultsCycloneDxConverter struct {
	bom     *cyclonedx.BOM
	cmdType utils.CommandType

	xrayVersion    string
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
	cdc.xrayVersion = xrayVersion
	// Reset the BOM
	cdc.bom = cyclonedx.NewBOM()
	cdc.bom.SerialNumber = fmt.Sprintf("urn:uuid:%s", multiScanId)
	cdc.bom.Metadata = &cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools:     &cyclonedx.ToolsChoice{},
		Authors:   &[]cyclonedx.OrganizationalContact{{Name: "JFrog"}},
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseNewTargetResults(target results.ScanTarget, _ ...error) (err error) {
	// TODO: Implement Metadata Components for single/multiple targets
	return
}

func createVulnerability(id, description string, severity severityutils.Severity, applicabilityStatus jasutils.ApplicabilityStatus) cyclonedx.Vulnerability {
	return cyclonedx.Vulnerability{
		ID:          id,
		Description: description,
		Ratings: &[]cyclonedx.VulnerabilityRating{{
			Severity: severityutils.SeverityToCycloneDxSeverity(severity),
			Score:    severityutils.GetSeverityScoreFloat64(severity, applicabilityStatus),
		}},
	}
}

func (cdc *CmdResultsCycloneDxConverter) getExistingVulnerability(id string) *cyclonedx.Vulnerability {
	if cdc.bom.Vulnerabilities == nil {
		return nil
	}
	for _, vulnerability := range *cdc.bom.Vulnerabilities {
		if vulnerability.ID == id {
			return &vulnerability
		}
	}
	return nil
}

func (cdc *CmdResultsCycloneDxConverter) getExistingComponent(ref string) *cyclonedx.Component {
	if cdc.bom == nil || cdc.bom.Components == nil {
		return nil
	}
	for _, component := range *cdc.bom.Components {
		if component.BOMRef == ref {
			return &component
		}
	}
	return nil
}

func (cdc *CmdResultsCycloneDxConverter) ParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	cdc.addXrayToolIfMissing()
	err = results.ForEachScaVulnerabilities(target, scaResponse.Scan.Vulnerabilities, cdc.entitledForJas, results.ScanResultsToRuns(applicableScan),
		func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (e error) {
			// Create a new SCA vulnerability if needed, add the affected component if needed and add the vulnerability to the BOM
			cycloneVulnerability := cdc.getOrCreateScaIssue(results.GetIssueIdentifier(cves, vulnerability.IssueId, ""), vulnerability.Summary, severity, applicabilityStatus)
			if hasImpactedAffects(*cycloneVulnerability, bom.XrayComponentIdToPurl(impactedPackagesId)) {
				// The affected component is already in the vulnerability
				return
			}
			// Add the affected component to the vulnerability
			if cycloneVulnerability.Affects == nil {
				cycloneVulnerability.Affects = &[]cyclonedx.Affects{}
			}
			*cycloneVulnerability.Affects = append(*cycloneVulnerability.Affects, createScaImpactedAffects(impactedPackagesId, fixedVersion))
			return
		},
	)
	return
}

func (cdc *CmdResultsCycloneDxConverter) addXrayToolIfMissing() {
	if cdc.bom == nil || cdc.bom.Metadata == nil || cdc.bom.Metadata.Tools == nil {
		return
	}
	if cdc.bom.Metadata.Tools.Services == nil {
		cdc.bom.Metadata.Tools.Services = &[]cyclonedx.Service{}
	}
	services := *cdc.bom.Metadata.Tools.Services
	for _, service := range services {
		if service.Name == xrayToolName {
			return
		}
	}
	*cdc.bom.Metadata.Tools.Services = append(services, cyclonedx.Service{
		Name:    xrayToolName,
		Version: cdc.xrayVersion,
	})
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateScaIssue(id, description string, severity severityutils.Severity, applicabilityStatus jasutils.ApplicabilityStatus) (scaVulnerability *cyclonedx.Vulnerability) {
	if scaVulnerability = cdc.getExistingVulnerability(id); scaVulnerability != nil {
		return
	}
	// Create a new SCA vulnerability, add it to the BOM and return it
	if cdc.bom.Vulnerabilities == nil {
		cdc.bom.Vulnerabilities = &[]cyclonedx.Vulnerability{}
	}
	*cdc.bom.Vulnerabilities = append(*cdc.bom.Vulnerabilities, createVulnerability(id, description, severity, applicabilityStatus))
	return &(*cdc.bom.Vulnerabilities)[len(*cdc.bom.Vulnerabilities)-1]
}

func hasImpactedAffects(vulnerability cyclonedx.Vulnerability, affectedRef string) bool {
	if vulnerability.Affects == nil {
		return false
	}
	for _, affected := range *vulnerability.Affects {
		if affected.Ref == affectedRef {
			return true
		}
	}
	return false
}

func createScaImpactedAffects(impactedPackageId string, fixedVersion []string) (affect cyclonedx.Affects) {
	_, impactedPackageVersion, _ := techutils.SplitComponentId(impactedPackageId)
	affect = cyclonedx.Affects{
		Ref:   bom.XrayComponentIdToPurl(impactedPackageId),
		Range: &[]cyclonedx.AffectedVersions{},
	}
	// Affected range
	*affect.Range = append(*affect.Range, cyclonedx.AffectedVersions{
		Version: impactedPackageVersion,
		Status:  cyclonedx.VulnerabilityStatusAffected,
	})
	// Fixed ranges
	for _, fixedVersion := range fixedVersion {
		*affect.Range = append(*affect.Range, cyclonedx.AffectedVersions{
			Version: fixedVersion,
			Status:  cyclonedx.VulnerabilityStatusNotAffected,
		})
	}
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
	return results.ForEachJasIssues(results.ScanResultsToRuns(secrets), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		cdc.addJasToolIfMissing(run.Tool.Driver)
		// Create a new JAS vulnerability, add it to the BOM and return it
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleShortDescriptionText(rule), severity)
		if hasImpactedAffects(*jasIssue, getJasFileRef(location)) {
			// The affected component is already in the vulnerability
			return
		}
		// jasIssue.Source = &cyclonedx.Source{Name: sarifutils.GetRunToolFullName(run)}
		// Add the affected component to the vulnerability
		if jasIssue.Affects == nil {
			jasIssue.Affects = &[]cyclonedx.Affects{}
		}
		*jasIssue.Affects = append(*jasIssue.Affects, cyclonedx.Affects{Ref: getJasFileRef(location)})
		if jasIssue.Properties == nil {
			jasIssue.Properties = &[]cyclonedx.Property{}
		}
		*jasIssue.Properties = append(*jasIssue.Properties, cyclonedx.Property{Name: "jfrog:secret:location", Value: fmt.Sprintf("%s#L%d-L%d", getJasFileRef(location), sarifutils.GetLocationStartLine(location), sarifutils.GetLocationEndLine(location))})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) ParseIacs(target results.ScanTarget, violations bool, iac []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	return results.ForEachJasIssues(results.ScanResultsToRuns(iac), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		cdc.addJasToolIfMissing(run.Tool.Driver)
		// Create a new JAS vulnerability, add it to the BOM and return it
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleShortDescriptionText(rule), severity)
		if hasImpactedAffects(*jasIssue, getJasFileRef(location)) {
			// The affected component is already in the vulnerability
			return
		}
		// jasIssue.Source = &cyclonedx.Source{Name: sarifutils.GetRunToolFullName(run)}
		// Add the affected component to the vulnerability
		if jasIssue.Affects == nil {
			jasIssue.Affects = &[]cyclonedx.Affects{}
		}
		*jasIssue.Affects = append(*jasIssue.Affects, cyclonedx.Affects{Ref: getJasFileRef(location)})
		if jasIssue.Properties == nil {
			jasIssue.Properties = &[]cyclonedx.Property{}
		}
		*jasIssue.Properties = append(*jasIssue.Properties, cyclonedx.Property{Name: "jfrog:iac:location", Value: fmt.Sprintf("%s#L%d-L%d", getJasFileRef(location), sarifutils.GetLocationStartLine(location), sarifutils.GetLocationEndLine(location))})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) ParseSast(target results.ScanTarget, violations bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	return results.ForEachJasIssues(results.ScanResultsToRuns(sast), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		cdc.addJasToolIfMissing(run.Tool.Driver)
		// Create a new JAS vulnerability, add it to the BOM and return it
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleShortDescriptionText(rule), severity)
		if hasImpactedAffects(*jasIssue, getJasFileRef(location)) {
			// The affected component is already in the vulnerability
			return
		}
		// jasIssue.Source = &cyclonedx.Source{Name: sarifutils.GetRunToolFullName(run)}
		// Add the affected component to the vulnerability
		if jasIssue.Affects == nil {
			jasIssue.Affects = &[]cyclonedx.Affects{}
		}
		*jasIssue.Affects = append(*jasIssue.Affects, cyclonedx.Affects{Ref: getJasFileRef(location)})
		if jasIssue.Properties == nil {
			jasIssue.Properties = &[]cyclonedx.Property{}
		}
		*jasIssue.Properties = append(*jasIssue.Properties, cyclonedx.Property{Name: "jfrog:sast:location", Value: fmt.Sprintf("%s#L%d-L%d", getJasFileRef(location), sarifutils.GetLocationStartLine(location), sarifutils.GetLocationEndLine(location))})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) addJasToolIfMissing(tool *sarif.ToolComponent) {
	if cdc.bom == nil || cdc.bom.Metadata == nil || cdc.bom.Metadata.Tools == nil {
		return
	}
	if cdc.bom.Metadata.Tools.Services == nil {
		cdc.bom.Metadata.Tools.Services = &[]cyclonedx.Service{}
	}
	services := *cdc.bom.Metadata.Tools.Services
	for _, service := range services {
		if service.Name == tool.Name {
			return
		}
	}
	*cdc.bom.Metadata.Tools.Services = append(services, cyclonedx.Service{
		Name:    tool.Name,
		Version: *tool.Version,
	})
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateJasIssue(id, description string, severity severityutils.Severity) (scaVulnerability *cyclonedx.Vulnerability) {
	if scaVulnerability = cdc.getExistingVulnerability(id); scaVulnerability != nil {
		return
	}
	// Create a new SCA vulnerability, add it to the BOM and return it
	if cdc.bom.Vulnerabilities == nil {
		cdc.bom.Vulnerabilities = &[]cyclonedx.Vulnerability{}
	}
	*cdc.bom.Vulnerabilities = append(*cdc.bom.Vulnerabilities, createVulnerability(id, description, severity, jasutils.NotScanned))
	return &(*cdc.bom.Vulnerabilities)[len(*cdc.bom.Vulnerabilities)-1]
}

func getJasFileRef(location *sarif.Location) string {
	return sarifutils.GetLocationFileName(location)
}
