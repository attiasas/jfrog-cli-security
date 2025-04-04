package cyclonedxparser

import (
	"fmt"
	"os"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	xrayToolName = "JFrog Xray Scanner"

	jasIssueLocationPropertyTemplate = "jfrog:%s:location"
	applicabilityStatusPropertyName  = "jfrog:contextual-analysis:status"
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
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	component := bom.CreateWorkingDirComponent(target.Target)
	if cdc.bom.Metadata.Component == nil {
		// Single target
		cdc.bom.Metadata.Component = &component
		return
	}
	// Multiple targets
	if cdc.bom.Metadata.Component.Components == nil || len(*cdc.bom.Metadata.Component.Components) == 0 {
		if cdc.bom.Metadata.Component.BOMRef == component.BOMRef {
			// The component is already in the BOM
			return
		}
		// The component is not in the BOM, Convert from single target to multiple targets
		if currentWd, e := os.Getwd(); e != nil {
			return e
		} else {
			wdComponent := bom.CreateWorkingDirComponent(currentWd)
			// Add the old main component as a sub-component
			wdComponent.Components = &[]cyclonedx.Component{*cdc.bom.Metadata.Component}
			// Set the current working directory as the main component
			cdc.bom.Metadata.Component = &wdComponent
		}
	}
	for _, existingComponent := range *cdc.bom.Metadata.Component.Components {
		if existingComponent.BOMRef == component.BOMRef {
			// The component is already in the BOM
			return
		}
	}
	// The component is not in the BOM, Add the new sub-component
	*cdc.bom.Metadata.Component.Components = append(*cdc.bom.Metadata.Component.Components, component)
	return
}

func (cdc *CmdResultsCycloneDxConverter) getExistingComponentIndex(ref string) int {
	if cdc.bom == nil || cdc.bom.Components == nil {
		return -1
	}
	for i, component := range *cdc.bom.Components {
		if component.BOMRef == ref {
			return i
		}
	}
	return -1
}

func (cdc *CmdResultsCycloneDxConverter) getExistingComponent(index int) *cyclonedx.Component {
	if cdc.bom == nil || cdc.bom.Components == nil || index < 0 || index >= len(*cdc.bom.Components) {
		return nil
	}
	return &(*cdc.bom.Components)[index]
}

func (cdc *CmdResultsCycloneDxConverter) ParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	cdc.addXrayToolIfMissing()
	err = results.ForEachScaVulnerabilities(target, scaResponse.Scan.Vulnerabilities, cdc.entitledForJas, results.ScanResultsToRuns(applicableScan),
		func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (e error) {
			// Create or get the affected component
			affectedComponentIndex := cdc.getOrCreateScaComponent(impactedPackagesId)
			affectedComponent := cdc.getExistingComponent(affectedComponentIndex)
			// Create a new SCA vulnerability if needed, add the affected component if needed and add the vulnerability to the BOM
			cycloneVulnerability := cdc.getOrCreateScaIssue(results.GetIssueIdentifier(cves, vulnerability.IssueId, ""), vulnerability.Summary, severity, applicabilityStatus)
			if hasImpactedAffects(*cycloneVulnerability, *affectedComponent) {
				// The affected component is already in the vulnerability
				return
			}
			// Add the affected component to the vulnerability
			if cycloneVulnerability.Affects == nil {
				cycloneVulnerability.Affects = &[]cyclonedx.Affects{}
			}
			*cycloneVulnerability.Affects = append(*cycloneVulnerability.Affects, createScaImpactedAffects(*affectedComponent, fixedVersion))
			return
		},
	)
	return
}

func (cdc *CmdResultsCycloneDxConverter) addXrayToolIfMissing() {
	if service := cdc.searchForService(xrayToolName); service != nil || cdc.bom == nil {
		// The service is already in the BOM
		return
	}
	// Add the service to the BOM
	if cdc.bom.Metadata.Tools == nil {
		cdc.bom.Metadata.Tools = &cyclonedx.ToolsChoice{}
	}
	if cdc.bom.Metadata.Tools.Services == nil {
		cdc.bom.Metadata.Tools.Services = &[]cyclonedx.Service{}
	}
	*cdc.bom.Metadata.Tools.Services = append(*cdc.bom.Metadata.Tools.Services, cyclonedx.Service{
		Name:    xrayToolName,
		Version: cdc.xrayVersion,
	})
}

func hasImpactedAffects(vulnerability cyclonedx.Vulnerability, affectedComponent cyclonedx.Component) bool {
	if vulnerability.Affects == nil {
		return false
	}
	for _, affected := range *vulnerability.Affects {
		if affected.Ref == affectedComponent.BOMRef {
			return true
		}
	}
	return false
}

func createScaImpactedAffects(affectedComponent cyclonedx.Component, fixedVersion []string) (affect cyclonedx.Affects) {
	_, impactedPackageVersion, _ := bom.SplitPackageURL(affectedComponent.PackageURL)
	affect = cyclonedx.Affects{
		Ref:   affectedComponent.BOMRef,
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

func (cdc *CmdResultsCycloneDxConverter) ParseLicenses(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	cdc.addXrayToolIfMissing()
	return results.ForEachLicenses(target, scaResponse.Scan.Licenses,
		func(license services.License, impactedPackagesId string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (e error) {
			// Create or get the affected component
			affectedComponentIndex := cdc.getOrCreateScaComponent(impactedPackagesId)
			affectedComponent := cdc.getExistingComponent(affectedComponentIndex)
			// Search for the license in the effected component
			found := false
			if affectedComponent.Licenses != nil {
				for _, licenseChoice := range *affectedComponent.Licenses {
					if licenseChoice.License == nil {
						// Not a license
						continue
					}
					if licenseChoice.License.ID == license.Key {
						found = true
						break
					}
				}
			}
			if found {
				// The license is already in the component, nothing to do
				return
			}
			// Add the license to the component
			if affectedComponent.Licenses == nil {
				affectedComponent.Licenses = &cyclonedx.Licenses{}
			}
			*affectedComponent.Licenses = append(*affectedComponent.Licenses, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					ID: license.Key,
				},
			})
			return
		},
	)
}

func (cdc *CmdResultsCycloneDxConverter) ParseSbom(target results.ScanTarget, sbom *cyclonedx.BOM) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	if sbom == nil {
		return
	}
	// Append the components and dependencies from the sbom to the current BOM
	cdc.appendComponents(sbom.Components)
	cdc.appendDependencies(sbom.Dependencies)
	return
}

func (cdc *CmdResultsCycloneDxConverter) appendComponents(components *[]cyclonedx.Component) {
	if cdc.bom == nil || components == nil || len(*components) == 0 {
		// No components to append
		return
	}
	if cdc.bom.Components == nil {
		cdc.bom.Components = &[]cyclonedx.Component{}
	}
	for _, component := range *components {
		if cdc.getExistingComponentIndex(component.BOMRef) >= 0 {
			// The component is already in the BOM
			continue
		}
		// Append the component to the BOM
		*cdc.bom.Components = append(*cdc.bom.Components, component)
	}
}

func (cdc *CmdResultsCycloneDxConverter) appendDependencies(dependencies *[]cyclonedx.Dependency) {
	if cdc.bom == nil || dependencies == nil || len(*dependencies) == 0 {
		// No dependencies to append
		return
	}
	if cdc.bom.Dependencies == nil {
		cdc.bom.Dependencies = &[]cyclonedx.Dependency{}
	}
	for _, dependency := range *dependencies {
		if cdc.getExistingDependencyEntry(dependency.Ref) != nil {
			// The dependency is already in the BOM
			continue
		}
		// Append the dependency to the BOM
		*cdc.bom.Dependencies = append(*cdc.bom.Dependencies, dependency)
	}
}

func (cdc *CmdResultsCycloneDxConverter) getExistingDependencyEntry(ref string) *cyclonedx.Dependency {
	if cdc.bom == nil || cdc.bom.Dependencies == nil {
		return nil
	}
	for _, dependency := range *cdc.bom.Dependencies {
		if dependency.Ref == ref {
			return &dependency
		}
	}
	return nil
}

func (cdc *CmdResultsCycloneDxConverter) ParseSecrets(target results.ScanTarget, violations bool, secrets []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	cdc.addJasService(secrets)
	return results.ForEachJasIssues(results.ScanResultsToRuns(secrets), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		// Create or get the affected component
		affectedComponentIndex := cdc.getOrCreateJasComponent(location)
		// Create a new JAS vulnerability, add it to the BOM and return it
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleShortDescriptionText(rule), severity)
		// Add the location to the vulnerability
		addJasIssueAffects(jasIssue, *cdc.getExistingComponent(affectedComponentIndex), cyclonedx.Property{
			Name:  fmt.Sprintf(jasIssueLocationPropertyTemplate, "secret"),
			Value: fmt.Sprintf("%s#L%d-L%d", sarifutils.GetLocationFileName(location), sarifutils.GetLocationStartLine(location), sarifutils.GetLocationEndLine(location)),
		})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) addJasService(runs []results.ScanResult[[]*sarif.Run]) {
	for _, runInfo := range runs {
		for _, run := range runInfo.Scan {
			// Add tool if missing
			if run == nil {
				continue
			}
			cdc.addJasToolIfMissing(run.Tool.Driver)
		}
	}
}

func (cdc *CmdResultsCycloneDxConverter) ParseIacs(target results.ScanTarget, violations bool, iac []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	cdc.addJasService(iac)
	return results.ForEachJasIssues(results.ScanResultsToRuns(iac), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		// Create or get the affected component
		affectedComponentIndex := cdc.getOrCreateJasComponent(location)
		// Create a new JAS vulnerability, add it to the BOM and return it
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleShortDescriptionText(rule), severity)
		// Add the location to the vulnerability
		addJasIssueAffects(jasIssue, *cdc.getExistingComponent(affectedComponentIndex), cyclonedx.Property{
			Name:  fmt.Sprintf(jasIssueLocationPropertyTemplate, "iac"),
			Value: fmt.Sprintf("%s#L%d-L%d", sarifutils.GetLocationFileName(location), sarifutils.GetLocationStartLine(location), sarifutils.GetLocationEndLine(location)),
		})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) ParseSast(target results.ScanTarget, violations bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	cdc.addJasService(sast)
	return results.ForEachJasIssues(results.ScanResultsToRuns(sast), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		// Create or get the affected component
		affectedComponentIndex := cdc.getOrCreateJasComponent(location)
		// Create a new JAS vulnerability, add it to the BOM and return it
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleShortDescriptionText(rule), severity)
		// Add the location to the vulnerability
		addJasIssueAffects(jasIssue, *cdc.getExistingComponent(affectedComponentIndex), cyclonedx.Property{
			Name:  fmt.Sprintf(jasIssueLocationPropertyTemplate, "sast"),
			Value: fmt.Sprintf("%s#L%d-L%d", sarifutils.GetLocationFileName(location), sarifutils.GetLocationStartLine(location), sarifutils.GetLocationEndLine(location)),
		})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) addJasToolIfMissing(tool *sarif.ToolComponent) {
	if service := cdc.searchForService(tool.Name); service != nil {
		// The service is already in the BOM
		return
	}
	if tool == nil || cdc.bom == nil {
		return
	}
	// Add the service to the BOM
	if cdc.bom.Metadata.Tools == nil {
		cdc.bom.Metadata.Tools = &cyclonedx.ToolsChoice{}
	}
	if cdc.bom.Metadata.Tools.Services == nil {
		cdc.bom.Metadata.Tools.Services = &[]cyclonedx.Service{}
	}
	*cdc.bom.Metadata.Tools.Services = append(*cdc.bom.Metadata.Tools.Services, cyclonedx.Service{
		Name:    tool.Name,
		Version: *tool.Version,
	})
}

func (cdc *CmdResultsCycloneDxConverter) searchForService(serviceName string) *cyclonedx.Service {
	if cdc.bom == nil || cdc.bom.Metadata == nil || cdc.bom.Metadata.Tools == nil || cdc.bom.Metadata.Tools.Services == nil {
		return nil
	}
	for _, service := range *cdc.bom.Metadata.Tools.Services {
		if service.Name == serviceName {
			return &service
		}
	}
	return nil
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateScaComponent(impactedPackageId string) (componentIndex int) {
	ref := bom.GetScaComponentRef(impactedPackageId)
	// Check if the component already exists in the BOM
	if componentIndex = cdc.getExistingComponentIndex(ref); componentIndex >= 0 {
		return
	}
	// Create a new component, add it to the BOM and return it
	if cdc.bom.Components == nil {
		cdc.bom.Components = &[]cyclonedx.Component{}
	}
	*cdc.bom.Components = append(*cdc.bom.Components, bom.CreateScaComponent(impactedPackageId))
	return len(*cdc.bom.Components) - 1
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateJasComponent(location *sarif.Location) (componentIndex int) {
	ref := bom.GetFileRef(sarifutils.GetLocationFileName(location))
	// Check if the component already exists in the BOM
	if componentIndex = cdc.getExistingComponentIndex(ref); componentIndex >= 0 {
		return
	}
	// Create a new component, add it to the BOM and return it
	if cdc.bom.Components == nil {
		cdc.bom.Components = &[]cyclonedx.Component{}
	}
	*cdc.bom.Components = append(*cdc.bom.Components, cyclonedx.Component{
		BOMRef: ref,
		Type:   cyclonedx.ComponentTypeFile,
		Name:   sarifutils.GetLocationFileName(location),
	})
	return len(*cdc.bom.Components) - 1
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

func createBaseVulnerability(id, description string, severity severityutils.Severity, applicabilityStatus jasutils.ApplicabilityStatus, properties ...cyclonedx.Property) cyclonedx.Vulnerability {
	vuln := cyclonedx.Vulnerability{
		BOMRef:      id,
		ID:          id,
		Description: description,
		Ratings: &[]cyclonedx.VulnerabilityRating{{
			Severity: severityutils.SeverityToCycloneDxSeverity(severity),
			Score:    severityutils.GetSeverityScoreFloat64(severity, applicabilityStatus),
		}},
	}
	if len(properties) > 0 {
		vuln.Properties = &properties
	}
	return vuln
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateScaIssue(id, description string, severity severityutils.Severity, applicabilityStatus jasutils.ApplicabilityStatus) (scaVulnerability *cyclonedx.Vulnerability) {
	if scaVulnerability = cdc.getExistingVulnerability(id); scaVulnerability != nil {
		return
	}
	// Create a new SCA vulnerability, add it to the BOM and return it
	if cdc.bom.Vulnerabilities == nil {
		cdc.bom.Vulnerabilities = &[]cyclonedx.Vulnerability{}
	}
	properties := []cyclonedx.Property{}
	if applicabilityStatus != jasutils.NotScanned {
		properties = append(properties, cyclonedx.Property{
			Name:  applicabilityStatusPropertyName,
			Value: applicabilityStatus.String(),
		})
	}
	vulnerability := createBaseVulnerability(id, description, severity, applicabilityStatus, properties...)
	*cdc.bom.Vulnerabilities = append(*cdc.bom.Vulnerabilities, vulnerability)
	return &(*cdc.bom.Vulnerabilities)[len(*cdc.bom.Vulnerabilities)-1]
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateJasIssue(id, description string, severity severityutils.Severity) (scaVulnerability *cyclonedx.Vulnerability) {
	if scaVulnerability = cdc.getExistingVulnerability(id); scaVulnerability != nil {
		return
	}
	// Create a new SCA vulnerability, add it to the BOM and return it
	if cdc.bom.Vulnerabilities == nil {
		cdc.bom.Vulnerabilities = &[]cyclonedx.Vulnerability{}
	}
	*cdc.bom.Vulnerabilities = append(*cdc.bom.Vulnerabilities, createBaseVulnerability(id, description, severity, jasutils.NotScanned))
	return &(*cdc.bom.Vulnerabilities)[len(*cdc.bom.Vulnerabilities)-1]
}

func addJasIssueAffects(jasIssue *cyclonedx.Vulnerability, affectedComponent cyclonedx.Component, properties ...cyclonedx.Property) {
	if hasImpactedAffects(*jasIssue, affectedComponent) {
		// The affected component is already in the vulnerability
		return
	}
	// Add the affected component to the vulnerability
	if jasIssue.Affects == nil {
		jasIssue.Affects = &[]cyclonedx.Affects{}
	}
	*jasIssue.Affects = append(*jasIssue.Affects, cyclonedx.Affects{Ref: affectedComponent.BOMRef})
	if len(properties) == 0 {
		// No properties to add
		return
	}
	// Add the properties to the vulnerability
	if jasIssue.Properties == nil {
		jasIssue.Properties = &[]cyclonedx.Property{}
	}
	*jasIssue.Properties = append(*jasIssue.Properties, properties...)
}
