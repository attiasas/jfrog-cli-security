package cyclonedxparser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdx"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	// <FILE_REF>#L<START_LINE>C<START_COLUMN>-L<END_LINE>C<END_COLUMN>
	locationIdTemplate = "%s#L%dC%d-L%dC%d"
	// <SCAN_TYPE> + locationIdTemplate
	jasIssueLocationPropertyTemplate = "jfrog:%s:location:" + locationIdTemplate

	secretValidationPropertyTemplate         = "jfrog:secret-validation:status:" + locationIdTemplate
	secretValidationMetadataPropertyTemplate = "jfrog:secret-validation:metadata:" + locationIdTemplate

	applicabilityStatusPropertyName       = "jfrog:contextual-analysis:status"
	applicabilityEvidencePropertyTemplate = "jfrog:contextual-analysis:evidence:" + locationIdTemplate
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
	if multiScanId != "" {
		cdc.bom.SerialNumber = cdx.GetIdRef(multiScanId)
	}
	cdc.bom.Metadata = &cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Authors:   &[]cyclonedx.OrganizationalContact{{Name: "JFrog"}},
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseNewTargetResults(target results.ScanTarget, _ ...error) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	component := cdx.CreateFileOrDirComponent(target.Target)
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
			wdComponent := cdx.CreateFileOrDirComponent(currentWd)
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

func (cdc *CmdResultsCycloneDxConverter) ParseSbomLicenses(target results.ScanTarget, components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	componentsWithLicenses := []cyclonedx.Component{}
	for _, component := range components {
		if component.Licenses == nil || len(*component.Licenses) == 0 {
			// No licenses to parse for this component
			continue
		}
		// Add the component to the list of components with licenses
		componentsWithLicenses = append(componentsWithLicenses, component)
	}
	if len(componentsWithLicenses) == 0 {
		return
	}
	// Append the components and dependencies from the sbom to the current BOM
	cdc.addXrayToolIfMissing()
	cdc.appendComponents(&componentsWithLicenses)
	return nil
}

func (cdc *CmdResultsCycloneDxConverter) ParseCVEs(target results.ScanTarget, enrichedSbom results.ScanResult[*cyclonedx.BOM], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	if enrichedSbom.Scan == nil || enrichedSbom.Scan.Vulnerabilities == nil || len(*enrichedSbom.Scan.Vulnerabilities) == 0 {
		// No vulnerabilities to parse
		return
	}
	source := cdc.addXrayToolIfMissing()
	cdc.addJasService(applicableScan)
	err = results.ForEachScaVulnerability(target, enrichedSbom.Scan, cdc.entitledForJas, results.ScanResultsToRuns(applicableScan),
		func(vulnerability cyclonedx.Vulnerability, component cyclonedx.Component, fixedVersion *[]cyclonedx.AffectedVersions, applicability *formats.Applicability, severity severityutils.Severity) (e error) {
			if vulnerability.Source == nil {
				vulnerability.Source = &cyclonedx.Source{Name: source.Name}
			}
			// Add the component to the vulnerability if it is not already attached
			if cdc.bom.Components == nil {
				cdc.bom.Components = &[]cyclonedx.Component{}
			}
			if sbomComponent := cdx.SearchComponentByRef(component.BOMRef, *cdc.bom.Components...); sbomComponent == nil {
				// The component is not in the BOM, add it
				*cdc.bom.Components = append(*cdc.bom.Components, component)
			}
			// Add the vulnerability to the BOM
			if cdc.bom.Vulnerabilities == nil {
				cdc.bom.Vulnerabilities = &[]cyclonedx.Vulnerability{}
			}
			if applicability != nil && applicability.Status != "" {
				// Add applicability status to the vulnerability
				vulnerability.Properties = cdx.AppendProperties(vulnerability.Properties, cyclonedx.Property{
					Name:  applicabilityStatusPropertyName,
					Value: applicability.Status,
				})
				for _, evidence := range applicability.Evidence {
					// Get or create the file component from the BOM
					fileComponent := cdx.GetComponentByIndex(cdc.bom, cdc.getOrCreateFileComponent(evidence.File))
					// Attach the fileComponent evidence affects to the vulnerability and add the evidence snippet
					addFileIssueAffects(&vulnerability, *fileComponent, cyclonedx.Property{
						Name:  fmt.Sprintf(applicabilityEvidencePropertyTemplate, fileComponent.BOMRef, evidence.StartLine, evidence.StartColumn, evidence.EndLine, evidence.EndColumn),
						Value: evidence.Snippet,
					})
				}
			}
			*cdc.bom.Vulnerabilities = append(*cdc.bom.Vulnerabilities, vulnerability)
			return
		},
	)
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseViolations(target results.ScanTarget, violations []services.Violation, applicableScan ...results.ScanResult[[]*sarif.Run]) error {
	// Not supported for CycloneDX.
	return nil
}

func (cdc *CmdResultsCycloneDxConverter) ParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	service := cdc.addXrayToolIfMissing()
	cdc.addJasService(applicableScan)
	err = results.ForEachScaVulnerabilities(target, scaResponse.Scan.Vulnerabilities, cdc.entitledForJas, results.ScanResultsToRuns(applicableScan),
		func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (e error) {
			// Create or get the affected component
			affectedComponent := cdx.GetComponentByIndex(cdc.bom, cdc.getOrCreateScaComponentFromXrayCompId(impactedPackagesId))
			extendedDescription := ""
			if vulnerability.ExtendedInformation != nil {
				extendedDescription = vulnerability.ExtendedInformation.FullDescription
			}
			cveIds, applicability, cwes, ratings := results.ExtractIssuesInfoForCdx(vulnerability.IssueId, cves, severity, applicabilityStatus, service)
			// Create vulnerability for each issueId
			for i := 0; i < len(cveIds); i++ {
				actualStatus := applicabilityStatus
				if applicability[i] != nil {
					actualStatus = jasutils.ConvertToApplicabilityStatus(applicability[i].Status)
				}
				// Create the SCA vulnerability
				cycloneVulnerability := cdc.getOrCreateScaIssue(vulnerability.IssueId, cveIds[i], vulnerability.Summary, extendedDescription, service, cwes[i], vulnerability.References, actualStatus, ratings[i]...)
				// Attach the affected impacted library component to the vulnerability
				cdx.AttachComponentAffects(cycloneVulnerability, *affectedComponent, func(affectedComponent cyclonedx.Component) cyclonedx.Affects {
					return cdx.CreateScaImpactedAffects(affectedComponent, fixedVersion)
				})
				if applicability[i] == nil {
					continue
				}
				for _, evidence := range applicability[i].Evidence {
					// Get or create the file component from the BOM
					fileComponent := cdx.GetComponentByIndex(cdc.bom, cdc.getOrCreateFileComponent(evidence.File))
					// Attach the fileComponent evidence affects to the vulnerability and add the evidence snippet
					addFileIssueAffects(cycloneVulnerability, *fileComponent, cyclonedx.Property{
						Name:  fmt.Sprintf(applicabilityEvidencePropertyTemplate, fileComponent.BOMRef, evidence.StartLine, evidence.StartColumn, evidence.EndLine, evidence.EndColumn),
						Value: evidence.Snippet,
					})
				}
			}
			return
		},
	)
	return
}

func getEvidenceLocation(target results.ScanTarget, location string) string {
	if target.Target == "" {
		// no target, return the location
		return location
	}
	// evidence location is relative to the target, build the full path
	root := target.Target
	isFile, err := fileutils.IsFileExists(root, false)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to check if %s is a file: %s", root, err))
		return location
	}
	if isFile {
		// Sca target can be the descriptor file at the target directory, so we need to get the parent directory
		root = filepath.Dir(root)
	}
	return filepath.Join(root, location)
}

func (cdc *CmdResultsCycloneDxConverter) addXrayToolIfMissing() (service *cyclonedx.Service) {
	if service = cdx.SearchForServiceByName(cdc.bom, utils.XrayToolName); service != nil || cdc.bom == nil {
		// The service is already in the BOM
		return
	}
	service = &cyclonedx.Service{
		Name:    utils.XrayToolName,
		Version: cdc.xrayVersion,
	}
	cdx.AddServiceToBomIfNotExists(cdc.bom, *service)
	return
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

func (cdc *CmdResultsCycloneDxConverter) ParseLicenses(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	cdc.addXrayToolIfMissing()
	return results.ForEachLicenses(target, scaResponse.Scan.Licenses,
		func(license services.License, impactedPackagesId string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (e error) {
			// Create or get the affected component
			affectedComponentIndex := cdc.getOrCreateScaComponentFromXrayCompId(impactedPackagesId)
			affectedComponent := cdx.GetComponentByIndex(cdc.bom, affectedComponentIndex)
			cdx.AttachLicenseToComponent(affectedComponent, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					ID:   license.Key,
					Name: license.Name,
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
		if cdx.GetComponentIndex(cdc.bom, component.BOMRef) >= 0 {
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
	return cdx.GetDependencyEntry(cdc.bom, ref)
}

func (cdc *CmdResultsCycloneDxConverter) ParseSecrets(target results.ScanTarget, violations bool, secrets []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	source := cdc.addJasService(secrets)
	return results.ForEachJasIssues(results.ScanResultsToRuns(secrets), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		startLine := sarifutils.GetLocationStartLine(location)
		startColumn := sarifutils.GetLocationStartColumn(location)
		endLine := sarifutils.GetLocationEndLine(location)
		endColumn := sarifutils.GetLocationEndColumn(location)
		// Create or get the affected component
		affectedComponentIndex := cdc.getOrCreateJasComponent(location)
		affectedComponent := cdx.GetComponentByIndex(cdc.bom, affectedComponentIndex)
		// Create a new JAS vulnerability, add it to the BOM and return it
		properties := []cyclonedx.Property{}
		applicabilityStatus := jasutils.NotScanned
		if secretValidation := results.GetSecretResultApplicability(result); secretValidation != nil {
			// Secret validation results exist
			applicabilityStatus = jasutils.ConvertToApplicabilityStatus(secretValidation.Status)
			properties = append(properties, cyclonedx.Property{
				Name:  fmt.Sprintf(secretValidationPropertyTemplate, affectedComponent.BOMRef, startLine, startColumn, endLine, endColumn),
				Value: secretValidation.Status,
			})
			if secretValidation.ScannerDescription != "" {
				properties = append(properties, cyclonedx.Property{
					Name:  fmt.Sprintf(secretValidationMetadataPropertyTemplate, affectedComponent.BOMRef, startLine, startColumn, endLine, endColumn),
					Value: secretValidation.ScannerDescription,
				})
			}
		}
		// TODO: make sure with secrets team what is the CWE for secrets (212?) they should output
		ratings := []cyclonedx.VulnerabilityRating{results.CreateSeverityRating(severity, applicabilityStatus, source)}
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleScannerId(rule), sarifutils.GetResultMsgText(result), sarifutils.GetRuleShortDescriptionText(rule), source, sarifutils.GetRuleCWE(rule), ratings)
		// Add the location to the vulnerability
		properties = append(properties, cyclonedx.Property{
			Name:  fmt.Sprintf(jasIssueLocationPropertyTemplate, "secret", affectedComponent.BOMRef, startLine, startColumn, endLine, endColumn),
			Value: sarifutils.GetLocationSnippetText(location),
		})
		addFileIssueAffects(jasIssue, *affectedComponent, properties...)
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) addJasService(runs []results.ScanResult[[]*sarif.Run]) (service *cyclonedx.Service) {
	for _, runInfo := range runs {
		for _, run := range runInfo.Scan {
			// Add tool if missing
			if run == nil || run.Tool.Driver == nil {
				continue
			}
			service = &cyclonedx.Service{
				Name:    run.Tool.Driver.Name,
				Version: *run.Tool.Driver.Version,
			}
			cdx.AddServiceToBomIfNotExists(cdc.bom, *service)
		}
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseIacs(target results.ScanTarget, violations bool, iac []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	source := cdc.addJasService(iac)
	return results.ForEachJasIssues(results.ScanResultsToRuns(iac), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		// Create or get the affected component
		affectedComponentIndex := cdc.getOrCreateJasComponent(location)
		// Create a new JAS vulnerability, add it to the BOM and return it
		ratings := []cyclonedx.VulnerabilityRating{results.CreateSeverityRating(severity, jasutils.Applicable, source)}
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleScannerId(rule), sarifutils.GetResultMsgText(result), sarifutils.GetRuleShortDescriptionText(rule), source, sarifutils.GetRuleCWE(rule), ratings)
		// Add the location to the vulnerability
		affectedComponent := cdx.GetComponentByIndex(cdc.bom, affectedComponentIndex)
		addFileIssueAffects(jasIssue, *affectedComponent, cyclonedx.Property{
			Name:  fmt.Sprintf(jasIssueLocationPropertyTemplate, "iac", affectedComponent.BOMRef, sarifutils.GetLocationStartLine(location), sarifutils.GetLocationStartColumn(location), sarifutils.GetLocationEndLine(location), sarifutils.GetLocationEndColumn(location)),
			Value: sarifutils.GetLocationSnippetText(location),
		})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) ParseSast(target results.ScanTarget, violations bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	source := cdc.addJasService(sast)
	return results.ForEachJasIssues(results.ScanResultsToRuns(sast), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		// Create or get the affected component
		affectedComponentIndex := cdc.getOrCreateJasComponent(location)
		// Create a new JAS vulnerability, add it to the BOM and return it
		ratings := []cyclonedx.VulnerabilityRating{results.CreateSeverityRating(severity, jasutils.Applicable, source)}
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleScannerId(rule), sarifutils.GetResultMsgText(result), sarifutils.GetRuleShortDescriptionText(rule), source, sarifutils.GetRuleCWE(rule), ratings)
		// Add the location to the vulnerability
		affectedComponent := cdx.GetComponentByIndex(cdc.bom, affectedComponentIndex)
		addFileIssueAffects(jasIssue, *affectedComponent, cyclonedx.Property{
			Name:  fmt.Sprintf(jasIssueLocationPropertyTemplate, "sast", affectedComponent.BOMRef, sarifutils.GetLocationStartLine(location), sarifutils.GetLocationStartColumn(location), sarifutils.GetLocationEndLine(location), sarifutils.GetLocationEndColumn(location)),
			Value: sarifutils.GetLocationSnippetText(location),
		})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateScaComponentFromXrayCompId(impactedPackageId string) (componentIndex int) {
	ref := results.XrayComponentIdToCdxComponentRef(impactedPackageId)
	// Check if the component already exists in the BOM
	if componentIndex = cdx.GetComponentIndex(cdc.bom, ref); componentIndex >= 0 {
		return
	}
	// Create a new component, add it to the BOM and return it
	if cdc.bom.Components == nil {
		cdc.bom.Components = &[]cyclonedx.Component{}
	}
	*cdc.bom.Components = append(*cdc.bom.Components, results.CreateScaComponentFromXrayCompId(impactedPackageId))
	return len(*cdc.bom.Components) - 1
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateJasComponent(location *sarif.Location) (componentIndex int) {
	return cdc.getOrCreateFileComponent(sarifutils.GetLocationFileName(location))
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateFileComponent(filePathOrUri string) (componentIndex int) {
	// Convert to relative path if the filePathOrUri is absolute
	filePathOrUri = strings.TrimPrefix(strings.TrimPrefix(filePathOrUri, "file:///"), strings.TrimPrefix(cdc.bom.Metadata.Component.Name, "/"))

	// Check if the component already exists in the BOM
	if componentIndex = cdx.GetComponentIndex(cdc.bom, cdx.GetFileRef(filePathOrUri)); componentIndex >= 0 {
		return
	}
	// Create a new component, add it to the BOM and return it
	if cdc.bom.Components == nil {
		cdc.bom.Components = &[]cyclonedx.Component{}
	}
	*cdc.bom.Components = append(*cdc.bom.Components, cdx.CreateFileOrDirComponent(filePathOrUri))
	return len(*cdc.bom.Components) - 1
}

func (cdc *CmdResultsCycloneDxConverter) getExistingVulnerability(ref string) *cyclonedx.Vulnerability {
	if cdc.bom.Vulnerabilities == nil {
		return nil
	}
	for _, vulnerability := range *cdc.bom.Vulnerabilities {
		if vulnerability.BOMRef == ref {
			return &vulnerability
		}
	}
	return nil
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateScaIssue(id, cveId, description, extendedDescription string, source *cyclonedx.Service, cwe, references []string, applicabilityStatus jasutils.ApplicabilityStatus, ratings ...cyclonedx.VulnerabilityRating) (scaVulnerability *cyclonedx.Vulnerability) {
	properties := []cyclonedx.Property{}
	if applicabilityStatus != jasutils.NotScanned {
		// Add applicability status to the vulnerability
		properties = append(properties, cyclonedx.Property{
			Name:  applicabilityStatusPropertyName,
			Value: applicabilityStatus.String(),
		})
	}
	params := cdx.CdxVulnerabilityParams{
		Ref:         cveId,
		ID:          id,
		Description: description,
		Details:     extendedDescription,
		Service:     source,
		CWE:         cwe,
		References:  references,
		Ratings:     ratings,
	}
	return cdx.GetOrCreateScaIssue(cdc.bom, params, properties...)
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateJasIssue(ref, id, msg, description string, source *cyclonedx.Service, cwe []string, ratings []cyclonedx.VulnerabilityRating, properties ...cyclonedx.Property) (scaVulnerability *cyclonedx.Vulnerability) {
	if scaVulnerability = cdc.getExistingVulnerability(ref); scaVulnerability != nil {
		return
	}
	// Create a new SCA vulnerability, add it to the BOM and return it
	if cdc.bom.Vulnerabilities == nil {
		cdc.bom.Vulnerabilities = &[]cyclonedx.Vulnerability{}
	}
	params := cdx.CdxVulnerabilityParams{
		Ref:         ref,
		ID:          id,
		Description: description,
		Details:     msg,
		Service:     source,
		CWE:         cwe,
		Ratings:     ratings,
	}
	*cdc.bom.Vulnerabilities = append(*cdc.bom.Vulnerabilities, cdx.CreateBaseVulnerability(params, properties...))
	return &(*cdc.bom.Vulnerabilities)[len(*cdc.bom.Vulnerabilities)-1]
}

func addFileIssueAffects(issue *cyclonedx.Vulnerability, fileComponent cyclonedx.Component, properties ...cyclonedx.Property) {
	cdx.AttachComponentAffects(issue, fileComponent, func(affectedComponent cyclonedx.Component) cyclonedx.Affects {
		return cyclonedx.Affects{Ref: affectedComponent.BOMRef}
	}, properties...)
}
