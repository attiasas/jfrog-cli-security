package cdx

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-security/utils"
)

// Regular expression to match CWE IDs, which can be in the format "CWE-1234" or just "1234".
var cweSupportedPattern = regexp.MustCompile(`(?:CWE-)?(\d+)`)

// Parse a given Package URL (purl) and return the component name, version, and package type.
// Examples:
//  1. purl: "pkg:golang/github.com/gophish/gophish@v0.1.2"
//     Returned values:
//     Component name: "github.com/gophish/gophish"
//     Component version: "v0.1.2"
//     Package type: "golang"
//     Qualifiers: map[string]string{}
//  2. purl: "pkg:golang/github.com/go-gitea/gitea"
//     Returned values:
//     Component name: "github.com/go-gitea/gitea"
//     Component version: ""
//     Package type: "golang"
//     Qualifiers: map[string]string{}
//  3. purl: "pkg:gav/xpp3:xpp3_min@1.1.4c"
//     Returned values:
//     Component name: "xpp3:xpp3_min"
//     Component version: "1.1.4c"
//     Package type: "gav"
//     Qualifiers: map[string]string{}
//  4. purl: "pkg:maven/org.apache.commons/commons-lang3@3.12.0?package-id=d3f8d67af404667f"
//     Returned values:
//     Component name: "org.apache.commons/commons-lang3"
//     Component version: "3.12.0"
//     Package type: "maven"
//     Qualifiers: map[string]string{"package-id": "d3f8d67af404667f"}
func SplitPackageUrlWithQualifiers(purl string) (compName, compVersion, packageType string, qualifiers map[string]string) {
	parsed, err := packageurl.FromString(purl)
	if err != nil {
		log.Debug(fmt.Sprintf("Failed to parse package URL '%s': %s", purl, err))
		return purl, "", "", nil
	}
	compName = parsed.Name
	if parsed.Namespace != "" {
		compName = parsed.Namespace + "/" + compName
	}
	compVersion = parsed.Version
	packageType = parsed.Type
	if err := parsed.Qualifiers.Normalize(); err != nil {
		log.Debug(fmt.Sprintf("Failed to normalize '%s' qualifiers: %s", purl, err))
		return
	}
	qualifiers = parsed.Qualifiers.Map()
	return
}

func SplitPackageURL(purl string) (compName, compVersion, packageType string) {
	compName, compVersion, packageType, _ = SplitPackageUrlWithQualifiers(purl)
	return
}

func ToPackageUrl(compName, version, packageType string, properties ...cyclonedx.Property) (output string) {
	// Convert properties if provided
	var qualifiers packageurl.Qualifiers
	if len(properties) > 0 {
		qualifiers = packageurl.QualifiersFromMap(propertiesToMap(properties...))
	}
	purl := packageurl.NewPackageURL(packageType, "", compName, version, qualifiers, "").String()
	// Unescape the output
	output, err := url.QueryUnescape(purl)
	if err != nil {
		log.Debug(fmt.Sprintf("Failed to unescape package URL: %s", err))
		// Return the original output
		return purl
	}
	return
}

func ToPackageRef(compName, version, packageType string) (output string) {
	return fmt.Sprintf("%s:%s@%s", packageType, compName, version)
}

func AppendProperties(properties *[]cyclonedx.Property, newProperties ...cyclonedx.Property) *[]cyclonedx.Property {
	for _, property := range newProperties {
		// Check if the property already exists
		if existingProperty := SearchProperty(properties, property.Name); existingProperty != nil {
			// The property already exists
			continue
		}
		if properties == nil {
			properties = &[]cyclonedx.Property{}
		}
		// The property does not exist, append it to the list
		*properties = append(*properties, property)
	}
	return properties
}

func propertiesToMap(properties ...cyclonedx.Property) (propertiesMap map[string]string) {
	propertiesMap = make(map[string]string)
	for _, property := range properties {
		if property.Name != "" && property.Value != "" {
			propertiesMap[property.Name] = property.Value
		}
	}
	return
}

func CreateFileOrDirComponent(filePathOrUri string) (component cyclonedx.Component) {
	component = cyclonedx.Component{
		BOMRef: GetFileRef(filePathOrUri),
		Type:   cyclonedx.ComponentTypeFile,
		Name:   convertToFileUrlIfNeeded(filePathOrUri),
	}
	return
}

func convertToFileUrlIfNeeded(location string) string {
	return filepath.ToSlash(location)
}

func GetIdRef(id string) string {
	return fmt.Sprintf("urn:uuid:%s", id)
}

func GetFileRef(filePathOrUri string) string {
	uri := convertToFileUrlIfNeeded(filePathOrUri)
	wdRef, err := utils.Md5Hash(uri)
	if err != nil {
		return uri
	}
	return wdRef
}

func IsMultiProject(sbom *cyclonedx.BOM) bool {
	return len(ReduceToRoots(sbom)) > 1
}

func SearchParent(componentRef string, components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) *cyclonedx.Component {
	if len(dependencies) == 0 || len(components) == 0 {
		return nil
	}
	for _, dependency := range dependencies {
		if dependency.Dependencies == nil || len(*dependency.Dependencies) == 0 {
			// No dependencies, continue to the next dependency
			continue
		}
		// Check if the component is a direct dependency
		for _, dep := range *dependency.Dependencies {
			if dep == componentRef {
				parentComponent := SearchComponentByRef(dependency.Ref, components...)
				if parentComponent == nil {
					log.Debug(fmt.Sprintf("Failed to find parent component for dependency '%s' in components", dependency.Ref))
					continue
				}
				// The component is a direct dependency, return it
				return parentComponent
			}
		}
	}
	return nil
}

func SearchDependencyEntry(dependencies *[]cyclonedx.Dependency, ref string) *cyclonedx.Dependency {
	if dependencies == nil || len(*dependencies) == 0 {
		return nil
	}
	for _, dependency := range *dependencies {
		if dependency.Ref == ref {
			return &dependency
		}
	}
	return nil
}

func SearchProperty(properties *[]cyclonedx.Property, name string) *cyclonedx.Property {
	if properties == nil || len(*properties) == 0 {
		return nil
	}
	for _, property := range *properties {
		if property.Name == name {
			return &property
		}
	}
	return nil
}

func GetMainComponentName(sbom *cyclonedx.BOM) (mainComponentName string) {
	mainComponentName = "unknown"
	if sbom == nil || sbom.Metadata == nil || sbom.Metadata.Component == nil {
		return
	}
	if sbom.Metadata.Component.Name != "" {
		mainComponentName = sbom.Metadata.Component.Name
	}
	return
}

// Conversion functions

func AttachLicenseToComponent(component *cyclonedx.Component, license cyclonedx.LicenseChoice) {
	if component.Licenses == nil {
		component.Licenses = &cyclonedx.Licenses{}
	}
	// Check if the license already exists in the component
	if hasLicense(*component, license.License.ID) {
		// The license already exists, no need to add it again
		return
	}
	// Create a new license and add it to the component
	*component.Licenses = append(*component.Licenses, license)
}

func hasLicense(component cyclonedx.Component, licenseName string) bool {
	if component.Licenses == nil || len(*component.Licenses) == 0 {
		return false
	}
	for _, license := range *component.Licenses {
		if license.License != nil && license.License.ID == licenseName {
			return true
		}
	}
	return false
}

func CreateScaImpactedAffects(impactedPackageComponent cyclonedx.Component, fixedVersions []string) (affect cyclonedx.Affects) {
	_, impactedPackageVersion, _ := SplitPackageURL(impactedPackageComponent.PackageURL)
	affect = cyclonedx.Affects{
		Ref:   impactedPackageComponent.BOMRef,
		Range: &[]cyclonedx.AffectedVersions{},
	}
	// Affected version
	*affect.Range = append(*affect.Range, cyclonedx.AffectedVersions{
		Version: impactedPackageVersion,
		Status:  cyclonedx.VulnerabilityStatusAffected,
	})
	// Fixed versions
	for _, fixedVersion := range fixedVersions {
		*affect.Range = append(*affect.Range, cyclonedx.AffectedVersions{
			Version: fixedVersion,
			Status:  cyclonedx.VulnerabilityStatusNotAffected,
		})
	}
	return
}

func AttachComponentAffects(issue *cyclonedx.Vulnerability, affectedComponent cyclonedx.Component, affectsGenerator func(affectedComponent cyclonedx.Component) cyclonedx.Affects, relatedProperties ...cyclonedx.Property) {
	if !HasImpactedAffects(*issue, affectedComponent) {
		// The affected component is not in the vulnerability, Add the affected component to the vulnerability
		if issue.Affects == nil {
			issue.Affects = &[]cyclonedx.Affects{}
		}
		*issue.Affects = append(*issue.Affects, affectsGenerator(affectedComponent))
	}
	if len(relatedProperties) == 0 {
		// No properties to add
		return
	}
	// Add the properties to the vulnerability
	issue.Properties = AppendProperties(issue.Properties, relatedProperties...)
}

func HasImpactedAffects(vulnerability cyclonedx.Vulnerability, affectedComponent cyclonedx.Component) bool {
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

// Returns the index of the vulnerability in the BOM
func GetOrCreateScaIssue(destination *cyclonedx.BOM, params CdxVulnerabilityParams, properties ...cyclonedx.Property) (scaVulnerability *cyclonedx.Vulnerability) {
	if scaVulnerability = SearchExistingVulnerabilityById(destination, params.ID); scaVulnerability != nil {
		// The vulnerability already exists, update the ratings with the applicable status and attach properties if needed
		UpdateOrAppendVulnerabilitiesRatings(scaVulnerability, params.Ratings...)
		scaVulnerability.Properties = AppendProperties(scaVulnerability.Properties, properties...)
		return scaVulnerability
	}
	// Create a new SCA vulnerability, add it to the BOM
	if destination.Vulnerabilities == nil {
		destination.Vulnerabilities = &[]cyclonedx.Vulnerability{}
	}
	vulnerability := CreateBaseVulnerability(params, properties...)
	*destination.Vulnerabilities = append(*destination.Vulnerabilities, vulnerability)
	return &(*destination.Vulnerabilities)[len(*destination.Vulnerabilities)-1]
}

type CdxVulnerabilityParams struct {
	Ref         string
	ID          string
	Details     string
	Description string
	Service     *cyclonedx.Service
	CWE         []string
	References  []string
	Ratings     []cyclonedx.VulnerabilityRating
}

func CreateBaseVulnerability(params CdxVulnerabilityParams, properties ...cyclonedx.Property) cyclonedx.Vulnerability {
	var source *cyclonedx.Source
	if params.Service != nil {
		source = &cyclonedx.Source{
			Name: params.Service.Name,
		}
	}
	var ratings *[]cyclonedx.VulnerabilityRating
	if params.Ratings != nil && len(params.Ratings) > 0 {
		ratings = &params.Ratings
	}
	vuln := cyclonedx.Vulnerability{
		BOMRef:      params.Ref,
		ID:          params.ID,
		Source:      source,
		CWEs:        convertCweToCycloneDx(params.CWE),
		Description: params.Description,
		Detail:      params.Details,
		Ratings:     ratings,
		References:  getReferences(params.References),
	}
	vuln.Properties = AppendProperties(vuln.Properties, properties...)
	return vuln
}

func getReferences(references []string) *[]cyclonedx.VulnerabilityReference {
	if references == nil || len(references) == 0 {
		return nil
	}
	refs := []cyclonedx.VulnerabilityReference{}
	for _, ref := range references {
		if ref == "" {
			continue // Skip empty references
		}
		refs = append(refs, cyclonedx.VulnerabilityReference{
			Source: &cyclonedx.Source{
				URL: ref,
			},
		})
	}
	if len(refs) == 0 {
		return nil // Return nil if no valid references were found
	}
	return &refs
}

func UpdateOrAppendVulnerabilitiesRatings(vulnerability *cyclonedx.Vulnerability, ratings ...cyclonedx.VulnerabilityRating) {
	if vulnerability == nil {
		return
	}
	// Check if the ratings already exist in the vulnerability
	for _, rating := range ratings {
		if existingRating := SearchRating(vulnerability.Ratings, rating.Method, rating.Source); existingRating != nil {
			// The rating already exists, update it
			if rating.Source != nil {
				existingRating.Source = rating.Source
			}
			if rating.Score != nil {
				existingRating.Score = rating.Score
			}
			if rating.Vector != "" {
				existingRating.Vector = rating.Vector
			}
			existingRating.Severity = rating.Severity
			continue
		}
		if vulnerability.Ratings == nil {
			vulnerability.Ratings = &[]cyclonedx.VulnerabilityRating{}
		}
		// The rating does not exist, append it to the vulnerability
		*vulnerability.Ratings = append(*vulnerability.Ratings, rating)
	}
}

func SearchRating(ratings *[]cyclonedx.VulnerabilityRating, method cyclonedx.ScoringMethod, sources ...*cyclonedx.Source) *cyclonedx.VulnerabilityRating {
	if ratings == nil || len(*ratings) == 0 {
		return nil
	}
	for _, rating := range *ratings {
		if rating.Method != method {
			continue // Skip if the method does not match
		}
		// If no sources are provided, return the first matching rating with the method
		if len(sources) == 0 {
			return &rating
		}
		for _, source := range sources {
			// If the rating's source matches the provided source, return the rating
			if rating.Source != nil && source.Name == rating.Source.Name {
				// If the rating's source matches the provided source, return the rating
				return &rating
			}
		}
	}
	return nil
}

func convertCweToCycloneDx(cwe []string) (cweList *[]int) {
	if cwe == nil || len(cwe) == 0 {
		return nil
	}
	cweList = &[]int{}
	for _, cweId := range cwe {
		if cweInt, isSupportedCwe := extractCWENumber(cweId); !isSupportedCwe {
			log.Warn("Failed to parse CWE ID: ", cweId)
			continue
		} else {
			*cweList = append(*cweList, cweInt)
		}
	}
	return
}

func extractCWENumber(cweId string) (cweInt int, isSupportedCwe bool) {
	matches := cweSupportedPattern.FindStringSubmatch(cweId)
	if len(matches) < 2 {
		// No CWE id found
		return 0, false
	}
	cweID, err := strconv.Atoi(matches[1])
	return cweID, err == nil // Return the CWE ID and whether it was successfully parsed
}

func SearchExistingVulnerabilityById(destination *cyclonedx.BOM, id string) *cyclonedx.Vulnerability {
	if destination == nil || destination.Vulnerabilities == nil {
		return nil
	}
	for _, vulnerability := range *destination.Vulnerabilities {
		if vulnerability.BOMRef == id {
			return &vulnerability
		}
	}
	return nil
}

func SearchForServiceByName(bom *cyclonedx.BOM, serviceName string) *cyclonedx.Service {
	if bom == nil || bom.Metadata == nil || bom.Metadata.Tools == nil || bom.Metadata.Tools.Services == nil {
		return nil
	}
	for _, service := range *bom.Metadata.Tools.Services {
		if service.Name == serviceName {
			return &service
		}
	}
	return nil
}

func AddServiceToBomIfNotExists(bom *cyclonedx.BOM, service cyclonedx.Service) {
	if SearchForServiceByName(bom, service.Name) != nil || bom == nil {
		return // Service already exists
	}
	// Add the service to the BOM
	if bom.Metadata == nil {
		bom.Metadata = &cyclonedx.Metadata{}
	}
	if bom.Metadata.Tools == nil {
		bom.Metadata.Tools = &cyclonedx.ToolsChoice{}
	}
	if bom.Metadata.Tools.Services == nil {
		bom.Metadata.Tools.Services = &[]cyclonedx.Service{}
	}
	*bom.Metadata.Tools.Services = append(*bom.Metadata.Tools.Services, service)
}

func ReduceToRoots(sbom *cyclonedx.BOM) (roots []cyclonedx.Dependency) {
	dependencies := sbom.Dependencies
	roots = []cyclonedx.Dependency{}
	if sbom.Dependencies == nil || len(*dependencies) == 0 {
		// If no dependencies are found, return an empty list
		return
	}
	// Set to track all references that are listed in `dependsOn`
	deps := datastructures.MakeSet[string]()
	dependedRefs := datastructures.MakeSet[string]()
	// Populate the maps
	for _, dep := range *dependencies {
		deps.Add(dep.Ref)
		if dep.Dependencies == nil {
			// No dependencies, continue
			continue
		}
		for _, dependsOn := range *dep.Dependencies {
			dependedRefs.Add(dependsOn)
		}
	}
	ids := GetLibraryComponentRefs(sbom)
	if len(ids) == 0 {
		// If no library components are found, use the dependencies as IDs
		ids = deps.ToSlice()
	}
	// Identify root dependencies (those not listed in any `dependsOn`)
	for _, id := range ids {
		if dep := GetDependencyEntry(sbom, id); dep != nil && !dependedRefs.Exists(dep.Ref) {
			// This is a root dependency, add it
			roots = append(roots, *dep)
		}
	}
	return
}

func GetLibraryComponentRefs(sbom *cyclonedx.BOM) (libraryComponentIds []string) {
	libraryComponentIds = []string{}
	if sbom == nil || sbom.Components == nil || len(*sbom.Components) == 0 {
		return
	}
	for _, component := range *sbom.Components {
		if component.Type == cyclonedx.ComponentTypeLibrary {
			libraryComponentIds = append(libraryComponentIds, component.BOMRef)
		}
	}
	return
}

func GetComponentIndex(sbom *cyclonedx.BOM, ref string) int {
	if sbom == nil || sbom.Components == nil || len(*sbom.Components) == 0 {
		return -1
	}
	for i, component := range *sbom.Components {
		if component.BOMRef == ref {
			return i
		}
	}
	return -1
}

func SearchComponentByRef(ref string, components ...cyclonedx.Component) (component *cyclonedx.Component) {
	for _, comp := range components {
		if comp.BOMRef == ref {
			return &comp
		}
	}
	// If no component is found with the given ref, return nil
	return nil
}

func GetComponent(sbom *cyclonedx.BOM, ref string) *cyclonedx.Component {
	if sbom == nil || sbom.Components == nil || len(*sbom.Components) == 0 {
		return nil
	}
	index := GetComponentIndex(sbom, ref)
	if index == -1 {
		return nil
	}
	return &(*sbom.Components)[index]
}

func GetComponentByIndex(sbom *cyclonedx.BOM, index int) *cyclonedx.Component {
	if sbom == nil || sbom.Components == nil || len(*sbom.Components) == 0 || index < 0 || index >= len(*sbom.Components) {
		// Invalid index, return nil
		return nil
	}
	return &(*sbom.Components)[index]
}

func GetDependencyEntry(sbom *cyclonedx.BOM, ref string) *cyclonedx.Dependency {
	if sbom == nil || sbom.Dependencies == nil || len(*sbom.Dependencies) == 0 {
		return nil
	}
	for _, dependency := range *sbom.Dependencies {
		if dependency.Ref == ref {
			return &dependency
		}
	}
	return nil
}

func GetDirectDependencies(sbom *cyclonedx.BOM, componentRef string) (dependencies []string) {
	if sbom == nil || sbom.Dependencies == nil {
		return
	}
	// Collect all the 'Direct' dependencies from the BOM
	for _, dependency := range *sbom.Dependencies {
		if dependency.Ref == componentRef {
			return *dependency.Dependencies
		}
	}
	return
}
