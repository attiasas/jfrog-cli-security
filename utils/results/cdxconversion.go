package results

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdx"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

const (
	binaryPathPropertyName = "jfrog:location:path"
)

func ScanResponseToSbom(destination *cyclonedx.BOM, scanResponse services.ScanResponse) (err error) {
	xrayService := &cyclonedx.Service{Name: utils.XrayToolName}
	for _, vulnerability := range scanResponse.Vulnerabilities {
		// Prepare the information needed to create the SCA vulnerability
		impactedPackagesIds, fixedVersions, _, _, err := SplitComponents("", vulnerability.Components)
		if err != nil {
			return err
		}
		severity, err := severityutils.ParseSeverity(vulnerability.Severity, false)
		if err != nil {
			return err
		}
		extendedDescription := ""
		if vulnerability.ExtendedInformation != nil {
			extendedDescription = vulnerability.ExtendedInformation.FullDescription
		}
		cves, _, cwes, ratings := ExtractIssuesInfoForCdx(vulnerability.IssueId, convertCves(vulnerability.Cves), severity, jasutils.NotScanned, xrayService)
		// Create vulnerability for each issueId
		for id := 0; id < len(cves); id++ {
			for compIndex := 0; compIndex < len(impactedPackagesIds); compIndex++ {
				// Create or get the affected component
				affectedComponent := getOrCreateScaComponent(destination, impactedPackagesIds[compIndex])
				// Create or Get the SCA vulnerability
				params := cdx.CdxVulnerabilityParams{
					Ref:         cves[id],
					Ratings:     ratings[id],
					CWE:         cwes[id],
					ID:          vulnerability.IssueId,
					Description: vulnerability.Summary,
					Details:     extendedDescription,
					References:  vulnerability.References,
					Service:     xrayService,
				}
				cycloneVulnerability := cdx.GetOrCreateScaIssue(destination, params)
				// Attach the affected impacted library component to the vulnerability
				cdx.AttachComponentAffects(cycloneVulnerability, *affectedComponent, func(affectedComponent cyclonedx.Component) cyclonedx.Affects {
					return cdx.CreateScaImpactedAffects(affectedComponent, fixedVersions[id])
				})

			}
		}
	}
	for _, license := range scanResponse.Licenses {
		// Prepare the information needed to create the SCA license
		impactedPackagesIds, _, _, _, err := SplitComponents("", license.Components)
		if err != nil {
			return err
		}
		for compIndex := 0; compIndex < len(impactedPackagesIds); compIndex++ {
			// Attach the license to the component
			component := getOrCreateScaComponent(destination, impactedPackagesIds[compIndex])
			cdx.AttachLicenseToComponent(component, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					ID:   license.Key,
					Name: license.Name,
				},
			})
		}
	}
	return
}

func DepsTreeToSbom(trees ...*xrayUtils.GraphNode) (components *[]cyclonedx.Component, dependencies *[]cyclonedx.Dependency) {
	parsed := datastructures.MakeSet[string]()
	components = &[]cyclonedx.Component{}
	dependencies = &[]cyclonedx.Dependency{}
	for _, root := range trees {
		if root.Id != "root" {
			components, dependencies = getDataFromNode(root, parsed, components, dependencies)
			continue
		}
		for _, module := range root.Nodes {
			components, dependencies = getDataFromNode(module, parsed, components, dependencies)
		}
	}
	return
}

func getDataFromNode(node *xrayUtils.GraphNode, parsed *datastructures.Set[string], components *[]cyclonedx.Component, dependencies *[]cyclonedx.Dependency) (*[]cyclonedx.Component, *[]cyclonedx.Dependency) {
	if parsed.Exists(node.Id) {
		// The node was already parsed, no need to parse it again
		return components, dependencies
	}
	parsed.Add(node.Id)
	// Create a new component and add it to the sbom
	*components = append(*components, CreateScaComponentFromXrayCompId(node.Id))
	if len(node.Nodes) > 0 {
		// Create a matching dependency entry describing the direct dependencies
		*dependencies = append(*dependencies, cyclonedx.Dependency{Ref: XrayComponentIdToCdxComponentRef(node.Id), Dependencies: getNodeDirectDependencies(node)})
	}
	// Go through the dependencies and add them to the sbom
	for _, dependencyNode := range node.Nodes {
		components, dependencies = getDataFromNode(dependencyNode, parsed, components, dependencies)
	}
	return components, dependencies
}

func getNodeDirectDependencies(node *xrayUtils.GraphNode) (dependencies *[]string) {
	dependencies = &[]string{}
	for _, dep := range node.Nodes {
		*dependencies = append(*dependencies, XrayComponentIdToPurl(dep.Id))
	}
	return
}

func CompTreeToSbom(trees ...*xrayUtils.BinaryGraphNode) (components *[]cyclonedx.Component, dependencies *[]cyclonedx.Dependency) {
	parsed := datastructures.MakeSet[string]()
	components = &[]cyclonedx.Component{}
	dependencies = &[]cyclonedx.Dependency{}
	for _, root := range trees {
		if root.Id != "root" {
			components, dependencies = getDataFromBinaryNode(root, parsed, components, dependencies)
			continue
		}
		for _, module := range root.Nodes {
			components, dependencies = getDataFromBinaryNode(module, parsed, components, dependencies)
		}
	}
	return
}

func getDataFromBinaryNode(node *xrayUtils.BinaryGraphNode, parsed *datastructures.Set[string], components *[]cyclonedx.Component, dependencies *[]cyclonedx.Dependency) (*[]cyclonedx.Component, *[]cyclonedx.Dependency) {
	if parsed.Exists(node.Id) {
		// The node was already parsed, no need to parse it again
		return components, dependencies
	}
	parsed.Add(node.Id)
	// Create a new component and add it to the sbom
	component := CreateScaComponentFromNode(node)
	*components = append(*components, component)
	if len(node.Nodes) > 0 {
		// Create a matching dependency entry describing the direct dependencies
		*dependencies = append(*dependencies, cyclonedx.Dependency{Ref: component.BOMRef, Dependencies: getNodeDirectBinaryComponents(node)})
	}
	// Go through the dependencies and add them to the sbom
	for _, dependencyNode := range node.Nodes {
		components, dependencies = getDataFromBinaryNode(dependencyNode, parsed, components, dependencies)
	}
	return components, dependencies
}

func getNodeDirectBinaryComponents(node *xrayUtils.BinaryGraphNode) (dependencies *[]string) {
	dependencies = &[]string{}
	for _, dep := range node.Nodes {
		*dependencies = append(*dependencies, XrayComponentIdToPurl(dep.Id))
	}
	return
}

func BomToTree(sbom *cyclonedx.BOM) (flatTree *xrayUtils.GraphNode, fullDependencyTrees []*xrayUtils.GraphNode) {
	return BomToFlatTree(sbom), BomToFullTree(sbom)
}

func BomToFullTree(sbom *cyclonedx.BOM) (fullDependencyTrees []*xrayUtils.GraphNode) {
	for _, rootEntry := range cdx.ReduceToRoots(sbom) {
		currentTree := &xrayUtils.GraphNode{Id: PurlToXrayComponentId(cdx.SearchComponentByRef(rootEntry.Ref, *sbom.Components...).PackageURL)}
		// Populate application tree
		populateDepsNodeDataFromBom(currentTree, sbom)
		// Add the tree to the output list
		fullDependencyTrees = append(fullDependencyTrees, currentTree)
	}
	return
}

func populateDepsNodeDataFromBom(node *xrayUtils.GraphNode, sbom *cyclonedx.BOM) {
	if node == nil || node.NodeHasLoop() {
		// If the node is nil or has a loop, return
		return
	}
	for _, dep := range cdx.GetDirectDependencies(sbom, XrayComponentIdToPurl(node.Id)) {
		depNode := &xrayUtils.GraphNode{Id: PurlToXrayComponentId(dep), Parent: node}
		// log.Debug(fmt.Sprintf("Adding dependency node: %s to parent node: %s", depNode.Id, node.Id))
		// Add the dependency to the current node
		node.Nodes = append(node.Nodes, depNode)
		// Recursively populate the node data
		populateDepsNodeDataFromBom(depNode, sbom)
	}
}

func BomToFullCompTree(sbom *cyclonedx.BOM) (fullDependencyTree *xrayUtils.BinaryGraphNode) {
	fullDependencyTrees := []*xrayUtils.BinaryGraphNode{}
	for _, rootEntry := range cdx.ReduceToRoots(sbom) {
		currentTree := toBinaryNode(sbom, rootEntry.Ref)
		// Populate application tree
		populateCompsNodeDataFromBom(currentTree, sbom)
		// Add the tree to the output list
		fullDependencyTrees = append(fullDependencyTrees, currentTree)
	}
	if len(fullDependencyTrees) == 1 {
		// Only one tree found, return it
		fullDependencyTree = fullDependencyTrees[0]
	} else if len(fullDependencyTrees) > 1 {
		// More than one tree found, create root node and add all trees to it
		id := "root"
		if sbom != nil && sbom.Metadata != nil && sbom.Metadata.Component != nil {
			id = sbom.Metadata.Component.Name
		}
		fullDependencyTree = &xrayUtils.BinaryGraphNode{Id: id, Nodes: fullDependencyTrees}
	}
	return
}

func populateCompsNodeDataFromBom(node *xrayUtils.BinaryGraphNode, sbom *cyclonedx.BOM) {
	for _, depRef := range cdx.GetDirectDependencies(sbom, XrayComponentIdToPurl(node.Id)) {
		depNode := toBinaryNode(sbom, depRef)
		// Add the dependency to the current node
		node.Nodes = append(node.Nodes, depNode)
		// Recursively populate the node data
		populateCompsNodeDataFromBom(depNode, sbom)
	}
}

func toBinaryNode(sbom *cyclonedx.BOM, ref string) *xrayUtils.BinaryGraphNode {
	component := cdx.GetComponent(sbom, ref)
	if component == nil {
		return nil
	}
	if component.Type != cyclonedx.ComponentTypeLibrary {
		// We are only interested in libraries for the dependency tree
		return nil
	}
	// Create a new BinaryGraphNode and set its ID
	node := &xrayUtils.BinaryGraphNode{Id: PurlToXrayComponentId(component.PackageURL)}
	if component.Licenses != nil {
		// Add the licenses to the node
		for _, license := range *component.Licenses {
			if license.License != nil && license.License.ID != "" {
				node.Licenses = append(node.Licenses, license.License.ID)
			}
		}
	}
	if component.Hashes != nil {
		// Add the hashes to the node
		for _, hash := range *component.Hashes {
			switch hash.Algorithm {
			case cyclonedx.HashAlgoSHA1:
				node.Sha1 = hash.Value
			case cyclonedx.HashAlgoSHA256:
				node.Sha256 = hash.Value
			}
		}
	}
	if component.Properties != nil {
		// Add the properties to the node
		for _, property := range *component.Properties {
			if property.Name == binaryPathPropertyName {
				node.Path = property.Value
			}
		}
	}
	return node
}

func BomToFlatTree(sbom *cyclonedx.BOM) (flatTree *xrayUtils.GraphNode) {
	flatTree = &xrayUtils.GraphNode{Id: "root"}
	for _, component := range getUniqueXrayCompIds(sbom) {
		flatTree.Nodes = append(flatTree.Nodes, &xrayUtils.GraphNode{Id: component})
	}
	return
}

func BomToFlatCompIds(sbom *cyclonedx.BOM) (flatDepList *[]string) {
	flatDepList = &[]string{}
	// Append all unique Xray component IDs to the flatDepList in one step
	*flatDepList = append(*flatDepList, getUniqueXrayCompIds(sbom)...)
	return
}

func getUniqueXrayCompIds(sbom *cyclonedx.BOM) (uniqueCompIds []string) {
	if sbom == nil || sbom.Components == nil {
		return
	}
	components := datastructures.MakeSet[string]()
	// Collect all unique components
	for _, component := range *sbom.Components {
		if component.Type != cyclonedx.ComponentTypeLibrary {
			// We are only interested in libraries for the dependency tree
			continue
		}
		components.Add(PurlToXrayComponentId(component.PackageURL))
	}
	return components.ToSlice()
}

func CreateScaComponentFromNode(node *xrayUtils.BinaryGraphNode) (component cyclonedx.Component) {
	properties := []cyclonedx.Property{}
	// Add the path property if it exists
	if node.Path != "" {
		properties = append(properties, cyclonedx.Property{Name: binaryPathPropertyName, Value: node.Path})
	}
	// Create the component
	component = CreateScaComponentFromXrayCompId(node.Id, properties...)
	licenses := cyclonedx.Licenses{}
	for _, license := range node.Licenses {
		if license == "" {
			continue
		}
		licenses = append(licenses, cyclonedx.LicenseChoice{License: &cyclonedx.License{ID: license}})
	}
	if len(licenses) > 0 {
		component.Licenses = &licenses
	}
	if node.Sha1 == "" && node.Sha256 == "" {
		return
	}
	// Add hashes to the component if they exist
	hashes := []cyclonedx.Hash{}
	if node.Sha1 != "" {
		hashes = append(hashes, cyclonedx.Hash{Algorithm: cyclonedx.HashAlgoSHA1, Value: node.Sha1})
	}
	if node.Sha256 != "" {
		hashes = append(hashes, cyclonedx.Hash{Algorithm: cyclonedx.HashAlgoSHA256, Value: node.Sha256})
	}
	if len(hashes) > 0 {
		component.Hashes = &hashes
	}
	return
}

func CreateScaComponentFromXrayCompId(xrayImpactedPackageId string, properties ...cyclonedx.Property) (component cyclonedx.Component) {
	compName, compVersion, compType := techutils.SplitComponentIdRaw(xrayImpactedPackageId)
	component = cyclonedx.Component{
		BOMRef:     XrayComponentIdToCdxComponentRef(xrayImpactedPackageId),
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       compName,
		Version:    compVersion,
		PackageURL: cdx.ToPackageUrl(compName, compVersion, techutils.ToCdxPackageType(compType)),
	}
	component.Properties = cdx.AppendProperties(component.Properties, properties...)
	return
}

func getOrCreateScaComponent(destination *cyclonedx.BOM, impactedPackageId string) (libComponent *cyclonedx.Component) {
	ref := XrayComponentIdToCdxComponentRef(impactedPackageId)
	// Check if the component already exists in the BOM
	if componentIndex := cdx.GetComponentIndex(destination, ref); componentIndex >= 0 {
		return &(*destination.Components)[componentIndex]
	}
	// Create a new component, add it to the BOM and return it
	if destination.Components == nil {
		destination.Components = &[]cyclonedx.Component{}
	}
	component := CreateScaComponentFromXrayCompId(impactedPackageId)
	*destination.Components = append(*destination.Components, component)
	return &(*destination.Components)[len(*destination.Components)-1]
}

// Extract the component name, version and type from PackageUrl and translate it to an Xray component id
func PurlToXrayComponentId(purl string) (xrayComponentId string) {
	compName, compVersion, compType := cdx.SplitPackageURL(purl)
	return techutils.ToXrayComponentId(compName, compVersion, techutils.CdxPackageTypeToXrayPackageType(compType))
}

func XrayComponentIdToPurl(xrayComponentId string) (purl string) {
	compName, compVersion, compType := techutils.SplitComponentIdRaw(xrayComponentId)
	return cdx.ToPackageUrl(compName, compVersion, techutils.ToCdxPackageType(compType))
}

func XrayComponentIdToCdxComponentRef(xrayImpactedPackageId string) string {
	compName, compVersion, compType := techutils.SplitComponentIdRaw(xrayImpactedPackageId)
	return cdx.ToPackageRef(compName, compVersion, techutils.ToCdxPackageType(compType))
}

func BomToDirectCompIds(sbom *cyclonedx.BOM) (directDepList *[]string) {
	directDepList = &[]string{}
	if sbom == nil || sbom.Components == nil {
		log.Debug("No components found in the SBOM, returning empty direct dependencies list.")
		return directDepList
	}
	for _, root := range cdx.ReduceToRoots(sbom) {
		if root.Dependencies == nil {
			continue
		}
		for _, directDependencyRef := range *root.Dependencies {
			dependencyComponent := cdx.SearchComponentByRef(directDependencyRef, *sbom.Components...)
			if dependencyComponent == nil {
				log.Debug(fmt.Sprintf("Failed to find component for direct dependency: %s", directDependencyRef))
				continue
			}
			*directDepList = append(*directDepList, PurlToXrayComponentId(dependencyComponent.PackageURL))
		}
	}
	return
}

func CreateSeverityRating(severity severityutils.Severity, applicabilityStatus jasutils.ApplicabilityStatus, service *cyclonedx.Service) cyclonedx.VulnerabilityRating {
	return cyclonedx.VulnerabilityRating{
		Source: &cyclonedx.Source{
			Name: service.Name,
		},
		Severity: severityutils.SeverityToCycloneDxSeverity(severity),
		Score:    severityutils.GetSeverityScoreFloat64(severity, applicabilityStatus),
		Method:   cyclonedx.ScoringMethodOther,
	}
}

func CreateCveRatings(cve formats.CveRow) (ratings []cyclonedx.VulnerabilityRating) {
	if cve.CvssV2 != "" {
		ratings = append(ratings, cyclonedx.VulnerabilityRating{
			Source: &cyclonedx.Source{
				Name: utils.XrayToolName,
			},
			Score:  severityutils.GetCvssScore(cve.CvssV2),
			Vector: cve.CvssV2Vector,
			Method: cyclonedx.ScoringMethodCVSSv2,
		})
	}
	if cve.CvssV3 != "" {
		ratings = append(ratings, cyclonedx.VulnerabilityRating{
			Source: &cyclonedx.Source{
				Name: utils.XrayToolName,
			},
			Score:  severityutils.GetCvssScore(cve.CvssV3),
			Vector: cve.CvssV3Vector,
			Method: cyclonedx.ScoringMethodCVSSv3,
		})
	}
	return
}
