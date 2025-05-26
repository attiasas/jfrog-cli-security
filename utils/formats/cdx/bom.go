package cdx

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

const (
	binaryPathPropertyName = "jfrog:location:path"
)

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

func propertiesToMap(properties ...cyclonedx.Property) (propertiesMap map[string]string) {
	propertiesMap = make(map[string]string)
	for _, property := range properties {
		if property.Name != "" && property.Value != "" {
			propertiesMap[property.Name] = property.Value
		}
	}
	return
}

// Extract the component name, version and type from PackageUrl and translate it to an Xray component id
func PurlToXrayComponentId(purl string) (xrayComponentId string) {
	compName, compVersion, compType := SplitPackageURL(purl)
	return techutils.ToXrayComponentId(compName, compVersion, techutils.CdxPackageTypeToXrayPackageType(compType))
}

func XrayComponentIdToPurl(xrayComponentId string) (purl string) {
	compName, compVersion, compType := techutils.SplitComponentIdRaw(xrayComponentId)
	return ToPackageUrl(compName, compVersion, techutils.ToCdxPackageType(compType))
}

func GetScaComponentRef(xrayImpactedPackageId string) string {
	compName, compVersion, compType := techutils.SplitComponentIdRaw(xrayImpactedPackageId)
	return ToPackageUrl(compName, compVersion, techutils.ToCdxPackageType(compType))
}

func CreateScaComponent(xrayImpactedPackageId string, properties ...cyclonedx.Property) (component cyclonedx.Component) {
	compName, compVersion, compType := techutils.SplitComponentIdRaw(xrayImpactedPackageId)
	component = cyclonedx.Component{
		BOMRef:     GetScaComponentRef(xrayImpactedPackageId),
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       compName,
		Version:    compVersion,
		PackageURL: ToPackageUrl(compName, compVersion, techutils.ToCdxPackageType(compType)),
	}
	if len(properties) > 0 {
		component.Properties = &properties
	}
	return
}

func CreateScaComponentFromNode(node *xrayUtils.BinaryGraphNode) (component cyclonedx.Component) {
	properties := []cyclonedx.Property{}
	// Add the path property if it exists
	if node.Path != "" {
		properties = append(properties, cyclonedx.Property{Name: binaryPathPropertyName, Value: node.Path})
	}
	// Create the component
	component = CreateScaComponent(node.Id, properties...)
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

func CreateFileOrDirComponent(filePathOrUri string) (component cyclonedx.Component) {
	component = cyclonedx.Component{
		BOMRef: GetFileRef(filePathOrUri),
		Type:   cyclonedx.ComponentTypeFile,
		Name:   convertToFileUrlIfNeeded(filePathOrUri),
	}
	return
}

func convertToFileUrlIfNeeded(location string) string {
	if !strings.HasPrefix(location, "file://") {
		return "file://" + filepath.ToSlash(location)
	}
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
	*components = append(*components, CreateScaComponent(node.Id))
	if len(node.Nodes) > 0 {
		// Create a matching dependency entry describing the direct dependencies
		*dependencies = append(*dependencies, cyclonedx.Dependency{Ref: GetScaComponentRef(node.Id), Dependencies: getNodeDirectDependencies(node)})
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
	for _, rootEntry := range ReduceToRoots(sbom) {
		currentTree := &xrayUtils.GraphNode{Id: rootEntry.Ref}
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
	for _, dep := range getDirectDependencies(sbom, node.Id) {
		depNode := &xrayUtils.GraphNode{Id: dep, Parent: node}
		// log.Debug(fmt.Sprintf("Adding dependency node: %s to parent node: %s", depNode.Id, node.Id))
		// Add the dependency to the current node
		node.Nodes = append(node.Nodes, depNode)
		// Recursively populate the node data
		populateDepsNodeDataFromBom(depNode, sbom)
	}
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
	ids := getLibraryComponentRefs(sbom)
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

func getLibraryComponentRefs(sbom *cyclonedx.BOM) (libraryComponentIds []string) {
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

func BomToFullCompTree(sbom *cyclonedx.BOM) (fullDependencyTree *xrayUtils.BinaryGraphNode) {
	fullDependencyTrees := []*xrayUtils.BinaryGraphNode{}
	for _, rootEntry := range ReduceToRoots(sbom) {
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
	for _, depRef := range getDirectDependencies(sbom, XrayComponentIdToPurl(node.Id)) {
		depNode := toBinaryNode(sbom, depRef)
		// Add the dependency to the current node
		node.Nodes = append(node.Nodes, depNode)
		// Recursively populate the node data
		populateCompsNodeDataFromBom(depNode, sbom)
	}
}

func toBinaryNode(sbom *cyclonedx.BOM, ref string) *xrayUtils.BinaryGraphNode {
	component := GetComponent(sbom, ref)
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

func getDirectDependencies(sbom *cyclonedx.BOM, componentRef string) (dependencies []string) {
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

func BomToDirectCompIds(sbom *cyclonedx.BOM) (directDepList *[]string) {
	directDepList = &[]string{}
	for _, root := range ReduceToRoots(sbom) {
		if root.Dependencies == nil {
			continue
		}
		for _, directDependency := range *root.Dependencies {
			*directDepList = append(*directDepList, PurlToXrayComponentId(directDependency))
		}
	}
	return
}
