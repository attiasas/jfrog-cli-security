package bom

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

func DepsTreeToSbom(trees ...*xrayUtils.GraphNode) (sbom *cyclonedx.BOM) {
	sbom = cyclonedx.NewBOM()
	sbom.Components = &[]cyclonedx.Component{}
	sbom.Dependencies = &[]cyclonedx.Dependency{}
	parsed := datastructures.MakeSet[string]()
	// Populate Metadata
	sbom.Metadata = parseTreesForApplicationsMetaData(trees)
	// Populate Components and Dependencies
	for _, tree := range trees {
		parseDepsTreeToBOM(tree, sbom, parsed)
	}
	return
}

func parseTreesForApplicationsMetaData(trees []*xrayUtils.GraphNode) (metadata *cyclonedx.Metadata) {
	metadata = &cyclonedx.Metadata{Component: &cyclonedx.Component{}}
	singleApplication := len(trees) == 1
	for _, tree := range trees {
		applicationComponent := cyclonedx.Component{
			BOMRef:     XrayComponentIdToPurl(tree.Id),
			PackageURL: XrayComponentIdToPurl(tree.Id),
			Type:       cyclonedx.ComponentTypeApplication,
		}
		if singleApplication {
			metadata.Component = &applicationComponent
		} else {
			*metadata.Component.Components = append(*metadata.Component.Components, applicationComponent)
		}
	}
	return
}

func parseDepsTreeToBOM(node *xrayUtils.GraphNode, sbom *cyclonedx.BOM, parsed *datastructures.Set[string]) {
	// Extract the component name, version and type from the Xray component id
	compName, compVersion, compType := techutils.SplitComponentIdRaw(node.Id)
	packageUrl := techutils.ToPackageUrl(compName, compVersion, compType)
	// Check if the component was already parsed
	if parsed.Exists(packageUrl) {
		return
	}
	parsed.Add(packageUrl)
	if node.Parent != nil {
		// Create a new component and add it to the sbom
		component := cyclonedx.Component{
			BOMRef:     packageUrl,
			PackageURL: packageUrl,
			Name:       compName,
			Version:    compVersion,
			Type:       cyclonedx.ComponentTypeLibrary,
		}
		*sbom.Components = append(*sbom.Components, component)
	}
	// Create a matching dependency
	dependency := cyclonedx.Dependency{Ref: packageUrl, Dependencies: getNodeDirectDependencies(node)}
	*sbom.Dependencies = append(*sbom.Dependencies, dependency)
	// Add the dependencies to the BOM
	for _, dependencyNode := range node.Nodes {
		parseDepsTreeToBOM(dependencyNode, sbom, parsed)
	}
}

func getNodeDirectDependencies(node *xrayUtils.GraphNode) (dependencies *[]string) {
	dependencies = &[]string{}
	for _, dep := range node.Nodes {
		*dependencies = append(*dependencies, XrayComponentIdToPurl(dep.Id))
	}
	return
}

func CompTreeToSbom(trees ...*xrayUtils.BinaryGraphNode) (sbom *cyclonedx.BOM) {
	return
}

func BomToTree(sbom *cyclonedx.BOM) (flatTree *xrayUtils.GraphNode, fullDependencyTrees []*xrayUtils.GraphNode) {
	return BomToFlatTree(sbom), BomToFullTree(sbom)
}

func BomToFullTree(sbom *cyclonedx.BOM) (fullDependencyTrees []*xrayUtils.GraphNode) {
	for _, applicationRef := range GetApplicationComponentRefs(sbom) {
		currentTree := &xrayUtils.GraphNode{Id: applicationRef}
		// Populate application tree
		populateDepsNodeDataFromBom(currentTree, sbom)
		// Add the tree to the output list
		fullDependencyTrees = append(fullDependencyTrees, currentTree)
	}
	return
}

func populateDepsNodeDataFromBom(node *xrayUtils.GraphNode, sbom *cyclonedx.BOM) {
	for _, dep := range getDirectDependencies(sbom, node.Id) {
		depNode := &xrayUtils.GraphNode{Id: dep, Parent: node}
		// Add the dependency to the current node
		node.Nodes = append(node.Nodes, depNode)
		// Recursively populate the node data
		populateDepsNodeDataFromBom(depNode, sbom)
	}
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

func BomToFlatCompTree(sbom *cyclonedx.BOM) (flatTree *xrayUtils.BinaryGraphNode) {
	flatTree = &xrayUtils.BinaryGraphNode{Id: "root"}
	for _, component := range getUniqueXrayCompIds(sbom) {
		flatTree.Nodes = append(flatTree.Nodes, &xrayUtils.BinaryGraphNode{Id: component})
	}
	return
}

// Help functions

func GetApplicationComponentRefs(bom *cyclonedx.BOM) (applicationComponentRefs []string) {
	if bom == nil || bom.Components == nil {
		return
	}
	// Collect all the 'Application' components from the BOM
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return
	}
	mainComponent := bom.Metadata.Component
	if mainComponent.Type == cyclonedx.ComponentTypeApplication {
		applicationComponentRefs = append(applicationComponentRefs, mainComponent.BOMRef)
	}
	for _, component := range *mainComponent.Components {
		if component.Type == cyclonedx.ComponentTypeApplication {
			applicationComponentRefs = append(applicationComponentRefs, component.BOMRef)
		}
	}
	return
}

func getUniqueXrayCompIds(sbom *cyclonedx.BOM) (uniqueCompIds []string) {
	components := datastructures.MakeSet[string]()
	// Collect all unique components
	for _, component := range *sbom.Components {
		components.Add(PurlToXrayComponentId(component.PackageURL))
	}
	return components.ToSlice()
}

// Extract the component name, version and type from PackageUrl and translate it to an Xray component id
func PurlToXrayComponentId(purl string) (xrayComponentId string) {
	compName, compVersion, compType := techutils.SplitPackageURL(purl)
	return techutils.ToXrayComponentId(compName, compVersion, compType)
}

func XrayComponentIdToPurl(xrayComponentId string) (purl string) {
	compName, compVersion, compType := techutils.SplitComponentIdRaw(xrayComponentId)
	return techutils.ToPackageUrl(compName, compVersion, compType)
}
