package sca

import (
	"github.com/CycloneDX/cyclonedx-go"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

func DepsTreeToSbom(trees ...*xrayUtils.GraphNode) (sbom *cyclonedx.BOM) {
	return
}

func CompTreeToSbom(trees ...*xrayUtils.BinaryGraphNode) (sbom *cyclonedx.BOM) {
	return
}

func BomToTree(sbom *cyclonedx.BOM) (flatTree *xrayUtils.GraphNode, fullDependencyTrees []*xrayUtils.GraphNode) {
	return BomToFlatTree(sbom), BomToFullTree(sbom)
}

func BomToFullTree(sbom *cyclonedx.BOM) (fullDependencyTrees []*xrayUtils.GraphNode) {
	return
}

func BomToFlatTree(sbom *cyclonedx.BOM) (flatTree *xrayUtils.GraphNode) {
	return
}

func BomToFlatCompTree(sbom *cyclonedx.BOM) (flatTree *xrayUtils.BinaryGraphNode) {
	return
}
