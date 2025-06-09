package scangraph

import (
	"fmt"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/runner"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdx"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"

	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayClientUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

type JfrogScanGraphStrategy struct {
	scangraph.ScanGraphParams
	threadId int
}

func copy(sgs *JfrogScanGraphStrategy) *JfrogScanGraphStrategy {
	return &JfrogScanGraphStrategy{
		ScanGraphParams: sgs.ScanGraphParams,
		threadId:        sgs.threadId,
	}
}

// We create a new instance of JfrogScanGraphStrategy with the same parameters as the original instance.
// We set the technology to the new instance.
func (sgs *JfrogScanGraphStrategy) WithParams(params *scangraph.ScanGraphParams) runner.SbomScanStrategy {
	instance := copy(sgs)
	instance.ScanGraphParams = *params
	return instance
}

func (sgs *JfrogScanGraphStrategy) Parallel(threadId int) runner.SbomScanStrategy {
	instance := copy(sgs)
	instance.threadId = threadId
	return instance
}

func (sgs *JfrogScanGraphStrategy) SbomEnrichTask(target *cyclonedx.BOM) (enriched *cyclonedx.BOM, violations []services.Violation, err error) {
	var scanResults services.ScanResponse
	scanType := sgs.ScanGraphParams.XrayGraphScanParams().ScanType
	defer func() {
		if err == nil {
			log.Info(clientUtils.GetLogMsgPrefix(sgs.threadId, false) + fmt.Sprintf("Finished '%s' graph scan. %s", scanType, utils.GetScanFindingsLog(utils.ScaScan, len(scanResults.Vulnerabilities), len(scanResults.Violations), -1)))
		}
		return
	}()
	// Run the Xray scan based on the scan type.
	if scanType == services.Binary {
		scanResults, err = sgs.RunXrayBinaryTreeScanGraph(target)
	} else {
		scanResults, err = sgs.RunXrayDependenciesTreeScanGraph(target)
	}
	if err != nil {
		err = errorutils.CheckErrorf("scanning %s components failed with error: %s", scanType, err.Error())
		return
	}
	// Convert the scan results to CycloneDX BOM
	violations = scanResults.Violations
	enriched = target
	err = cdx.ScanResponseToSbom(enriched, scanResults)
	return
}

func (sgs *JfrogScanGraphStrategy) ScaScanTask(target *cyclonedx.BOM) (techResults services.ScanResponse, err error) {
	scanType := sgs.ScanGraphParams.XrayGraphScanParams().ScanType
	defer func() {
		if err == nil {
			log.Info(fmt.Sprintf("%s Finished '%s' graph scan. %s", clientUtils.GetLogMsgPrefix(sgs.threadId, false), scanType, utils.GetScanFindingsLog(utils.ScaScan, len(techResults.Vulnerabilities), len(techResults.Violations), -1)))
		}
		return
	}()
	if scanType == services.Binary {
		return sgs.RunXrayBinaryTreeScanGraph(target)
	}
	// Source code scan
	return sgs.RunXrayDependenciesTreeScanGraph(target)
}

func (sgs *JfrogScanGraphStrategy) RunXrayBinaryTreeScanGraph(target *cyclonedx.BOM) (results services.ScanResponse, err error) {
	params := &sgs.ScanGraphParams
	params.XrayGraphScanParams().ScanType = services.Binary
	// Convert BOM to tree and set to scan it
	fullCompTree := cdx.BomToFullCompTree(target)
	params.XrayGraphScanParams().BinaryGraph = fullCompTree
	// Scan
	xrayManager, err := xray.CreateXrayServiceManager(params.ServerDetails(), xray.WithScopedProjectKey(params.XrayGraphScanParams().ProjectKey))
	if err != nil {
		return
	}
	scanResults, err := scangraph.RunScanGraphAndGetResults(params, xrayManager)
	if err != nil {
		err = errorutils.CheckErrorf("scanning binary components failed with error: %s", err.Error())
		return
	}
	results = *scanResults
	return
}

func (sgs *JfrogScanGraphStrategy) RunXrayDependenciesTreeScanGraph(target *cyclonedx.BOM) (results services.ScanResponse, err error) {
	params := &sgs.ScanGraphParams
	params.XrayGraphScanParams().ScanType = services.Dependency
	// Convert BOM to tree and set the flat dependency tree to the scan parameters to improve net performance.
	flatDepTree, fullDepTree := cdx.BomToTree(target)
	search := "github.com/open-policy-agent"
	for i := range flatDepTree.Nodes {
		if strings.Contains(flatDepTree.Nodes[i].Id, search) {
			log.Debug(fmt.Sprintf("Found dependency with id '%s' in the flat dependency tree", flatDepTree.Nodes[i].Id))
		}
	}
	params.XrayGraphScanParams().DependenciesGraph = flatDepTree
	// Set Technology param
	technology := sgs.Technology()
	params.XrayGraphScanParams().Technology = technology.String()
	params.SetTechnology(technology)
	// Create Xray service manager
	xrayManager, err := xray.CreateXrayServiceManager(params.ServerDetails(), xray.WithScopedProjectKey(params.XrayGraphScanParams().ProjectKey))
	if err != nil {
		err = errorutils.CheckErrorf("failed to create Xray service manager: %w", err)
		return
	}
	// Scan
	log.Info(fmt.Sprintf("%s Scanning %d %s dependencies...", clientUtils.GetLogMsgPrefix(sgs.threadId, false), len(flatDepTree.Nodes), technology))
	scanResults, err := scangraph.RunScanGraphAndGetResults(params, xrayManager)
	if err != nil {
		err = errorutils.CheckErrorf("scanning %s dependencies failed with error: %s", technology.ToFormal(), err.Error())
		return
	}
	// Set the technology for each vulnerability and violation if not already set
	for i := range scanResults.Vulnerabilities {
		if scanResults.Vulnerabilities[i].Technology == "" {
			scanResults.Vulnerabilities[i].Technology = technology.String()
		}
	}
	for i := range scanResults.Violations {
		if scanResults.Violations[i].Technology == "" {
			scanResults.Violations[i].Technology = technology.String()
		}
	}
	// In Source code Xray Scan Graph, we send flat tree to Xray and construct the impact paths locally to improve performance.
	results = buildImpactPathsForScanResponse(*scanResults, fullDepTree)
	return
}

// BuildImpactPathsForScanResponse builds the full impact paths for each vulnerability found in the scanResult argument, using the dependencyTrees argument.
// Returns the updated services.ScanResponse slice.
func buildImpactPathsForScanResponse(scanResult services.ScanResponse, dependencyTree []*xrayClientUtils.GraphNode) services.ScanResponse {
	if len(scanResult.Vulnerabilities) > 0 {
		buildVulnerabilitiesImpactPaths(scanResult.Vulnerabilities, dependencyTree)
	}
	if len(scanResult.Violations) > 0 {
		buildViolationsImpactPaths(scanResult.Violations, dependencyTree)
	}
	if len(scanResult.Licenses) > 0 {
		buildLicensesImpactPaths(scanResult.Licenses, dependencyTree)
	}
	return scanResult
}

func buildVulnerabilitiesImpactPaths(vulnerabilities []services.Vulnerability, dependencyTrees []*xrayClientUtils.GraphNode) {
	issuesMap := make(map[string][][]services.ImpactPathNode)
	for _, vulnerability := range vulnerabilities {
		fillIssuesMapWithEmptyImpactPaths(issuesMap, vulnerability.Components)
	}
	buildImpactPaths(issuesMap, dependencyTrees)
	for i := range vulnerabilities {
		updateComponentsWithImpactPaths(vulnerabilities[i].Components, issuesMap)
	}
}

func buildViolationsImpactPaths(violations []services.Violation, dependencyTrees []*xrayClientUtils.GraphNode) {
	issuesMap := make(map[string][][]services.ImpactPathNode)
	for _, violation := range violations {
		fillIssuesMapWithEmptyImpactPaths(issuesMap, violation.Components)
	}
	buildImpactPaths(issuesMap, dependencyTrees)
	for i := range violations {
		updateComponentsWithImpactPaths(violations[i].Components, issuesMap)
	}
}

func buildLicensesImpactPaths(licenses []services.License, dependencyTrees []*xrayClientUtils.GraphNode) {
	issuesMap := make(map[string][][]services.ImpactPathNode)
	for _, license := range licenses {
		fillIssuesMapWithEmptyImpactPaths(issuesMap, license.Components)
	}
	buildImpactPaths(issuesMap, dependencyTrees)
	for i := range licenses {
		updateComponentsWithImpactPaths(licenses[i].Components, issuesMap)
	}
}

// Initialize a map of issues empty impact paths
func fillIssuesMapWithEmptyImpactPaths(issuesImpactPathsMap map[string][][]services.ImpactPathNode, components map[string]services.Component) {
	for dependencyName := range components {
		issuesImpactPathsMap[dependencyName] = [][]services.ImpactPathNode{}
	}
}

// Set the impact paths for each issue in the map
func buildImpactPaths(issuesImpactPathsMap map[string][][]services.ImpactPathNode, dependencyTrees []*xrayClientUtils.GraphNode) {
	for _, dependency := range dependencyTrees {
		setPathsForIssues(dependency, issuesImpactPathsMap, []services.ImpactPathNode{})
	}
}

func setPathsForIssues(dependency *xrayClientUtils.GraphNode, issuesImpactPathsMap map[string][][]services.ImpactPathNode, pathFromRoot []services.ImpactPathNode) {
	pathFromRoot = append(pathFromRoot, services.ImpactPathNode{ComponentId: dependency.Id})
	if _, exists := issuesImpactPathsMap[dependency.Id]; exists {
		// Create a copy of pathFromRoot to avoid modifying the original slice
		pathCopy := make([]services.ImpactPathNode, len(pathFromRoot))
		issuesImpactPathsMap[dependency.Id] = append(issuesImpactPathsMap[dependency.Id], pathCopy)
	}
	for _, depChild := range dependency.Nodes {
		setPathsForIssues(depChild, issuesImpactPathsMap, pathFromRoot)
	}
}

func updateComponentsWithImpactPaths(components map[string]services.Component, issuesMap map[string][][]services.ImpactPathNode) {
	for dependencyName := range components {
		updatedComponent := services.Component{
			FixedVersions: components[dependencyName].FixedVersions,
			ImpactPaths:   issuesMap[dependencyName],
			Cpes:          components[dependencyName].Cpes,
		}
		components[dependencyName] = updatedComponent
	}
}
