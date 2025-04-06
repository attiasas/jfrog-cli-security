package audit

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/bom"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayClientUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

type JfrogScanGraphStrategy struct {
	Params *AuditParams
}

func (sgs *JfrogScanGraphStrategy) ScaScanTask(tech techutils.Technology, target *cyclonedx.BOM) (techResults []services.ScanResponse, err error) {
	// Prepare
	serverDetails, err := sgs.Params.ServerDetails()
	if err != nil {
		return
	}
	flatDepTree, fullDepTree := bom.BomToTree(target)
	// Create the scan graph parameters.
	xrayScanGraphParams := sgs.Params.createXrayGraphScanParams()
	xrayScanGraphParams.MultiScanId = sgs.Params.GetMultiScanId()
	xrayScanGraphParams.XrayVersion = sgs.Params.GetXrayVersion()
	xrayScanGraphParams.XscVersion = sgs.Params.GetXscVersion()
	xrayScanGraphParams.Technology = tech.String()
	xrayScanGraphParams.DependenciesGraph = flatDepTree
	scanGraphParams := scangraph.NewScanGraphParams().
		SetServerDetails(serverDetails).
		SetXrayGraphScanParams(xrayScanGraphParams).
		SetTechnology(tech).
		SetFixableOnly(sgs.Params.fixableOnly).
		SetSeverityLevel(sgs.Params.minSeverityFilter.String())
	// Scan the dependency tree.
	log.Info(fmt.Sprintf("Scanning %d %s dependencies", len(flatDepTree.Nodes), tech) + "...")
	if techResults, err = RunXrayDependenciesTreeScanGraph(scanGraphParams); err != nil {
		return
	}
	log.Info(fmt.Sprintf("Finished '%s' dependency tree scan. %s", tech.ToFormal(), utils.GetScanFindingsLog(utils.ScaScan, len(techResults[0].Vulnerabilities), len(techResults[0].Violations), -1)))
	techResults = buildImpactPathsForScanResponse(techResults, fullDepTree)
	return
}

func RunXrayDependenciesTreeScanGraph(scanGraphParams *scangraph.ScanGraphParams) (results []services.ScanResponse, err error) {
	var scanResults *services.ScanResponse
	technology := scanGraphParams.Technology()
	xrayManager, err := xray.CreateXrayServiceManager(scanGraphParams.ServerDetails())
	if err != nil {
		return nil, err
	}
	scanResults, err = scangraph.RunScanGraphAndGetResults(scanGraphParams, xrayManager)
	if err != nil {
		err = errorutils.CheckErrorf("scanning %s dependencies failed with error: %s", technology.ToFormal(), err.Error())
		return
	}
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
	results = append(results, *scanResults)
	return
}

// BuildImpactPathsForScanResponse builds the full impact paths for each vulnerability found in the scanResult argument, using the dependencyTrees argument.
// Returns the updated services.ScanResponse slice.
func buildImpactPathsForScanResponse(scanResult []services.ScanResponse, dependencyTree []*xrayClientUtils.GraphNode) []services.ScanResponse {
	for _, result := range scanResult {
		if len(result.Vulnerabilities) > 0 {
			buildVulnerabilitiesImpactPaths(result.Vulnerabilities, dependencyTree)
		}
		if len(result.Violations) > 0 {
			buildViolationsImpactPaths(result.Violations, dependencyTree)
		}
		if len(result.Licenses) > 0 {
			buildLicensesImpactPaths(result.Licenses, dependencyTree)
		}
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
		copy(pathCopy, pathFromRoot)
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
