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

// If an output dir was provided through --output-dir flag, we create in the provided path new file containing the scan results
// func dumpScanResponseToFileIfNeeded(results []services.ScanResponse, scanResultsOutputDir string, scanType utils.SubScanType) (err error) {
// 	if scanResultsOutputDir == "" || results == nil {
// 		return
// 	}
// 	fileContent, err := json.Marshal(results)
// 	if err != nil {
// 		return fmt.Errorf("failed to write %s scan results to file: %s", scanType, err.Error())
// 	}
// 	return utils.DumpContentToFile(fileContent, scanResultsOutputDir, scanType.String())
// }

// // We can only perform SCA scan if we identified at least one technology for a target.
// func hasAtLeastOneTech(cmdResults *results.SecurityCommandResults) bool {
// 	if len(cmdResults.Targets) == 0 {
// 		return false
// 	}
// 	for _, scan := range cmdResults.Targets {
// 		if scan.Technology != techutils.NoTech {
// 			return true
// 		}
// 	}
// 	return false
// }

// func buildDepTreeAndRunScaScan(auditParallelRunner *utils.SecurityParallelRunner, auditParams *AuditParams, cmdResults *results.SecurityCommandResults) (generalError error) {
// 	if len(auditParams.ScansToPerform()) > 0 && !slices.Contains(auditParams.ScansToPerform(), utils.ScaScan) {
// 		log.Debug("Skipping SCA scan as requested by input...")
// 		return
// 	}
// 	if auditParams.configProfile != nil {
// 		if len(auditParams.configProfile.Modules) < 1 {
// 			// Verify Modules are not nil and contain at least one modules
// 			return fmt.Errorf("config profile %s has no modules. A config profile must contain at least one modules", auditParams.configProfile.ProfileName)
// 		}
// 		if !auditParams.configProfile.Modules[0].ScanConfig.EnableScaScan {
// 			log.Debug(fmt.Sprintf("Skipping SCA scan as requested by '%s' config profile...", auditParams.configProfile.ProfileName))
// 			return
// 		}
// 	}
// 	// Prepare
// 	currentWorkingDir, generalError := os.Getwd()
// 	if errorutils.CheckError(generalError) != nil {
// 		return
// 	}
// 	serverDetails, generalError := auditParams.ServerDetails()
// 	if generalError != nil {
// 		return
// 	}
// 	if !hasAtLeastOneTech(cmdResults) {
// 		log.Info("Couldn't determine a package manager or build tool used by this project. Skipping the SCA scan...")
// 		return
// 	}
// 	defer func() {
// 		// Make sure to return to the original working directory, buildDependencyTree may change it
// 		generalError = errors.Join(generalError, errorutils.CheckError(os.Chdir(currentWorkingDir)))
// 	}()
// 	// Perform SCA scans
// 	for _, targetResult := range cmdResults.Targets {
// 		if targetResult.Technology == "" {
// 			log.Warn(fmt.Sprintf("Couldn't determine a package manager or build tool used by this project. Skipping the SCA scan in '%s'...", targetResult.Target))
// 			continue
// 		}
// 		// Get the dependency tree for the technology in the working directory.
// 		treeResult, bdtErr := buildDependencyTree(targetResult.ScanTarget, auditParams)
// 		if bdtErr != nil {
// 			var projectNotInstalledErr *biutils.ErrProjectNotInstalled
// 			if errors.As(bdtErr, &projectNotInstalledErr) {
// 				log.Warn(bdtErr.Error())
// 				continue
// 			}
// 			_ = targetResult.AddTargetError(fmt.Errorf("failed to build dependency tree: %s", bdtErr.Error()), auditParams.AllowPartialResults())
// 			continue
// 		}
// 		// Create sca scan task
// 		auditParallelRunner.ScaScansWg.Add(1)
// 		// defer auditParallelRunner.ScaScansWg.Done()
// 		_, taskErr := auditParallelRunner.Runner.AddTaskWithError(executeScaScanTask(auditParallelRunner, serverDetails, auditParams, targetResult, treeResult), func(err error) {
// 			_ = targetResult.AddTargetError(fmt.Errorf("failed to execute SCA scan: %s", err.Error()), auditParams.AllowPartialResults())
// 		})
// 		if taskErr != nil {
// 			_ = targetResult.AddTargetError(fmt.Errorf("failed to create SCA scan task: %s", taskErr.Error()), auditParams.AllowPartialResults())
// 			auditParallelRunner.ScaScansWg.Done()
// 		}
// 	}
// 	return
// }

// // Perform the SCA scan for the given scan information.
// func executeScaScanTask(auditParallelRunner *utils.SecurityParallelRunner, serverDetails *config.ServerDetails, auditParams *AuditParams,
// 	scan *results.TargetResults, treeResult *DependencyTreeResult) parallel.TaskFunc {
// 	return func(threadId int) (err error) {
// 		defer auditParallelRunner.ScaScansWg.Done()
// 		log.Info(clientutils.GetLogMsgPrefix(threadId, false)+"Running SCA scan for", scan.Target, "vulnerable dependencies in", scan.Target, "directory...")
// 		// Scan the dependency tree.
// 		scanResults, xrayErr := runScaWithTech(scan.Technology, auditParams, serverDetails, *treeResult.FlatTree, treeResult.FullDepTrees)

// 		auditParallelRunner.ResultsMu.Lock()
// 		defer auditParallelRunner.ResultsMu.Unlock()
// 		// We add the results before checking for errors, so we can display the results even if an error occurred.
// 		scan.NewScaScanResults(scaRunner.GetScaScansStatusCode(xrayErr, scanResults...), scanResults...).IsMultipleRootProject = clientutils.Pointer(len(treeResult.FullDepTrees) > 1)
// 		// addThirdPartyDependenciesToParams(auditParams, scan.Technology, treeResult.FlatTree, treeResult.FullDepTrees)

// 		if xrayErr != nil {
// 			return fmt.Errorf("%s Xray dependency tree scan request on '%s' failed:\n%s", clientutils.GetLogMsgPrefix(threadId, false), scan.Technology, xrayErr.Error())
// 		}
// 		err = dumpScanResponseToFileIfNeeded(scanResults, auditParams.scanResultsOutputDir, utils.ScaScan)
// 		return
// 	}
// }

// func runScaWithTech(tech techutils.Technology, params *AuditParams, serverDetails *config.ServerDetails,
// 	flatTree xrayCmdUtils.GraphNode, fullDependencyTrees []*xrayCmdUtils.GraphNode) (techResults []services.ScanResponse, err error) {
// 	// Create the scan graph parameters.
// 	xrayScanGraphParams := params.createXrayGraphScanParams()
// 	xrayScanGraphParams.MultiScanId = params.GetMultiScanId()
// 	xrayScanGraphParams.XrayVersion = params.GetXrayVersion()
// 	xrayScanGraphParams.XscVersion = params.GetXscVersion()
// 	xrayScanGraphParams.Technology = tech.String()

// 	xrayScanGraphParams.DependenciesGraph = &flatTree
// 	scanGraphParams := scangraph.NewScanGraphParams().
// 		SetServerDetails(serverDetails).
// 		SetXrayGraphScanParams(xrayScanGraphParams).
// 		SetTechnology(tech).
// 		SetFixableOnly(params.fixableOnly).
// 		SetSeverityLevel(params.minSeverityFilter.String())

// 	log.Info(fmt.Sprintf("Scanning %d %s dependencies", len(flatTree.Nodes), tech) + "...")
// 	techResults, err = auditSca.RunXrayDependenciesTreeScanGraph(scanGraphParams)
// 	if err != nil {
// 		return
// 	}
// 	log.Info(fmt.Sprintf("Finished '%s' dependency tree scan. %s", tech.ToFormal(), utils.GetScanFindingsLog(utils.ScaScan, len(techResults[0].Vulnerabilities), len(techResults[0].Violations), -1)))
// 	techResults = auditSca.BuildImpactPathsForScanResponse(techResults, fullDependencyTrees)
// 	return
// }
