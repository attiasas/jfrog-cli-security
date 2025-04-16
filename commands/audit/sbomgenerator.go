package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/CycloneDX/cyclonedx-go"

	biUtils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayClientUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/cocoapods"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/conan"
	_go "github.com/jfrog/jfrog-cli-security/commands/audit/sca/go"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/java"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/npm"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/nuget"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/pnpm"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/python"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/swift"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/yarn"

	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/artifactory"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdx"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
)

type JfrogSourceCodeBomGenerator struct {
	params *AuditParams
}

func (jbg *JfrogSourceCodeBomGenerator) Parallel(threadId int) bom.SbomGenerator {
	return jbg
}

func (jbg *JfrogSourceCodeBomGenerator) GenerateSbom(target results.ScanTarget) (sbom *cyclonedx.BOM, err error) {
	// Create the CycloneDX BOM
	sbom = cyclonedx.NewBOM()
	wdComponent := cdx.CreateFileOrDirComponent(target.Target)
	sbom.Metadata = &cyclonedx.Metadata{Component: &wdComponent}

	// Make sure to return to the original working directory, buildDependencyTree may change it
	if currentWorkingDir, generalError := os.Getwd(); errorutils.CheckError(generalError) != nil {
		err = fmt.Errorf("failed to get current working directory: %w", generalError)
		return
	} else {
		defer func() {
			generalError = errors.Join(generalError, errorutils.CheckError(os.Chdir(currentWorkingDir)))
		}()
	}
	log.Debug(fmt.Sprintf("Generating '%s' dependency tree...", target.Target))
	treeResult, bdtErr := buildDependencyTree(target, jbg.params)
	if bdtErr != nil {
		var projectNotInstalledErr *biUtils.ErrProjectNotInstalled
		if errors.As(bdtErr, &projectNotInstalledErr) {
			log.Warn(bdtErr.Error())
			return
		}
		err = fmt.Errorf("failed to build dependency tree: %s", bdtErr.Error())
		return
	}
	sbom.Components, sbom.Dependencies = cdx.DepsTreeToSbom(treeResult.FullDepTrees...)
	return
}

type DependencyTreeResult struct {
	FlatTree     *xrayClientUtils.GraphNode
	FullDepTrees []*xrayClientUtils.GraphNode
	DownloadUrls map[string]string
}

// This method will change the working directory to the scan's working directory.
func buildDependencyTree(scan results.ScanTarget, params *AuditParams) (*DependencyTreeResult, error) {
	if err := os.Chdir(scan.Target); err != nil {
		return nil, errorutils.CheckError(err)
	}
	serverDetails, err := SetResolutionRepoInAuditParamsIfExists(params.AuditBasicParams, scan.Technology)
	if err != nil {
		return nil, err
	}
	treeResult, techErr := GetTechDependencyTree(params.AuditBasicParams, serverDetails, scan.Technology)
	if techErr != nil {
		return nil, fmt.Errorf("failed while building '%s' dependency tree: %w", scan.Technology, techErr)
	}
	if treeResult.FlatTree == nil || len(treeResult.FlatTree.Nodes) == 0 {
		return nil, errorutils.CheckErrorf("no dependencies were found. Please try to build your project and re-run the audit command")
	}
	return &treeResult, nil
}

func SetResolutionRepoInAuditParamsIfExists(params utils.AuditParams, tech techutils.Technology) (serverDetails *config.ServerDetails, err error) {
	if serverDetails, err = params.ServerDetails(); err != nil {
		return
	}
	if params.DepsRepo() != "" || params.IgnoreConfigFile() {
		// If the depsRepo is already set or the configuration file is ignored, there is no need to search for the configuration file.
		return
	}
	artifactoryDetails, err := artifactory.GetResolutionRepoIfExists(tech)
	if err != nil {
		return
	}
	if artifactoryDetails == nil {
		return params.ServerDetails()
	}
	// If the configuration file is found, the server details and the target repository are extracted from it.
	params.SetDepsRepo(artifactoryDetails.TargetRepository)
	params.SetServerDetails(artifactoryDetails.ServerDetails)
	serverDetails = artifactoryDetails.ServerDetails
	return
}

func GetTechDependencyTree(params utils.AuditParams, artifactoryServerDetails *config.ServerDetails, tech techutils.Technology) (depTreeResult DependencyTreeResult, err error) {
	logMessage := fmt.Sprintf("Calculating %s dependencies", tech.ToFormal())
	curationLogMsg, curationCacheFolder, err := getCurationCacheFolderAndLogMsg(params, tech)
	if err != nil {
		return
	}
	// In case it's not curation command these 'curationLogMsg' be empty
	logMessage += curationLogMsg
	log.Info(logMessage + "...")
	if params.Progress() != nil {
		params.Progress().SetHeadlineMsg(logMessage)
	}

	var uniqueDeps []string
	var uniqDepsWithTypes map[string]*xray.DepTreeNode
	startTime := time.Now()

	switch tech {
	case techutils.Maven, techutils.Gradle:
		depTreeResult.FullDepTrees, uniqDepsWithTypes, err = java.BuildDependencyTree(java.DepTreeParams{
			Server:                  artifactoryServerDetails,
			DepsRepo:                params.DepsRepo(),
			IsMavenDepTreeInstalled: params.IsMavenDepTreeInstalled(),
			UseWrapper:              params.UseWrapper(),
			IsCurationCmd:           params.IsCurationCmd(),
			CurationCacheFolder:     curationCacheFolder,
		}, tech)
	case techutils.Npm:
		depTreeResult.FullDepTrees, uniqueDeps, err = npm.BuildDependencyTree(params)
	case techutils.Pnpm:
		depTreeResult.FullDepTrees, uniqueDeps, err = pnpm.BuildDependencyTree(params)
	case techutils.Conan:
		depTreeResult.FullDepTrees, uniqueDeps, err = conan.BuildDependencyTree(params)
	case techutils.Yarn:
		depTreeResult.FullDepTrees, uniqueDeps, err = yarn.BuildDependencyTree(params)
	case techutils.Go:
		depTreeResult.FullDepTrees, uniqueDeps, err = _go.BuildDependencyTree(params)
	case techutils.Pipenv, techutils.Pip, techutils.Poetry:
		depTreeResult.FullDepTrees, uniqueDeps,
			depTreeResult.DownloadUrls, err = python.BuildDependencyTree(params, tech)
	case techutils.Nuget:
		depTreeResult.FullDepTrees, uniqueDeps, err = nuget.BuildDependencyTree(params)
	case techutils.Cocoapods:
		xrayVersion := params.GetXrayVersion()
		err = clientUtils.ValidateMinimumVersion(clientUtils.Xray, xrayVersion, scangraph.CocoapodsScanMinXrayVersion)
		if err != nil {
			return depTreeResult, fmt.Errorf("your xray version %s does not allow cocoapods scanning", xrayVersion)
		}
		depTreeResult.FullDepTrees, uniqueDeps, err = cocoapods.BuildDependencyTree(params)
	case techutils.Swift:
		xrayVersion := params.GetXrayVersion()
		err = clientUtils.ValidateMinimumVersion(clientUtils.Xray, xrayVersion, scangraph.SwiftScanMinXrayVersion)
		if err != nil {
			return depTreeResult, fmt.Errorf("your xray version %s does not allow swift scanning", xrayVersion)
		}
		depTreeResult.FullDepTrees, uniqueDeps, err = swift.BuildDependencyTree(params)
	default:
		err = errorutils.CheckErrorf("%s is currently not supported", string(tech))
	}
	if err != nil || (len(uniqueDeps) == 0 && len(uniqDepsWithTypes) == 0) {
		return
	}
	log.Debug(fmt.Sprintf("Created '%s' dependency tree with %d nodes. Elapsed time: %.1f seconds.", tech.ToFormal(), len(uniqueDeps), time.Since(startTime).Seconds()))
	if len(uniqDepsWithTypes) > 0 {
		depTreeResult.FlatTree, err = createFlatTreeWithTypes(uniqDepsWithTypes)
		return
	}
	depTreeResult.FlatTree, err = createFlatTree(uniqueDeps)
	return
}

func createFlatTreeWithTypes(uniqueDeps map[string]*xray.DepTreeNode) (*xrayClientUtils.GraphNode, error) {
	if err := logDeps(uniqueDeps); err != nil {
		return nil, err
	}
	var uniqueNodes []*xrayClientUtils.GraphNode
	for uniqueDep, nodeAttr := range uniqueDeps {
		node := &xrayClientUtils.GraphNode{Id: uniqueDep}
		if nodeAttr != nil {
			node.Types = nodeAttr.Types
			node.Classifier = nodeAttr.Classifier
		}
		uniqueNodes = append(uniqueNodes, node)
	}
	return &xrayClientUtils.GraphNode{Id: "root", Nodes: uniqueNodes}, nil
}

func createFlatTree(uniqueDeps []string) (*xrayClientUtils.GraphNode, error) {
	if err := logDeps(uniqueDeps); err != nil {
		return nil, err
	}
	uniqueNodes := []*xrayClientUtils.GraphNode{}
	for _, uniqueDep := range uniqueDeps {
		uniqueNodes = append(uniqueNodes, &xrayClientUtils.GraphNode{Id: uniqueDep})
	}
	return &xrayClientUtils.GraphNode{Id: "root", Nodes: uniqueNodes}, nil
}

func logDeps(uniqueDeps any) (err error) {
	if log.GetLogger().GetLogLevel() != log.DEBUG {
		// Avoid printing and marshaling if not on DEBUG mode.
		return
	}
	jsonList, err := json.Marshal(uniqueDeps)
	if errorutils.CheckError(err) != nil {
		return err
	}
	log.Debug("Unique dependencies list:\n" + clientUtils.IndentJsonArray(jsonList))

	return
}

func getCurationCacheFolderAndLogMsg(params utils.AuditParams, tech techutils.Technology) (logMessage string, curationCacheFolder string, err error) {
	if !params.IsCurationCmd() {
		return
	}
	if curationCacheFolder, err = getCurationCacheByTech(tech); err != nil || curationCacheFolder == "" {
		return
	}

	dirExist, err := fileutils.IsDirExists(curationCacheFolder, false)
	if err != nil {
		return
	}

	if dirExist {
		if dirIsEmpty, scopErr := fileutils.IsDirEmpty(curationCacheFolder); scopErr != nil || !dirIsEmpty {
			err = scopErr
			return
		}
	}

	logMessage = ". Quick note: we're running our first scan on the project with curation-audit. Expect this one to take a bit longer. Subsequent scans will be faster. Thanks for your patience"

	return logMessage, curationCacheFolder, err
}

func getCurationCacheByTech(tech techutils.Technology) (string, error) {
	if tech == techutils.Maven || tech == techutils.Go {
		return utils.GetCurationCacheFolderByTech(tech)
	}
	return "", nil
}
