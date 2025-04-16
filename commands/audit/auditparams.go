package audit

import (
	"time"

	"github.com/jfrog/jfrog-cli-security/sca/bom"
	scaRunner "github.com/jfrog/jfrog-cli-security/sca/runner"
	jfrogScanGraph "github.com/jfrog/jfrog-cli-security/sca/runner/scangraph"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type AuditParams struct {
	// Common params to all scan routines
	resultsContext    results.ResultContext
	workingDirs       []string
	installFunc       func(tech string) error
	fixableOnly       bool
	minSeverityFilter severityutils.Severity
	*xrayutils.AuditBasicParams
	multiScanId string
	// Include third party dependencies source code in the applicability scan.
	thirdPartyApplicabilityScan bool
	threads                     int
	scanResultsOutputDir        string
	scanResultsRepository       string
	startTime                   time.Time
	// Dynamic logic params
	scanStrategy scaRunner.SbomScanStrategy
	bomGenerator bom.SbomGenerator
}

func NewAuditParams() *AuditParams {
	params := &AuditParams{
		AuditBasicParams: &xrayutils.AuditBasicParams{},
	}
	params.scanStrategy = &jfrogScanGraph.JfrogScanGraphStrategy{}
	params.bomGenerator = &JfrogSourceCodeBomGenerator{params: params}
	return params
}

func (params *AuditParams) ScanStrategy() scaRunner.SbomScanStrategy {
	return params.scanStrategy
}

func (params *AuditParams) BomGenerator() bom.SbomGenerator {
	return params.bomGenerator
}

// When building pip dependency tree using pipdeptree, some of the direct dependencies are recognized as transitive and missed by the CA scanner.
// Our solution for this case is to send all dependencies to the CA scanner.
// When thirdPartyApplicabilityScan is true, use flatten graph to include all the dependencies in applicability scanning.
// Only npm is supported for this flag.
func (params *AuditParams) ShouldGetFlatTreeForApplicableScan(tech techutils.Technology) bool {
	// Check if bomGenerator is set to JfrogBomGenerator type, if not, return false
	if params.bomGenerator == nil || !(params.bomGenerator.(*JfrogSourceCodeBomGenerator) != nil) {
		return false
	}
	return tech == techutils.Pip || (params.thirdPartyApplicabilityScan && tech == techutils.Npm)
}

func (params *AuditParams) InstallFunc() func(tech string) error {
	return params.installFunc
}

func (params *AuditParams) WorkingDirs() []string {
	return params.workingDirs
}

func (params *AuditParams) SetMultiScanId(msi string) *AuditParams {
	params.multiScanId = msi
	return params
}

func (params *AuditParams) GetMultiScanId() string {
	return params.multiScanId
}

func (params *AuditParams) SetStartTime(startTime time.Time) *AuditParams {
	params.startTime = startTime
	return params
}

func (params *AuditParams) StartTime() time.Time {
	return params.startTime
}

func (params *AuditParams) SetGraphBasicParams(gbp *xrayutils.AuditBasicParams) *AuditParams {
	params.AuditBasicParams = gbp
	return params
}

func (params *AuditParams) SetWorkingDirs(workingDirs []string) *AuditParams {
	params.workingDirs = workingDirs
	return params
}

func (params *AuditParams) SetInstallFunc(installFunc func(tech string) error) *AuditParams {
	params.installFunc = installFunc
	return params
}

func (params *AuditParams) FixableOnly() bool {
	return params.fixableOnly
}

func (params *AuditParams) SetFixableOnly(fixable bool) *AuditParams {
	params.fixableOnly = fixable
	return params
}

func (params *AuditParams) MinSeverityFilter() severityutils.Severity {
	return params.minSeverityFilter
}

func (params *AuditParams) SetMinSeverityFilter(minSeverityFilter severityutils.Severity) *AuditParams {
	params.minSeverityFilter = minSeverityFilter
	return params
}

func (params *AuditParams) SetThirdPartyApplicabilityScan(includeThirdPartyDeps bool) *AuditParams {
	params.thirdPartyApplicabilityScan = includeThirdPartyDeps
	return params
}

func (params *AuditParams) SetDepsRepo(depsRepo string) *AuditParams {
	params.AuditBasicParams.SetDepsRepo(depsRepo)
	return params
}

func (params *AuditParams) SetThreads(threads int) *AuditParams {
	params.threads = threads
	return params
}

func (params *AuditParams) SetResultsContext(resultsContext results.ResultContext) *AuditParams {
	params.resultsContext = resultsContext
	return params
}

func (params *AuditParams) SetScansResultsOutputDir(outputDir string) *AuditParams {
	params.scanResultsOutputDir = outputDir
	return params
}

func (params *AuditParams) SetScansResultsRepository(repository string) *AuditParams {
	params.scanResultsRepository = repository
	return params
}

func (params *AuditParams) createXrayGraphScanParams() *services.XrayGraphScanParams {
	return &services.XrayGraphScanParams{
		RepoPath:               params.resultsContext.RepoPath,
		Watches:                params.resultsContext.Watches,
		ProjectKey:             params.resultsContext.ProjectKey,
		GitRepoHttpsCloneUrl:   params.resultsContext.GitRepoHttpsCloneUrl,
		IncludeVulnerabilities: params.resultsContext.IncludeVulnerabilities,
		IncludeLicenses:        params.resultsContext.IncludeLicenses,
		ScanType:               services.Dependency,
	}
}
