package runner

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscServices "github.com/jfrog/jfrog-client-go/xsc/services"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdx"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

// SbomScanStrategy is an interface for scanning SBOMs using different strategies.
type SbomScanStrategy interface {
	// Parallel creates new instance of Scanner for parallel execution.
	Parallel(threadId int) SbomScanStrategy
	// ScaScanTask scans the given SBOM using the specified technology.
	ScaScanTask(target *cyclonedx.BOM) (services.ScanResponse, error)
}

// ScaParams holds the parameters for running SCA scans.
type ScaScanParams struct {
	ServerDetails       *config.ServerDetails
	ScansToPerform      []utils.SubScanType
	ConfigProfile       *xscServices.ConfigProfile
	AllowPartialResults bool
	ResultsOutputDir    string
	ScanResults         *results.TargetResults
}

type DependencyScanParams struct {
	Runner *utils.SecurityParallelRunner
	ScaScanParams
}

type ComponentScanParams struct {
	ScaScanParams
}

func RunScaScan(strategy SbomScanStrategy, params DependencyScanParams) (generalError error) {
	if shouldRun, err := shouldRunScan(params.ScaScanParams, -1); err != nil {
		return err
	} else if !shouldRun {
		return
	}
	targetResult := params.ScanResults
	// Create sca scan task
	if _, taskCreationErr := params.Runner.Runner.AddTaskWithError(createScaScanTaskWithRunner(params.Runner, targetResult, strategy, params.ResultsOutputDir), func(err error) {
		_ = targetResult.AddTargetError(fmt.Errorf("failed to execute SCA scan: %s", err.Error()), params.AllowPartialResults)
	}); taskCreationErr != nil {
		_ = targetResult.AddTargetError(fmt.Errorf("failed to create SCA scan task: %s", taskCreationErr.Error()), params.AllowPartialResults)
		// If we failed to create the task, we need to mark it as done
		params.Runner.ScaScansWg.Done()
	}
	return
}

func createScaScanTaskWithRunner(auditParallelRunner *utils.SecurityParallelRunner, targetResult *results.TargetResults, strategy SbomScanStrategy, outputDir string) parallel.TaskFunc {
	auditParallelRunner.ScaScansWg.Add(1)
	return func(threadId int) (err error) {
		defer auditParallelRunner.ScaScansWg.Done()
		auditParallelRunner.ResultsMu.Lock()
		defer auditParallelRunner.ResultsMu.Unlock()
		return scaScanTask(threadId, targetResult, strategy, outputDir)
	}
}

func RunScaBinaryScans(strategy SbomScanStrategy, params ComponentScanParams, threadId int) (generalError error) {
	if shouldRunScan, err := shouldRunScan(params.ScaScanParams, threadId); err != nil {
		return err
	} else if !shouldRunScan {
		return
	}
	// Scan target
	if taskErr := scaScanTask(threadId, params.ScanResults, strategy, params.ResultsOutputDir); taskErr != nil {
		return params.ScanResults.AddTargetError(fmt.Errorf("failed to execute SCA scan: %s", taskErr.Error()), params.AllowPartialResults)
	}
	return
}

func shouldRunScan(params ScaScanParams, threadId int) (bool, error) {
	logPrefix := ""
	if threadId >= 0 {
		logPrefix = clientUtils.GetLogMsgPrefix(threadId, false)
	}
	if len(params.ScansToPerform) > 0 && !slices.Contains(params.ScansToPerform, utils.ScaScan) {
		log.Debug(fmt.Sprintf(logPrefix+"Skipping SCA scan for %s as requested by input...", params.ScanResults.Target))
		return false, nil

	}
	if params.ConfigProfile != nil {
		if len(params.ConfigProfile.Modules) < 1 {
			// Verify Modules are not nil and contain at least one modules
			return false, fmt.Errorf("config profile %s has no modules. A config profile must contain at least one modules", params.ConfigProfile.ProfileName)
		}
		if !params.ConfigProfile.Modules[0].ScanConfig.ScaScannerConfig.EnableScaScan {
			log.Debug(fmt.Sprintf(logPrefix+"Skipping SCA scan as requested by '%s' config profile...", params.ConfigProfile.ProfileName))
			return false, nil
		}
	}
	if !params.ScanResults.HasSbomComponents() {
		log.Debug(fmt.Sprintf(logPrefix+"Skipping SCA scan for %s as no dependencies were found in the target", params.ScanResults.Target))
		return false, nil
	}
	return true, nil
}

func scaScanTask(threadId int, targetResult *results.TargetResults, strategy SbomScanStrategy, outputDir string) error {
	log.Info(clientUtils.GetLogMsgPrefix(threadId, false)+"Running SCA scan for", targetResult.Target)

	// SCA Scan the target.
	scanResults, err := strategy.Parallel(threadId).ScaScanTask(targetResult.Sbom)

	// We add the results before checking for errors, so we can display the results even if an error occurred.
	targetResult.NewScaScanResults(GetScaScansStatusCode(err, scanResults), scanResults).IsMultipleRootProject = clientUtils.Pointer(cdx.IsMultiProject(targetResult.Sbom))
	if err != nil {
		return err
	}

	if targetResult.Technology == "" {
		targetResult.Technology = techutils.Technology(scanResults.ScannedPackageType)
	}

	return dumpScanResponseToFileIfNeeded(scanResults, outputDir, utils.ScaScan)
}

// Infer the status code of SCA Xray scan, must have at least one result, if err occurred or any of the results is `failed` return 1, otherwise return 0.
func GetScaScansStatusCode(err error, results ...services.ScanResponse) int {
	if err != nil || len(results) == 0 {
		return 1
	}
	for _, result := range results {
		if result.ScannedStatus == "Failed" {
			return 1
		}
	}
	return 0
}

// If an output dir was provided through --output-dir flag, we create in the provided path new file containing the scan results
func dumpScanResponseToFileIfNeeded(results services.ScanResponse, scanResultsOutputDir string, scanType utils.SubScanType) (err error) {
	if scanResultsOutputDir == "" {
		return
	}
	fileContent, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to write %s scan results to file: %s", scanType, err.Error())
	}
	return utils.DumpContentToFile(fileContent, scanResultsOutputDir, scanType.String())
}
