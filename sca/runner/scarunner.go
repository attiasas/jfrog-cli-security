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
	ScaScanTask(tech techutils.Technology, target *cyclonedx.BOM) ([]services.ScanResponse, error)
}

// ScaParams holds the parameters for running SCA scans.
type ScaScanParams struct {
	Runner              *utils.SecurityParallelRunner
	ServerDetails       *config.ServerDetails
	ScansToPerform      []utils.SubScanType
	ConfigProfile       *xscServices.ConfigProfile
	AllowPartialResults bool
	ScanResults         *results.SecurityCommandResults
	ResultsOutputDir    string
	Strategy            SbomScanStrategy
}

func RunScaScans(params ScaScanParams) (generalError error) {
	if len(params.ScansToPerform) > 0 && !slices.Contains(params.ScansToPerform, utils.ScaScan) {
		log.Debug("Skipping SCA scan as requested by input...")
		return
	}
	if params.ConfigProfile != nil {
		if len(params.ConfigProfile.Modules) < 1 {
			// Verify Modules are not nil and contain at least one modules
			return fmt.Errorf("config profile %s has no modules. A config profile must contain at least one modules", params.ConfigProfile.ProfileName)
		}
		if !params.ConfigProfile.Modules[0].ScanConfig.EnableScaScan {
			log.Debug(fmt.Sprintf("Skipping SCA scan as requested by '%s' config profile...", params.ConfigProfile.ProfileName))
			return
		}
	}
	// Scan targets
	for _, targetResult := range params.ScanResults.Targets {
		if targetResult.Sbom == nil || targetResult.Sbom.Dependencies == nil || len(*targetResult.Sbom.Dependencies) == 0 {
			log.Debug(fmt.Sprintf("Skipping SCA scan for %s as no dependencies were found in the target", targetResult.Target))
			continue
		}
		// Create sca scan task
		if _, taskCreationErr := params.Runner.Runner.AddTaskWithError(createScaScanTask(params.Runner, targetResult, params.Strategy, params.ResultsOutputDir), func(err error) {
			_ = targetResult.AddTargetError(fmt.Errorf("failed to execute SCA scan: %s", err.Error()), params.AllowPartialResults)
		}); taskCreationErr != nil {
			_ = targetResult.AddTargetError(fmt.Errorf("failed to create SCA scan task: %s", taskCreationErr.Error()), params.AllowPartialResults)
			// If we failed to create the task, we need to mark it as done
			params.Runner.ScaScansWg.Done()
		}
	}
	return
}

func createScaScanTask(auditParallelRunner *utils.SecurityParallelRunner, targetResult *results.TargetResults, strategy SbomScanStrategy, outputDir string) parallel.TaskFunc {
	auditParallelRunner.ScaScansWg.Add(1)
	return func(threadId int) (err error) {
		defer auditParallelRunner.ScaScansWg.Done()
		log.Info(clientUtils.GetLogMsgPrefix(threadId, false)+"Running SCA scan for", targetResult.Target, "vulnerable dependencies in", targetResult.Target, "directory...")
		//
		auditParallelRunner.ResultsMu.Lock()
		defer auditParallelRunner.ResultsMu.Unlock()
		// SCA Scan the target.
		scanResults, xrayErr := strategy.ScaScanTask(targetResult.Technology, targetResult.Sbom)
		// We add the results before checking for errors, so we can display the results even if an error occurred.
		targetResult.NewScaScanResults(GetScaScansStatusCode(xrayErr, scanResults...), scanResults...).IsMultipleRootProject = clientUtils.Pointer(cdx.IsMultiProject(targetResult.Sbom))
		if xrayErr != nil {
			return fmt.Errorf("%s Xray dependency tree scan request on '%s' failed:\n%s", clientUtils.GetLogMsgPrefix(threadId, false), targetResult.Technology, xrayErr.Error())
		}
		return dumpScanResponseToFileIfNeeded(scanResults, outputDir, utils.ScaScan)
	}
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
func dumpScanResponseToFileIfNeeded(results []services.ScanResponse, scanResultsOutputDir string, scanType utils.SubScanType) (err error) {
	if scanResultsOutputDir == "" || results == nil {
		return
	}
	fileContent, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to write %s scan results to file: %s", scanType, err.Error())
	}
	return utils.DumpContentToFile(fileContent, scanResultsOutputDir, scanType.String())
}
