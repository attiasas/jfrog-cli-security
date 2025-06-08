package enrich

import (
	"fmt"
	"os"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"

	"github.com/jfrog/jfrog-cli-security/sca/runner"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/catalog"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdx"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type EnrichScanParams struct {
	ServerDetails *config.ServerDetails
	ProjectKey    string
}

type EnrichScanStrategy struct {
	EnrichScanParams
	threadId int
}

func copy(sgs *EnrichScanStrategy) *EnrichScanStrategy {
	return &EnrichScanStrategy{
		EnrichScanParams: sgs.EnrichScanParams,
	}
}

func (ess *EnrichScanStrategy) Parallel(threadId int) runner.SbomScanStrategy {
	instance := copy(ess)
	ess.threadId = threadId
	return instance
}

func (ess *EnrichScanStrategy) ScaScanTask(target *cyclonedx.BOM) (response services.ScanResponse, err error) {
	catalogManager, err := catalog.CreateCatalogServiceManager(ess.ServerDetails, catalog.WithScopedProjectKey(ess.ProjectKey))
	if err != nil {
		return services.ScanResponse{}, fmt.Errorf("failed to create catalog service manager: %w", err)
	}
	log.Info(clientUtils.GetLogMsgPrefix(ess.threadId, false) + fmt.Sprintf("Enriching BOM with %d library components...", len(cdx.GetLibraryComponentRefs(target))))
	enriched, err := catalogManager.Enrich(target)
	if err != nil {
		return services.ScanResponse{}, fmt.Errorf("failed to enrich BOM: %w", err)
	}
	vulnerabilities := 0
	if enriched.Vulnerabilities != nil {
		vulnerabilities = len(*enriched.Vulnerabilities)
	}
	log.Info(utils.GetScanVulnerabilitiesLog(utils.ScaScan, vulnerabilities))
	if str, e := utils.GetAsJsonString(enriched, true, true); e == nil {
		if err = os.WriteFile("/Users/assafa/Documents/code/jfrog-projects/jfrog-cli-security/scagn.json", []byte(str), 0644); errorutils.CheckError(err) != nil {
			return services.ScanResponse{}, fmt.Errorf("failed to write scan results to file: %s", err.Error())
		}
		log.Debug(fmt.Sprintf("%s Enriched BOM: %s", clientUtils.GetLogMsgPrefix(ess.threadId, false), str))
	}
	// response = toScanResponse(enriched)
	log.Info(fmt.Sprintf("%s Finished '%s' enrich. %s", clientUtils.GetLogMsgPrefix(ess.threadId, false), services.Dependency, utils.GetScanVulnerabilitiesLog(utils.ScaScan, len(response.Vulnerabilities))))
	return
}

func (ess *EnrichScanStrategy) SbomScanTask(target *cyclonedx.BOM) (response *cyclonedx.BOM, err error) {
	catalogManager, err := catalog.CreateCatalogServiceManager(ess.ServerDetails, catalog.WithScopedProjectKey(ess.ProjectKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create catalog service manager: %w", err)
	}
	log.Info(clientUtils.GetLogMsgPrefix(ess.threadId, false) + fmt.Sprintf("Enriching BOM with %d library components...", len(cdx.GetLibraryComponentRefs(target))))
	enriched, err := catalogManager.Enrich(target)
	if err != nil {
		return nil, fmt.Errorf("failed to enrich BOM: %w", err)
	}
	vulnerabilities := 0
	if enriched.Vulnerabilities != nil {
		vulnerabilities = len(*enriched.Vulnerabilities)
	}
	log.Info(utils.GetScanVulnerabilitiesLog(utils.ScaScan, vulnerabilities))
	if str, e := utils.GetAsJsonString(enriched, true, true); e == nil {
		log.Debug(fmt.Sprintf("%s Enriched BOM: %s", clientUtils.GetLogMsgPrefix(ess.threadId, false), str))
	}
	// response = toScanResponse(enriched)
	response = enriched
	log.Info(clientUtils.GetLogMsgPrefix(ess.threadId, false) + fmt.Sprintf("Finished '%s' enrich. %s", services.Dependency, utils.GetScanVulnerabilitiesLog(utils.ScaScan, len(*response.Vulnerabilities))))
	return
}

func getSeverity(vulnerability cyclonedx.Vulnerability) string {
	if vulnerability.Ratings == nil || len(*vulnerability.Ratings) == 0 {
		return severityutils.Unknown.String()
	}
	// Convert the ratings to severities
	severities := []severityutils.Severity{}
	for _, rating := range *vulnerability.Ratings {
		severities = append(severities, severityutils.CycloneDxSeverityToSeverity(rating.Severity))
	}
	// Get the most severe rating
	return severityutils.MostSevereSeverity(severities...).String()

}
