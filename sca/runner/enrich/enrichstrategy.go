package enrich

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"

	"github.com/jfrog/jfrog-cli-security/sca/runner"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/catalog"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdx"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
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
		log.Debug(clientUtils.GetLogMsgPrefix(ess.threadId, false) + fmt.Sprintf("Enriched BOM: %s", str))
	}
	// response = toScanResponse(enriched)
	log.Info(clientUtils.GetLogMsgPrefix(ess.threadId, false) + fmt.Sprintf("Finished '%s' enrich. %s", services.Dependency, utils.GetScanVulnerabilitiesLog(utils.ScaScan, len(response.Vulnerabilities))))
	return
}

func (ess *EnrichScanStrategy) SbomEnrichTask(target *cyclonedx.BOM) (enriched *cyclonedx.BOM, _ []services.Violation, err error) {
	catalogManager, err := catalog.CreateCatalogServiceManager(ess.ServerDetails, catalog.WithScopedProjectKey(ess.ProjectKey))
	if err != nil {
		return nil, []services.Violation{}, fmt.Errorf("failed to create catalog service manager: %w", err)
	}
	log.Info(clientUtils.GetLogMsgPrefix(ess.threadId, false) + fmt.Sprintf("Enriching BOM with %d library components...", len(cdx.GetLibraryComponentRefs(target))))
	enriched, err = catalogManager.Enrich(target)
	if err != nil {
		return nil, []services.Violation{}, fmt.Errorf("failed to enrich BOM: %w", err)
	}
	vulnerabilities := 0
	if enriched.Vulnerabilities != nil {
		vulnerabilities = len(*enriched.Vulnerabilities)
	}
	log.Info(clientUtils.GetLogMsgPrefix(ess.threadId, false) + fmt.Sprintf("Finished '%s' enrich. %s", services.Dependency, utils.GetScanVulnerabilitiesLog(utils.ScaScan, vulnerabilities)))
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
