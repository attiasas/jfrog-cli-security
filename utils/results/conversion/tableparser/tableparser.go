package tableparser

import (
	"sort"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/maps"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/simplejsonparser"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/jfrog-client-go/xray/services"
)

type CmdResultsTableConverter struct {
	simpleJsonConvertor *simplejsonparser.CmdResultsSimpleJsonConverter
	sbomInfo            map[string]formats.SbomTableRow
	// If supported, pretty print the output in the tables
	pretty bool
}

func NewCmdResultsTableConverter(pretty bool) *CmdResultsTableConverter {
	return &CmdResultsTableConverter{pretty: pretty, simpleJsonConvertor: simplejsonparser.NewCmdResultsSimpleJsonConverter(pretty, true), sbomInfo: make(map[string]formats.SbomTableRow)}
}

func (tc *CmdResultsTableConverter) Get() (formats.ResultsTables, error) {
	simpleJsonFormat, err := tc.simpleJsonConvertor.Get()
	if err != nil {
		return formats.ResultsTables{}, err
	}
	return formats.ResultsTables{
		LicensesTable: formats.ConvertToLicenseTableRow(simpleJsonFormat.Licenses),
		SbomTable:     SortSbom(maps.Values(tc.sbomInfo)),

		SecurityVulnerabilitiesTable:   formats.ConvertToScaVulnerabilityOrViolationTableRow(simpleJsonFormat.Vulnerabilities),
		SecurityViolationsTable:        formats.ConvertToScaVulnerabilityOrViolationTableRow(simpleJsonFormat.SecurityViolations),
		LicenseViolationsTable:         formats.ConvertToLicenseViolationTableRow(simpleJsonFormat.LicensesViolations),
		OperationalRiskViolationsTable: formats.ConvertToOperationalRiskViolationTableRow(simpleJsonFormat.OperationalRiskViolations),
		SecretsVulnerabilitiesTable:    formats.ConvertToSecretsTableRow(simpleJsonFormat.SecretsVulnerabilities),
		SecretsViolationsTable:         formats.ConvertToSecretsTableRow(simpleJsonFormat.SecretsViolations),
		IacVulnerabilitiesTable:        formats.ConvertToIacOrSastTableRow(simpleJsonFormat.IacsVulnerabilities),
		IacViolationsTable:             formats.ConvertToIacOrSastTableRow(simpleJsonFormat.IacsViolations),
		SastVulnerabilitiesTable:       formats.ConvertToIacOrSastTableRow(simpleJsonFormat.SastVulnerabilities),
		SastViolationsTable:            formats.ConvertToIacOrSastTableRow(simpleJsonFormat.SastViolations),
	}, nil
}

func (tc *CmdResultsTableConverter) Reset(cmdType utils.CommandType, multiScanId, xrayVersion string, entitledForJas, multipleTargets bool, generalError error) (err error) {
	return tc.simpleJsonConvertor.Reset(cmdType, multiScanId, xrayVersion, entitledForJas, multipleTargets, generalError)
}

func (tc *CmdResultsTableConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	return tc.simpleJsonConvertor.ParseNewTargetResults(target, errors...)
}

func (tc *CmdResultsTableConverter) ParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseScaIssues(target, violations, scaResponse, applicableScan...)
}

func (tc *CmdResultsTableConverter) ParseLicenses(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse]) (err error) {
	return tc.simpleJsonConvertor.ParseLicenses(target, scaResponse)
}

func (tc *CmdResultsTableConverter) ParseSecrets(target results.ScanTarget, isViolationsResults bool, secrets []results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseSecrets(target, isViolationsResults, secrets)
}

func (tc *CmdResultsTableConverter) ParseIacs(target results.ScanTarget, isViolationsResults bool, iacs []results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseIacs(target, isViolationsResults, iacs)
}

func (tc *CmdResultsTableConverter) ParseSast(target results.ScanTarget, isViolationsResults bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseSast(target, isViolationsResults, sast)
}

func (tc *CmdResultsTableConverter) ParseSbom(_ results.ScanTarget, sbom *cyclonedx.BOM) (err error) {
	return results.ForEachSbom(sbom, func(component cyclonedx.Component, relatedDependencies *cyclonedx.Dependency, isDirect bool) (e error) {
		if component.Type != cyclonedx.ComponentTypeLibrary {
			// We are only interested in libraries for the Table Sbom
			return
		}
		id := component.PackageURL
		currName, currVersion, currType := techutils.SplitPackageURL(id)
		entry := formats.SbomTableRow{Component: currName, Version: currVersion, PackageType: currType, Relation: getDirectStr(isDirect), Direct: isDirect}
		if parsedEntry, exists := tc.sbomInfo[id]; exists {
			if entry.Direct && !parsedEntry.Direct {
				// If the new entry is direct, we want to override the existing entry
				tc.sbomInfo[id] = entry
			}
			// No need to add the entry again
			return
		}
		// The entry does not exist, we want to add it
		tc.sbomInfo[id] = entry
		return
	})
}

func getDirectStr(isDirect bool) string {
	if isDirect {
		return "Direct"
	}
	return "Transitive"
}

func SortSbom(components []formats.SbomTableRow) []formats.SbomTableRow {
	sort.Slice(components, func(i, j int) bool {
		if components[i].Direct == components[j].Direct {
			if components[i].Component == components[j].Component {
				if components[i].Version == components[j].Version {
					// Last order by type
					return components[i].PackageType < components[j].PackageType
				}
				// Third order by version
				return components[i].Version < components[j].Version
			}
			// Second order by component
			return components[i].Component < components[j].Component
		}
		// First order by direct components
		return components[i].Direct
	})
	return components
}
