package main

import (
	"fmt"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/module/serialize"
	"github.com/aquasecurity/trivy/pkg/module/wasm"
)

const (
	ModuleVersion = 1
	ModuleName    = "ubuntu-severity-cvss"
)

func main() {
	wasm.RegisterModule(UbuntuSeverityCvss{})
}

type UbuntuSeverityCvss struct {
}

func (UbuntuSeverityCvss) Version() int {
	return ModuleVersion
}

func (UbuntuSeverityCvss) Name() string {
	return ModuleName
}

func (UbuntuSeverityCvss) PostScanSpec() serialize.PostScanSpec {
	return serialize.PostScanSpec{
		Action: api.ActionInsert,
		IDs: []string{"CVE-2024-7348"},
	}
}

func getSeverity(cvss types.CVSS) types.Severity {
	if cvss.V3Score == 0 {
		return types.SeverityUnknown
	} else if cvss.V3Score < 4 {
		return types.SeverityLow
	} else if cvss.V3Score < 7 {
		return types.SeverityMedium
	} else if cvss.V3Score < 9 {
		return types.SeverityHigh
	} else {
		return types.SeverityCritical
	}
}

func (UbuntuSeverityCvss) PostScan(results serialize.Results) (serialize.Results, error) {
	wasm.Info("Running Postscan")
	for i, result := range results {
	    wasm.Info(fmt.Sprintf("Iterating results %#v", results))
		for j, vuln := range result.Vulnerabilities {
			if vuln.SeveritySource != "ubuntu" {
				wasm.Info(fmt.Sprintf("Skipping %s with SeveritySource %s", vuln.VulnerabilityID, vuln.SeveritySource))
				continue
			}
			wasm.Info(fmt.Sprintf("Checking CVE: %s for pkgId: %s to see if severity needs to be updated", vuln.VulnerabilityID, vuln.PkgID))

			var severity types.Severity = types.SeverityUnknown
			if cvss, ok := vuln.CVSS["nvd"]; ok {
				severity = getSeverity(cvss)
			} else if cvss, ok := vuln.CVSS["ghsa"]; ok {
				severity = getSeverity(cvss)
			} else {
				for k := range vuln.CVSS {
					severity = getSeverity(vuln.CVSS[k])
					break
				}
			}

			if vulnSeverity, ok := types.NewSeverity(vuln.Severity); ok == nil {
				if vulnSeverity < severity {
					wasm.Info(fmt.Sprintf("Updating severity for %s from %s to %s", vuln.VulnerabilityID, vulnSeverity.String(), severity.String()))
					results[i].Vulnerabilities[j].Severity = severity.String()
				}
			}
		}
	}

	return results, nil
}
