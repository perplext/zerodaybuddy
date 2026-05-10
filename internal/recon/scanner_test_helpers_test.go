package recon

import (
	"os/exec"

	"github.com/perplext/zerodaybuddy/pkg/models"
)

// execCommandContext is a variable to allow mocking in tests.
//
//nolint:unused // used by sibling _test.go files in this package; analyzer doesn't track cross-test-file usage reliably
var execCommandContext = exec.CommandContext

// makeAssets creates Asset objects from string values.
//
//nolint:unused // used by sibling _test.go files in this package; analyzer doesn't track cross-test-file usage reliably
func makeAssets(assetType models.AssetType, values []string) []models.Asset {
	var assets []models.Asset
	for _, value := range values {
		assets = append(assets, models.Asset{
			Type:  assetType,
			Value: value,
		})
	}
	return assets
}
