package recon

import (
	"os/exec"

	"github.com/perplext/zerodaybuddy/pkg/models"
)

// execCommandContext is a variable to allow mocking in tests
var execCommandContext = exec.CommandContext

// makeAssets creates Asset objects from string values
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