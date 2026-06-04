package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/perplext/zerodaybuddy/pkg/models"
)

// TestFinding_GetWithNullableColumnsScansCleanly is a regression test for the
// scan-NULL-into-non-pointer-Go-type bug. The schema (per
// migrations/001_initial_schema.sql) declares `cvss`, `impact`, and
// `remediation` as nullable. Before the fix, scanning a row where any of
// those columns is SQL NULL crashed with "converting NULL to float64/string
// is unsupported" — the bulk-import path always populated them so the bug
// stayed latent until a row arrived from the web UI, manual SQL, or any
// future scope-file import path.
func TestFinding_GetWithNullableColumnsScansCleanly(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()
	ctx := context.Background()

	// Seed a project so the finding has a valid foreign key.
	project := &models.Project{
		Name:      "NullScanProj",
		Handle:    "null-scan",
		Platform:  "hackerone",
		StartDate: time.Now(),
		Status:    models.ProjectStatusActive,
		Scope: models.Scope{
			InScope: []models.Asset{{Type: models.AssetTypeDomain, Value: "example.com"}},
		},
	}
	require.NoError(t, store.CreateProject(ctx, project))

	// Insert a finding row directly via SQL with the nullable columns left
	// out — they default to NULL because the schema has no DEFAULT for them.
	// This bypasses CreateFinding (which would zero-fill them) and reproduces
	// the failure mode of any non-bulk-import ingest path. We reach through
	// the Store interface to the *SQLiteStore concrete type for raw SQL.
	sqlStore, ok := store.(*SQLiteStore)
	require.True(t, ok, "test requires SQLiteStore concrete backend")
	_, err := sqlStore.DB().ExecContext(ctx, `
		INSERT INTO findings (
			id, project_id, title, description, severity, status,
			found_by, found_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		"finding-null-001", project.ID,
		"Bare-minimum finding", "minimal description",
		"medium", "new",
		"regression-test", time.Now(), time.Now(), time.Now())
	require.NoError(t, err, "raw INSERT with NULL cvss/impact/remediation must succeed")

	// GetFinding: must return the row without erroring on the NULL columns,
	// and the resulting Finding should carry the Go zero values for those
	// fields (0 for CVSS, "" for Impact/Remediation).
	got, err := store.GetFinding(ctx, "finding-null-001")
	require.NoError(t, err, "GetFinding must scan NULL nullable columns cleanly")
	assert.Equal(t, "finding-null-001", got.ID)
	assert.Equal(t, "Bare-minimum finding", got.Title)
	assert.Equal(t, float64(0), got.CVSS, "NULL cvss should hydrate to 0")
	assert.Equal(t, "", got.Impact, "NULL impact should hydrate to empty string")
	assert.Equal(t, "", got.Remediation, "NULL remediation should hydrate to empty string")

	// ListFindings: same scan path, must succeed for the project.
	findings, err := store.ListFindings(ctx, project.ID)
	require.NoError(t, err, "ListFindings must scan NULL nullable columns cleanly")
	require.Len(t, findings, 1)
	assert.Equal(t, "finding-null-001", findings[0].ID)
}

// TestFinding_GetWithPopulatedNullableColumnsRoundtrips guards the other
// direction: a finding created with non-zero cvss/impact/remediation must
// still roundtrip those values through GetFinding after the wrapper change.
func TestFinding_GetWithPopulatedNullableColumnsRoundtrips(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()
	ctx := context.Background()

	project := &models.Project{
		Name:      "RoundtripProj",
		Handle:    "roundtrip",
		Platform:  "hackerone",
		StartDate: time.Now(),
		Status:    models.ProjectStatusActive,
		Scope: models.Scope{
			InScope: []models.Asset{{Type: models.AssetTypeDomain, Value: "example.com"}},
		},
	}
	require.NoError(t, store.CreateProject(ctx, project))

	finding := &models.Finding{
		ProjectID:   project.ID,
		Title:       "Populated finding",
		Description: "all the fields",
		Severity:    models.SeverityHigh,
		Status:      models.FindingStatusNew,
		CVSS:        7.5,
		Impact:      "Auth bypass exposes user PII.",
		Remediation: "Validate JWT signature on every request.",
		FoundBy:     "regression-test",
		FoundAt:     time.Now(),
	}
	require.NoError(t, store.CreateFinding(ctx, finding))

	got, err := store.GetFinding(ctx, finding.ID)
	require.NoError(t, err)
	assert.Equal(t, 7.5, got.CVSS)
	assert.Equal(t, "Auth bypass exposes user PII.", got.Impact)
	assert.Equal(t, "Validate JWT signature on every request.", got.Remediation)
}
