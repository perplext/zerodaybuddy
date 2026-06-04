package models

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplext/zerodaybuddy/pkg/utils"
	"gopkg.in/yaml.v3"
)

// PlatformManual is the platform value for manually-created projects (no
// bug-bounty platform API behind them).
const PlatformManual = "manual"

// maxScopeFileSize caps how large a scope file may be before parsing. It guards
// against accidental huge files and against YAML alias-expansion ("billion
// laughs") attacks that would otherwise exhaust memory during unmarshal.
const maxScopeFileSize = 1 << 20 // 1 MiB

// Scope-file loading errors. Callers can match these with errors.Is.
var (
	ErrScopeFileTooLarge   = errors.New("scope file exceeds maximum allowed size")
	ErrScopeFileEmpty      = errors.New("scope file is empty")
	ErrScopeNoInScope      = errors.New("scope must declare at least one in-scope asset")
	ErrScopeInvalidType    = errors.New("scope asset has an unknown type")
	ErrScopeEmptyValue     = errors.New("scope asset has an empty value")
	ErrScopeUnknownFormat  = errors.New("unrecognized scope file format")
)

// validAssetTypes is the set of asset types accepted in a scope file. It mirrors
// the AssetType enum declared in models.go; widening the enum there is the only
// supported way to accept new types here.
var validAssetTypes = map[AssetType]struct{}{
	AssetTypeDomain:        {},
	AssetTypeIP:            {},
	AssetTypeURL:           {},
	AssetTypeMobile:        {},
	AssetTypeBinary:        {},
	AssetTypeContainer:     {},
	AssetTypeSmartContract: {},
	AssetTypeRepository:    {},
	AssetTypeOther:         {},
}

// IsValidAssetType reports whether t is one of the recognized AssetType values.
func IsValidAssetType(t AssetType) bool {
	_, ok := validAssetTypes[t]
	return ok
}

// ValidateScope checks a Scope for the invariants every project requires:
// at least one in-scope asset, and every asset (in or out of scope) carrying a
// known type and a non-empty value. It deliberately does NOT reject internal /
// RFC-1918 / loopback values — being in scope is an authorization statement,
// not a permission to scan; the scan service's SSRF filter is the enforcement
// boundary for what may actually be reached.
func ValidateScope(s *Scope) error {
	if s == nil {
		return ErrScopeNoInScope
	}
	if len(s.InScope) == 0 {
		return ErrScopeNoInScope
	}
	if err := validateAssets("in_scope", s.InScope); err != nil {
		return err
	}
	if err := validateAssets("out_of_scope", s.OutOfScope); err != nil {
		return err
	}
	return nil
}

func validateAssets(field string, assets []Asset) error {
	for i, asset := range assets {
		if strings.TrimSpace(asset.Value) == "" {
			return fmt.Errorf("%w: %s[%d]", ErrScopeEmptyValue, field, i)
		}
		if !IsValidAssetType(asset.Type) {
			return fmt.Errorf("%w: %s[%d] has type %q (allowed: %s)",
				ErrScopeInvalidType, field, i, asset.Type, allowedAssetTypesList())
		}
	}
	return nil
}

func allowedAssetTypesList() string {
	// Stable, human-readable list for error messages.
	return strings.Join([]string{
		string(AssetTypeDomain), string(AssetTypeIP), string(AssetTypeURL),
		string(AssetTypeMobile), string(AssetTypeBinary), string(AssetTypeContainer),
		string(AssetTypeSmartContract), string(AssetTypeRepository), string(AssetTypeOther),
	}, ", ")
}

// NewManualProject builds a Project for manual (non-platform) mode from a scope.
// It is the single construction point shared by the CLI (App.CreateManualProject)
// and the web create handler, so manual-mode defaults — research type, active
// status, handle-from-name, manual platform — cannot drift between the two
// surfaces. The scope is validated; an invalid scope returns an error and no
// project. Name validation is the caller's responsibility (CLI/web validate it
// against pkg/validation before constructing).
func NewManualProject(name, handle string, projectType ProjectType, scope Scope) (*Project, error) {
	if err := ValidateScope(&scope); err != nil {
		return nil, err
	}
	if projectType == "" {
		projectType = ProjectTypeResearch
	}
	if strings.TrimSpace(handle) == "" {
		handle = name
	}
	return &Project{
		Name:      name,
		Handle:    handle,
		Platform:  PlatformManual,
		Type:      projectType,
		StartDate: utils.CurrentTime(),
		Status:    ProjectStatusActive,
		Scope:     scope,
	}, nil
}

// LoadScopeFile reads, parses, and validates a scope file at path. The format is
// chosen by extension: ".json" parses as JSON; ".yaml"/".yml" and any other
// extension parse as YAML (a superset that also accepts JSON), so an
// extensionless file still works. Unknown keys are rejected rather than silently
// dropped, so a typo like "in_scopes:" surfaces as an error instead of an empty
// scope.
func LoadScopeFile(path string) (*Scope, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat scope file: %w", err)
	}
	if info.Size() > maxScopeFileSize {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrScopeFileTooLarge, info.Size(), maxScopeFileSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read scope file: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrScopeFileEmpty
	}

	var scope Scope
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&scope); err != nil {
			return nil, fmt.Errorf("failed to parse JSON scope file: %w", err)
		}
	default:
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&scope); err != nil {
			return nil, fmt.Errorf("failed to parse YAML scope file: %w", err)
		}
	}

	if err := ValidateScope(&scope); err != nil {
		return nil, err
	}
	return &scope, nil
}
