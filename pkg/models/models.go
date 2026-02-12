package models

import (
	"net/url"
	"time"
)

// AssetType represents the type of an asset
type AssetType string

const (
	AssetTypeDomain  AssetType = "domain"
	AssetTypeIP      AssetType = "ip"
	AssetTypeURL     AssetType = "url"
	AssetTypeMobile  AssetType = "mobile"
	AssetTypeBinary  AssetType = "binary"
	AssetTypeOther   AssetType = "other"
)

// ProjectType represents the type of a project
type ProjectType string

const (
	ProjectTypeBugBounty ProjectType = "bug-bounty"
	ProjectTypeVDP       ProjectType = "vdp"        // Vulnerability Disclosure Program
	ProjectTypeResearch  ProjectType = "research"   // Personal security research
	ProjectTypePentest   ProjectType = "pentest"    // Client penetration testing
)

// ProjectStatus represents the status of a project
type ProjectStatus string

const (
	ProjectStatusActive    ProjectStatus = "active"
	ProjectStatusArchived  ProjectStatus = "archived"
	ProjectStatusCompleted ProjectStatus = "completed"
)

// FindingStatus represents the status of a finding
type FindingStatus string

const (
	FindingStatusNew        FindingStatus = "new"
	FindingStatusConfirmed  FindingStatus = "confirmed"
	FindingStatusDuplicate  FindingStatus = "duplicate"
	FindingStatusFalsePositive FindingStatus = "false_positive"
	FindingStatusReported   FindingStatus = "reported"
	FindingStatusResolved   FindingStatus = "resolved"
)

// FindingSeverity represents the severity of a finding
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityHigh     FindingSeverity = "high"
	SeverityMedium   FindingSeverity = "medium"
	SeverityLow      FindingSeverity = "low"
	SeverityInfo     FindingSeverity = "info"
)

// Program represents a bug bounty program
type Program struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Handle      string    `json:"handle"`
	Description string    `json:"description"`
	URL         string    `json:"url"`
	Platform    string    `json:"platform"`
	Policy      string    `json:"policy"`
	Scope       Scope     `json:"scope"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Project represents a bug bounty project
type Project struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Handle      string        `json:"handle"`
	Platform    string        `json:"platform"`
	Type        ProjectType   `json:"type"`
	Description string        `json:"description"`
	StartDate   time.Time     `json:"start_date"`
	EndDate     *time.Time    `json:"end_date,omitempty"`
	Status      ProjectStatus `json:"status"`
	Scope       Scope         `json:"scope"`
	Notes       string        `json:"notes"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// Scope represents the scope of a bug bounty program or project
type Scope struct {
	InScope   []Asset `json:"in_scope"`
	OutOfScope []Asset `json:"out_of_scope"`
}

// Asset represents a target asset in a bug bounty program or project
type Asset struct {
	Type         AssetType   `json:"type"`
	Value        string      `json:"value"`
	Description  string      `json:"description"`
	Instructions string      `json:"instructions"`
	Tags         []string    `json:"tags"`
	Attributes   map[string]interface{} `json:"attributes"`
}

// IsInScope checks if a given asset is in scope
func (s *Scope) IsInScope(assetType AssetType, value string) bool {
	// Check if the asset is explicitly out of scope
	for _, asset := range s.OutOfScope {
		if asset.Type == assetType && matchAsset(asset.Value, value) {
			return false
		}
	}

	// Check if the asset is explicitly in scope
	for _, asset := range s.InScope {
		if asset.Type == assetType && matchAsset(asset.Value, value) {
			return true
		}
	}

	// If we're checking a subdomain and the parent domain is in scope
	if assetType == AssetTypeDomain {
		for _, asset := range s.InScope {
			if asset.Type == AssetTypeDomain && isSubdomain(asset.Value, value) {
				return true
			}
		}
	}

	// If we're checking a URL and the domain is in scope
	if assetType == AssetTypeURL {
		u, err := url.Parse(value)
		if err == nil && u.Host != "" {
			for _, asset := range s.InScope {
				if asset.Type == AssetTypeDomain && (asset.Value == u.Host || isSubdomain(asset.Value, u.Host)) {
					return true
				}
			}
		}
	}

	return false
}

// Host represents a discovered host
type Host struct {
	ID          string      `json:"id"`
	ProjectID   string      `json:"project_id"`
	Type        AssetType   `json:"type"`
	Value       string      `json:"value"`
	IP          string      `json:"ip,omitempty"`
	Status      string      `json:"status"`
	Title       string      `json:"title,omitempty"`
	Technologies []string    `json:"technologies,omitempty"`
	Ports       []int       `json:"ports,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Screenshot  string      `json:"screenshot,omitempty"`
	Notes       string      `json:"notes,omitempty"`
	FoundBy     string      `json:"found_by"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// Endpoint represents a discovered URL endpoint
type Endpoint struct {
	ID          string      `json:"id"`
	ProjectID   string      `json:"project_id"`
	HostID      string      `json:"host_id"`
	URL         string      `json:"url"`
	Method      string      `json:"method,omitempty"`
	Status      int         `json:"status"`
	ContentType string      `json:"content_type,omitempty"`
	Title       string      `json:"title,omitempty"`
	Parameters  []Parameter `json:"parameters,omitempty"`
	Notes       string      `json:"notes,omitempty"`
	FoundBy     string      `json:"found_by"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// Parameter represents a URL or form parameter
type Parameter struct {
	Name        string      `json:"name"`
	Value       string      `json:"value,omitempty"`
	Type        string      `json:"type,omitempty"`
	Description string      `json:"description,omitempty"`
	Interesting bool        `json:"interesting"`
}

// FindingType represents the type of finding
type FindingType string

const (
	FindingTypeVulnerability FindingType = "vulnerability"
	FindingTypeExposure      FindingType = "exposure"
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypeInformation   FindingType = "information"
)

// FindingConfidence represents the confidence level of a finding
type FindingConfidence string

const (
	ConfidenceHigh   FindingConfidence = "high"
	ConfidenceMedium FindingConfidence = "medium"
	ConfidenceLow    FindingConfidence = "low"
)

// Finding represents a vulnerability finding
type Finding struct {
	ID          string         `json:"id"`
	ProjectID   string         `json:"project_id"`
	Type        FindingType    `json:"type"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Details     string         `json:"details"`
	Severity    FindingSeverity `json:"severity"`
	Confidence  FindingConfidence `json:"confidence"`
	Status      FindingStatus  `json:"status"`
	URL         string         `json:"url,omitempty"`
	CVSS        float64        `json:"cvss,omitempty"`
	CWE         string         `json:"cwe,omitempty"`
	Steps       []string       `json:"steps"`
	Evidence    interface{}    `json:"evidence"` // Can be []Evidence or map[string]interface{}
	Metadata    interface{}    `json:"metadata,omitempty"` // Additional metadata
	Impact      string         `json:"impact"`
	Remediation string         `json:"remediation"`
	References  []string       `json:"references"`
	FoundBy     string         `json:"found_by"`
	FoundAt     time.Time      `json:"found_at"`
	AffectedAssets []string    `json:"affected_assets"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// Evidence represents evidence for a finding
type Evidence struct {
	Type        string      `json:"type"`
	Data        string      `json:"data"`
	Description string      `json:"description,omitempty"`
}

// Report represents a generated report
type Report struct {
	ID          string                 `json:"id"`
	ProjectID   string                 `json:"project_id"`
	FindingID   string                 `json:"finding_id,omitempty"`
	Title       string                 `json:"title"`
	Format      string                 `json:"format"`
	Content     string                 `json:"content"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Task represents a background task
type Task struct {
	ID          string                 `json:"id"`
	ProjectID   string                 `json:"project_id"`
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Status      string                 `json:"status"`
	Priority    string                 `json:"priority"`
	AssignedTo  string                 `json:"assigned_to"`
	Progress    int                    `json:"progress"`
	Details     map[string]interface{} `json:"details"`
	Result      map[string]interface{} `json:"result"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt time.Time              `json:"completed_at,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// matchAsset checks if a value matches an asset pattern
// Handles exact matches and wildcard patterns
func matchAsset(pattern, value string) bool {
	// TODO: Implement pattern matching for wildcards like *.example.com
	return pattern == value
}

// isSubdomain checks if a domain is a subdomain of another
func isSubdomain(parent, child string) bool {
	// TODO: Implement proper subdomain checking
	return false
}
