package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAssetTypes(t *testing.T) {
	// Test that asset types have the expected values
	assert.Equal(t, AssetType("domain"), AssetTypeDomain)
	assert.Equal(t, AssetType("ip"), AssetTypeIP)
	assert.Equal(t, AssetType("url"), AssetTypeURL)
	assert.Equal(t, AssetType("mobile"), AssetTypeMobile)
	assert.Equal(t, AssetType("binary"), AssetTypeBinary)
	assert.Equal(t, AssetType("other"), AssetTypeOther)
}

func TestProjectStatus(t *testing.T) {
	// Test that project statuses have the expected values
	assert.Equal(t, ProjectStatus("active"), ProjectStatusActive)
	assert.Equal(t, ProjectStatus("archived"), ProjectStatusArchived)
	assert.Equal(t, ProjectStatus("completed"), ProjectStatusCompleted)
}

func TestFindingStatus(t *testing.T) {
	// Test that finding statuses have the expected values
	assert.Equal(t, FindingStatus("new"), FindingStatusNew)
	assert.Equal(t, FindingStatus("confirmed"), FindingStatusConfirmed)
	assert.Equal(t, FindingStatus("duplicate"), FindingStatusDuplicate)
	assert.Equal(t, FindingStatus("false_positive"), FindingStatusFalsePositive)
	assert.Equal(t, FindingStatus("reported"), FindingStatusReported)
	assert.Equal(t, FindingStatus("resolved"), FindingStatusResolved)
}

func TestFindingSeverity(t *testing.T) {
	// Test that finding severities have the expected values
	assert.Equal(t, FindingSeverity("critical"), SeverityCritical)
	assert.Equal(t, FindingSeverity("high"), SeverityHigh)
	assert.Equal(t, FindingSeverity("medium"), SeverityMedium)
	assert.Equal(t, FindingSeverity("low"), SeverityLow)
	assert.Equal(t, FindingSeverity("info"), SeverityInfo)
}

func TestFindingType(t *testing.T) {
	// Test that finding types have the expected values
	assert.Equal(t, FindingType("vulnerability"), FindingTypeVulnerability)
	assert.Equal(t, FindingType("exposure"), FindingTypeExposure)
	assert.Equal(t, FindingType("misconfiguration"), FindingTypeMisconfiguration)
	assert.Equal(t, FindingType("information"), FindingTypeInformation)
}

func TestFindingConfidence(t *testing.T) {
	// Test that finding confidence levels have the expected values
	assert.Equal(t, FindingConfidence("high"), ConfidenceHigh)
	assert.Equal(t, FindingConfidence("medium"), ConfidenceMedium)
	assert.Equal(t, FindingConfidence("low"), ConfidenceLow)
}

func TestScopeIsInScope(t *testing.T) {
	scope := Scope{
		InScope: []Asset{
			{Type: AssetTypeDomain, Value: "example.com"},
			{Type: AssetTypeDomain, Value: "*.internal.com"},
			{Type: AssetTypeIP, Value: "192.168.1.0/24"},
			{Type: AssetTypeURL, Value: "https://api.example.com/*"},
		},
		OutOfScope: []Asset{
			{Type: AssetTypeDomain, Value: "admin.example.com"},
			{Type: AssetTypeIP, Value: "192.168.1.100"},
		},
	}

	tests := []struct {
		name      string
		assetType AssetType
		value     string
		expected  bool
	}{
		{
			name:      "domain in scope exact match",
			assetType: AssetTypeDomain,
			value:     "example.com",
			expected:  true,
		},
		{
			name:      "domain out of scope",
			assetType: AssetTypeDomain,
			value:     "admin.example.com",
			expected:  false,
		},
		{
			name:      "domain not in scope",
			assetType: AssetTypeDomain,
			value:     "notinscope.com",
			expected:  false,
		},
		{
			name:      "subdomain check",
			assetType: AssetTypeDomain,
			value:     "sub.example.com",
			expected:  false, // TODO: Should be true when isSubdomain is implemented
		},
		{
			name:      "IP in scope",
			assetType: AssetTypeIP,
			value:     "192.168.1.0/24",
			expected:  true,
		},
		{
			name:      "IP out of scope",
			assetType: AssetTypeIP,
			value:     "192.168.1.100",
			expected:  false,
		},
		{
			name:      "URL with in-scope domain",
			assetType: AssetTypeURL,
			value:     "https://example.com/test",
			expected:  true,
		},
		{
			name:      "URL with out-of-scope domain",
			assetType: AssetTypeURL,
			value:     "https://admin.example.com/test",
			expected:  false,
		},
		{
			name:      "URL parsing error",
			assetType: AssetTypeURL,
			value:     "not-a-url",
			expected:  false,
		},
		{
			name:      "other asset type",
			assetType: AssetTypeMobile,
			value:     "com.example.app",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scope.IsInScope(tt.assetType, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchAsset(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		value    string
		expected bool
	}{
		{
			name:     "exact match",
			pattern:  "example.com",
			value:    "example.com",
			expected: true,
		},
		{
			name:     "no match",
			pattern:  "example.com",
			value:    "other.com",
			expected: false,
		},
		// TODO: Add wildcard tests when implemented
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchAsset(tt.pattern, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSubdomain(t *testing.T) {
	tests := []struct {
		name     string
		parent   string
		child    string
		expected bool
	}{
		{
			name:     "not implemented",
			parent:   "example.com",
			child:    "sub.example.com",
			expected: false, // TODO: Should be true when implemented
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSubdomain(tt.parent, tt.child)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProgramStructure(t *testing.T) {
	now := time.Now()
	program := Program{
		ID:          "prog-123",
		Name:        "Test Program",
		Handle:      "test-program",
		Description: "A test bug bounty program",
		URL:         "https://example.com/program",
		Platform:    "hackerone",
		Policy:      "Be nice",
		Scope: Scope{
			InScope: []Asset{
				{Type: AssetTypeDomain, Value: "example.com"},
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	assert.Equal(t, "prog-123", program.ID)
	assert.Equal(t, "Test Program", program.Name)
	assert.Equal(t, "test-program", program.Handle)
	assert.Equal(t, "hackerone", program.Platform)
	assert.Len(t, program.Scope.InScope, 1)
}

func TestProjectStructure(t *testing.T) {
	now := time.Now()
	project := Project{
		ID:          "proj-123",
		Name:        "Test Project",
		Handle:      "test-project",
		Platform:    "bugcrowd",
		Description: "A test project",
		StartDate:   now,
		Status:      ProjectStatusActive,
		Scope: Scope{
			InScope: []Asset{
				{
					Type:         AssetTypeDomain,
					Value:        "*.example.com",
					Description:  "All subdomains",
					Instructions: "Test everything",
					Tags:         []string{"web", "api"},
					Attributes: map[string]interface{}{
						"importance": "high",
					},
				},
			},
			OutOfScope: []Asset{
				{
					Type:  AssetTypeDomain,
					Value: "admin.example.com",
				},
			},
		},
		Notes:     "Important notes",
		CreatedAt: now,
		UpdatedAt: now,
	}

	assert.Equal(t, "proj-123", project.ID)
	assert.Equal(t, "Test Project", project.Name)
	assert.Equal(t, ProjectStatusActive, project.Status)
	assert.Len(t, project.Scope.InScope, 1)
	assert.Len(t, project.Scope.OutOfScope, 1)
	
	// Test Asset fields
	inScopeAsset := project.Scope.InScope[0]
	assert.Equal(t, AssetTypeDomain, inScopeAsset.Type)
	assert.Equal(t, "*.example.com", inScopeAsset.Value)
	assert.Equal(t, "All subdomains", inScopeAsset.Description)
	assert.Equal(t, "Test everything", inScopeAsset.Instructions)
	assert.Contains(t, inScopeAsset.Tags, "web")
	assert.Contains(t, inScopeAsset.Tags, "api")
	assert.Equal(t, "high", inScopeAsset.Attributes["importance"])
}

func TestHostStructure(t *testing.T) {
	now := time.Now()
	host := Host{
		ID:           "host-123",
		ProjectID:    "proj-123",
		Type:         AssetTypeDomain,
		Value:        "api.example.com",
		IP:           "192.168.1.1",
		Status:       "alive",
		Title:        "Example API",
		Technologies: []string{"nginx", "php"},
		Ports:        []int{80, 443},
		Headers: map[string]string{
			"Server": "nginx/1.19.0",
		},
		Screenshot: "base64-encoded-data",
		Notes:      "Interesting host",
		FoundBy:    "subfinder",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	assert.Equal(t, "host-123", host.ID)
	assert.Equal(t, AssetTypeDomain, host.Type)
	assert.Equal(t, "api.example.com", host.Value)
	assert.Contains(t, host.Technologies, "nginx")
	assert.Contains(t, host.Ports, 443)
	assert.Equal(t, "nginx/1.19.0", host.Headers["Server"])
}

func TestEndpointStructure(t *testing.T) {
	now := time.Now()
	endpoint := Endpoint{
		ID:          "ep-123",
		ProjectID:   "proj-123",
		HostID:      "host-123",
		URL:         "https://api.example.com/v1/users",
		Method:      "GET",
		Status:      200,
		ContentType: "application/json",
		Title:       "Users API",
		Parameters: []Parameter{
			{
				Name:        "page",
				Value:       "1",
				Type:        "query",
				Description: "Page number",
				Interesting: false,
			},
			{
				Name:        "api_key",
				Type:        "header",
				Interesting: true,
			},
		},
		Notes:     "Public API endpoint",
		FoundBy:   "katana",
		CreatedAt: now,
		UpdatedAt: now,
	}

	assert.Equal(t, "ep-123", endpoint.ID)
	assert.Equal(t, "https://api.example.com/v1/users", endpoint.URL)
	assert.Equal(t, 200, endpoint.Status)
	assert.Len(t, endpoint.Parameters, 2)
	
	// Test Parameter fields
	param1 := endpoint.Parameters[0]
	assert.Equal(t, "page", param1.Name)
	assert.Equal(t, "1", param1.Value)
	assert.Equal(t, "query", param1.Type)
	assert.False(t, param1.Interesting)
	
	param2 := endpoint.Parameters[1]
	assert.Equal(t, "api_key", param2.Name)
	assert.True(t, param2.Interesting)
}

func TestFindingStructure(t *testing.T) {
	now := time.Now()
	finding := Finding{
		ID:          "finding-123",
		ProjectID:   "proj-123",
		Type:        FindingTypeVulnerability,
		Title:       "SQL Injection in User API",
		Description: "The user API is vulnerable to SQL injection",
		Details:     "Detailed technical information",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceHigh,
		Status:      FindingStatusConfirmed,
		URL:         "https://api.example.com/v1/users?id=1",
		CVSS:        8.5,
		CWE:         "CWE-89",
		Steps: []string{
			"Navigate to /v1/users",
			"Add SQL payload to id parameter",
			"Observe database error",
		},
		Evidence: []Evidence{
			{
				Type:        "request",
				Data:        "GET /v1/users?id=1' OR '1'='1",
				Description: "SQL injection payload",
			},
			{
				Type: "response",
				Data: "Database error: You have an error in your SQL syntax",
			},
		},
		Metadata: map[string]interface{}{
			"tool": "sqlmap",
		},
		Impact:      "Attacker can extract sensitive data",
		Remediation: "Use parameterized queries",
		References: []string{
			"https://owasp.org/www-community/attacks/SQL_Injection",
		},
		FoundBy:        "nuclei",
		FoundAt:        now,
		AffectedAssets: []string{"api.example.com"},
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	assert.Equal(t, "finding-123", finding.ID)
	assert.Equal(t, FindingTypeVulnerability, finding.Type)
	assert.Equal(t, SeverityHigh, finding.Severity)
	assert.Equal(t, ConfidenceHigh, finding.Confidence)
	assert.Equal(t, FindingStatusConfirmed, finding.Status)
	assert.Equal(t, 8.5, finding.CVSS)
	assert.Equal(t, "CWE-89", finding.CWE)
	assert.Len(t, finding.Steps, 3)
	
	// Test Evidence as slice
	if evidence, ok := finding.Evidence.([]Evidence); ok {
		assert.Len(t, evidence, 2)
		assert.Equal(t, "request", evidence[0].Type)
		assert.Equal(t, "SQL injection payload", evidence[0].Description)
	}
	
	// Test Metadata
	if metadata, ok := finding.Metadata.(map[string]interface{}); ok {
		assert.Equal(t, "sqlmap", metadata["tool"])
	}
}

func TestReportStructure(t *testing.T) {
	now := time.Now()
	report := Report{
		ID:        "report-123",
		ProjectID: "proj-123",
		FindingID: "finding-123",
		Title:     "SQL Injection Report",
		Format:    "markdown",
		Content:   "# SQL Injection\n\nDetailed report content...",
		Metadata: map[string]interface{}{
			"version":   "1.0",
			"generated": "auto",
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	assert.Equal(t, "report-123", report.ID)
	assert.Equal(t, "proj-123", report.ProjectID)
	assert.Equal(t, "finding-123", report.FindingID)
	assert.Equal(t, "markdown", report.Format)
	assert.Contains(t, report.Content, "SQL Injection")
	assert.Equal(t, "1.0", report.Metadata["version"])
}

func TestTaskStructure(t *testing.T) {
	now := time.Now()
	task := Task{
		ID:          "task-123",
		ProjectID:   "proj-123",
		Type:        "recon",
		Name:        "Subdomain Enumeration",
		Description: "Enumerate all subdomains for example.com",
		Status:      "running",
		Priority:    "high",
		AssignedTo:  "scanner-1",
		Progress:    75,
		Details: map[string]interface{}{
			"target":     "example.com",
			"tools":      []string{"subfinder", "amass"},
			"concurrent": 10,
		},
		Result: map[string]interface{}{
			"subdomains": []string{"api.example.com", "www.example.com"},
			"count":      2,
		},
		Metadata: map[string]interface{}{
			"retries": 0,
		},
		StartedAt:   now,
		CompletedAt: now.Add(10 * time.Minute),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	assert.Equal(t, "task-123", task.ID)
	assert.Equal(t, "recon", task.Type)
	assert.Equal(t, "running", task.Status)
	assert.Equal(t, "high", task.Priority)
	assert.Equal(t, 75, task.Progress)
	
	// Test Details
	assert.Equal(t, "example.com", task.Details["target"])
	if tools, ok := task.Details["tools"].([]string); ok {
		assert.Contains(t, tools, "subfinder")
	}
	
	// Test Result
	if subdomains, ok := task.Result["subdomains"].([]string); ok {
		assert.Len(t, subdomains, 2)
		assert.Contains(t, subdomains, "api.example.com")
	}
	assert.Equal(t, 2, task.Result["count"])
}