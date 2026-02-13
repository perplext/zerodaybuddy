package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// GitHubConfig holds configuration for GitHub Issues integration.
type GitHubConfig struct {
	Token string
	Owner string
	Repo  string
}

// GitHubIssueCreator creates GitHub issues from confirmed findings.
type GitHubIssueCreator struct {
	config GitHubConfig
	logger *utils.Logger
	client *http.Client
}

// NewGitHubIssueCreator creates a new GitHub issue creator.
func NewGitHubIssueCreator(cfg GitHubConfig, logger *utils.Logger) *GitHubIssueCreator {
	return &GitHubIssueCreator{
		config: cfg,
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// githubIssueRequest represents the GitHub API create issue payload.
type githubIssueRequest struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels,omitempty"`
}

// githubIssueResponse represents the GitHub API issue response.
type githubIssueResponse struct {
	ID      int    `json:"id"`
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
}

// CreateIssueFromFinding creates a GitHub issue from a confirmed finding.
// Only findings with status "confirmed" should be submitted.
func (g *GitHubIssueCreator) CreateIssueFromFinding(ctx context.Context, finding *models.Finding) (string, error) {
	if g.config.Token == "" {
		return "", fmt.Errorf("GitHub token not configured")
	}

	if finding.Status != models.FindingStatusConfirmed {
		return "", fmt.Errorf("only confirmed findings can be submitted as issues (current status: %s)", finding.Status)
	}

	g.logger.Debug("Creating GitHub issue for finding: %s", finding.Title)

	payload := githubIssueRequest{
		Title:  formatIssueTitle(finding),
		Body:   formatIssueBody(finding),
		Labels: issueLabels(finding),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", g.config.Owner, g.config.Repo)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", g.config.Token))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, respBody)
	}

	var issueResp githubIssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&issueResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	g.logger.Debug("GitHub issue created: %s", issueResp.HTMLURL)
	return issueResp.HTMLURL, nil
}

// formatIssueTitle creates a GitHub issue title from a finding.
func formatIssueTitle(f *models.Finding) string {
	severity := string(f.Severity)
	if severity == "" {
		severity = "unknown"
	}
	return fmt.Sprintf("[%s] %s", severity, f.Title)
}

// formatIssueBody creates a GitHub issue body from a finding.
func formatIssueBody(f *models.Finding) string {
	var sb bytes.Buffer

	sb.WriteString("## Security Finding\n\n")

	sb.WriteString(fmt.Sprintf("**Severity:** %s\n", f.Severity))
	if f.CVSS > 0 {
		sb.WriteString(fmt.Sprintf("**CVSS Score:** %.1f", f.CVSS))
		if f.CVSSVersion != "" {
			sb.WriteString(fmt.Sprintf(" (v%s)", f.CVSSVersion))
		}
		sb.WriteString("\n")
	}
	if f.CWE != "" {
		sb.WriteString(fmt.Sprintf("**CWE:** %s\n", f.CWE))
	}
	sb.WriteString(fmt.Sprintf("**Found by:** %s\n", f.FoundBy))
	sb.WriteString(fmt.Sprintf("**Found at:** %s\n\n", f.FoundAt.Format(time.RFC3339)))

	sb.WriteString("## Description\n\n")
	sb.WriteString(f.Description)
	sb.WriteString("\n\n")

	if f.Details != "" {
		sb.WriteString("## Details\n\n")
		sb.WriteString(f.Details)
		sb.WriteString("\n\n")
	}

	if f.URL != "" {
		sb.WriteString("## Affected URL\n\n")
		sb.WriteString(fmt.Sprintf("`%s`\n\n", f.URL))
	}

	if len(f.AffectedAssets) > 0 {
		sb.WriteString("## Affected Assets\n\n")
		for _, asset := range f.AffectedAssets {
			sb.WriteString(fmt.Sprintf("- `%s`\n", asset))
		}
		sb.WriteString("\n")
	}

	if len(f.Steps) > 0 {
		sb.WriteString("## Steps to Reproduce\n\n")
		for i, step := range f.Steps {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
		sb.WriteString("\n")
	}

	if f.Impact != "" {
		sb.WriteString("## Impact\n\n")
		sb.WriteString(f.Impact)
		sb.WriteString("\n\n")
	}

	if f.Remediation != "" {
		sb.WriteString("## Remediation\n\n")
		sb.WriteString(f.Remediation)
		sb.WriteString("\n\n")
	}

	if len(f.References) > 0 {
		sb.WriteString("## References\n\n")
		for _, ref := range f.References {
			sb.WriteString(fmt.Sprintf("- %s\n", ref))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("---\n")
	sb.WriteString("*Created by ZeroDayBuddy*\n")

	return sb.String()
}

// issueLabels generates GitHub labels for a finding.
func issueLabels(f *models.Finding) []string {
	labels := []string{"security"}

	switch f.Severity {
	case models.SeverityCritical:
		labels = append(labels, "severity:critical")
	case models.SeverityHigh:
		labels = append(labels, "severity:high")
	case models.SeverityMedium:
		labels = append(labels, "severity:medium")
	case models.SeverityLow:
		labels = append(labels, "severity:low")
	}

	if f.FoundBy != "" {
		labels = append(labels, fmt.Sprintf("scanner:%s", f.FoundBy))
	}

	return labels
}
