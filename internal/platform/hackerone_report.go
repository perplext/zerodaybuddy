package platform

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/perplext/zerodaybuddy/pkg/models"
)

// SubmitReport submits a finding as a report to HackerOne using the Report Intents API.
// It implements the ReportSubmitter interface.
func (h *HackerOne) SubmitReport(ctx context.Context, programHandle string, finding *models.Finding) (string, error) {
	if h.config.APIKey == "" {
		return "", fmt.Errorf("HackerOne API credentials not configured")
	}

	h.logger.Debug("Submitting report to HackerOne program: %s", programHandle)

	// Step 1: Create a report intent
	intentID, err := h.createReportIntent(ctx, programHandle)
	if err != nil {
		return "", fmt.Errorf("failed to create report intent: %w", err)
	}

	// Step 2: Submit the report using the intent
	reportID, err := h.submitReportWithIntent(ctx, intentID, programHandle, finding)
	if err != nil {
		return "", fmt.Errorf("failed to submit report: %w", err)
	}

	h.logger.Debug("Report submitted successfully, ID: %s", reportID)
	return reportID, nil
}

// reportIntentRequest represents the HackerOne Report Intent creation payload.
type reportIntentRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			ProgramHandle string `json:"program_handle"`
		} `json:"attributes"`
	} `json:"data"`
}

// reportIntentResponse represents the response from creating a report intent.
type reportIntentResponse struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Token string `json:"token"`
		} `json:"attributes"`
	} `json:"data"`
}

// createReportIntent creates a new report intent with HackerOne.
func (h *HackerOne) createReportIntent(ctx context.Context, programHandle string) (string, error) {
	payload := reportIntentRequest{}
	payload.Data.Type = "report-intent"
	payload.Data.Attributes.ProgramHandle = programHandle

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/report_intents", h.config.APIUrl)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s",
		base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", h.config.APIKey, h.config.APIKey)))))

	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, respBody)
	}

	var intentResp reportIntentResponse
	if err := json.NewDecoder(resp.Body).Decode(&intentResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return intentResp.Data.ID, nil
}

// reportSubmissionRequest represents the HackerOne report submission payload.
type reportSubmissionRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Title            string `json:"title"`
			VulnerabilityInfo string `json:"vulnerability_information"`
			Impact           string `json:"impact"`
			Severity         struct {
				Rating string `json:"rating"`
			} `json:"severity"`
			WeaknessID string `json:"weakness_id,omitempty"`
		} `json:"attributes"`
		Relationships struct {
			Program struct {
				Data struct {
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"data"`
			} `json:"program"`
		} `json:"relationships"`
	} `json:"data"`
}

// reportSubmissionResponse represents the response from submitting a report.
type reportSubmissionResponse struct {
	Data struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}

// submitReportWithIntent submits the actual report using a report intent.
func (h *HackerOne) submitReportWithIntent(ctx context.Context, intentID, programHandle string, finding *models.Finding) (string, error) {
	payload := reportSubmissionRequest{}
	payload.Data.Type = "report"
	payload.Data.Attributes.Title = finding.Title
	payload.Data.Attributes.VulnerabilityInfo = formatReportBody(finding)
	payload.Data.Attributes.Impact = finding.Impact
	payload.Data.Attributes.Severity.Rating = mapSeverityToHackerOne(finding.Severity)

	if finding.CWE != "" {
		payload.Data.Attributes.WeaknessID = finding.CWE
	}

	payload.Data.Relationships.Program.Data.Type = "program"
	payload.Data.Relationships.Program.Data.ID = programHandle

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/reports", h.config.APIUrl)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s",
		base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", h.config.APIKey, h.config.APIKey)))))

	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, respBody)
	}

	var reportResp reportSubmissionResponse
	if err := json.NewDecoder(resp.Body).Decode(&reportResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return reportResp.Data.ID, nil
}

// formatReportBody formats a Finding into a HackerOne report body.
func formatReportBody(f *models.Finding) string {
	var sb bytes.Buffer
	sb.WriteString("## Summary\n\n")
	sb.WriteString(f.Description)
	sb.WriteString("\n\n")

	if f.Details != "" {
		sb.WriteString("## Details\n\n")
		sb.WriteString(f.Details)
		sb.WriteString("\n\n")
	}

	if len(f.Steps) > 0 {
		sb.WriteString("## Steps to Reproduce\n\n")
		for i, step := range f.Steps {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
		sb.WriteString("\n")
	}

	if f.URL != "" {
		sb.WriteString("## Affected URL\n\n")
		sb.WriteString(f.URL)
		sb.WriteString("\n\n")
	}

	if f.Remediation != "" {
		sb.WriteString("## Recommended Fix\n\n")
		sb.WriteString(f.Remediation)
		sb.WriteString("\n")
	}

	return sb.String()
}

// mapSeverityToHackerOne maps our severity to HackerOne severity rating.
func mapSeverityToHackerOne(severity models.FindingSeverity) string {
	switch severity {
	case models.SeverityCritical:
		return "critical"
	case models.SeverityHigh:
		return "high"
	case models.SeverityMedium:
		return "medium"
	case models.SeverityLow:
		return "low"
	default:
		return "none"
	}
}
