package models

// ReportType represents the type of a report
type ReportType string

const (
	// ReportTypeProject is a report about a project
	ReportTypeProject ReportType = "project"
	// ReportTypeFinding is a report about a finding
	ReportTypeFinding ReportType = "finding"
)
