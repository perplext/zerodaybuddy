package scan

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/perplext/zerodaybuddy/internal/recon"
	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"golang.org/x/sync/semaphore"
)

// internalCIDRs are IP ranges that must never be scanned (SSRF protection).
var internalCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",     // loopback
		"10.0.0.0/8",      // RFC 1918
		"172.16.0.0/12",   // RFC 1918
		"192.168.0.0/16",  // RFC 1918
		"169.254.0.0/16",  // link-local / cloud metadata
		"::1/128",         // IPv6 loopback
		"fc00::/7",        // IPv6 ULA
		"fe80::/10",       // IPv6 link-local
	} {
		_, network, _ := net.ParseCIDR(cidr)
		internalCIDRs = append(internalCIDRs, network)
	}
}

// isInternalHost returns true if the hostname resolves to a private/internal IP.
func isInternalHost(hostname string) bool {
	ips, err := net.LookupHost(hostname)
	if err != nil {
		return true // fail closed — if we can't resolve, block it
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, cidr := range internalCIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// filterSSRFURLs removes URLs that resolve to internal/private IPs.
func filterSSRFURLs(urls []string, logger *utils.Logger) []string {
	var safe []string
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			logger.Warn("Skipping malformed URL: %s", u)
			continue
		}
		hostname := parsed.Hostname()
		if isInternalHost(hostname) {
			logger.Warn("Blocked SSRF attempt — %s resolves to internal IP", hostname)
			continue
		}
		safe = append(safe, u)
	}
	return safe
}

// Service provides vulnerability scanning functionality
type Service struct {
	store  interface {
		GetProject(ctx context.Context, id string) (*models.Project, error)
		GetHost(ctx context.Context, id string) (*models.Host, error)
		GetEndpoint(ctx context.Context, id string) (*models.Endpoint, error)
		ListHosts(ctx context.Context, projectID string) ([]*models.Host, error)
		ListEndpoints(ctx context.Context, hostID string) ([]*models.Endpoint, error)
		ListEndpointsByProject(ctx context.Context, projectID string) ([]*models.Endpoint, error)
		CreateFinding(ctx context.Context, finding *models.Finding) error
		CreateTask(ctx context.Context, task *models.Task) error
		UpdateTask(ctx context.Context, task *models.Task) error
	}
	config config.Config
	logger *utils.Logger
	scannerFactory ScannerFactory
}

// NewService creates a new scanning service
func NewService(store interface {
	GetProject(ctx context.Context, id string) (*models.Project, error)
	GetHost(ctx context.Context, id string) (*models.Host, error)
	GetEndpoint(ctx context.Context, id string) (*models.Endpoint, error)
	ListHosts(ctx context.Context, projectID string) ([]*models.Host, error)
	ListEndpoints(ctx context.Context, hostID string) ([]*models.Endpoint, error)
	ListEndpointsByProject(ctx context.Context, projectID string) ([]*models.Endpoint, error)
	CreateFinding(ctx context.Context, finding *models.Finding) error
	CreateTask(ctx context.Context, task *models.Task) error
	UpdateTask(ctx context.Context, task *models.Task) error
}, config config.Config, logger *utils.Logger) *Service {
	return &Service{
		store:  store,
		config: config,
		logger: logger,
		scannerFactory: recon.NewScannerFactory(config, logger),
	}
}

// ScanTarget scans a target for vulnerabilities
func (s *Service) ScanTarget(ctx context.Context, projectID string, target string, concurrency int) error {
	// Validate inputs
	if projectID == "" {
		return fmt.Errorf("project ID is required")
	}
	
	if concurrency < 1 || concurrency > 100 {
		return fmt.Errorf("concurrency must be between 1 and 100")
	}
	
	// Get the project
	project, err := s.store.GetProject(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	
	// Create a task to track the scan
	task := &models.Task{
		ProjectID:   projectID,
		Type:        "scan",
		Status:      "running",
		Description: fmt.Sprintf("Vulnerability scan of %s", target),
		StartedAt:   time.Now(),
		Progress:    0,
	}
	
	if err := s.store.CreateTask(ctx, task); err != nil {
		return fmt.Errorf("failed to create scan task: %w", err)
	}
	
	// Ensure task is marked as completed or failed
	defer func() {
		task.CompletedAt = time.Now()
		if task.Status == "running" {
			task.Status = "completed"
			task.Progress = 100
		}
		if updateErr := s.store.UpdateTask(ctx, task); updateErr != nil {
			s.logger.Error("Failed to update task status: %v", updateErr)
		}
	}()
	
	// Determine what to scan based on the target
	var scanErr error
	switch {
	case target == "all" || target == "":
		// Scan all discovered endpoints
		scanErr = s.scanAllEndpoints(ctx, project, task, concurrency)
	case strings.HasPrefix(target, "host:"):
		// Scan specific host
		hostID := strings.TrimPrefix(target, "host:")
		scanErr = s.scanHost(ctx, project, hostID, task, concurrency)
	case strings.HasPrefix(target, "endpoint:"):
		// Scan specific endpoint
		endpointID := strings.TrimPrefix(target, "endpoint:")
		scanErr = s.scanEndpoint(ctx, project, endpointID, task)
	default:
		// Assume it's a URL or hostname
		scanErr = s.scanURL(ctx, project, target, task)
	}
	
	if scanErr != nil {
		task.Status = "failed"
		// Store error in result
		task.Result = map[string]interface{}{"error": scanErr.Error()}
		return scanErr
	}
	
	return nil
}

// scanAllEndpoints scans all discovered endpoints in the project
func (s *Service) scanAllEndpoints(ctx context.Context, project *models.Project, task *models.Task, concurrency int) error {
	endpoints, err := s.store.ListEndpointsByProject(ctx, project.ID)
	if err != nil {
		return fmt.Errorf("failed to list endpoints: %w", err)
	}
	
	if len(endpoints) == 0 {
		s.logger.Info("No endpoints found to scan")
		return nil
	}
	
	s.logger.Info("Starting vulnerability scan for %d endpoints", len(endpoints))
	
	// Collect URLs from endpoints
	var urls []string
	for _, endpoint := range endpoints {
		// URLs are already stored as full URLs in endpoints
		if endpoint.URL != "" {
			urls = append(urls, endpoint.URL)
		}
	}
	
	if len(urls) == 0 {
		s.logger.Info("No HTTP/HTTPS endpoints to scan")
		return nil
	}
	
	// Run nuclei scan with concurrency control
	return s.runNucleiScan(ctx, project, urls, task, concurrency)
}

// scanHost scans all endpoints for a specific host
func (s *Service) scanHost(ctx context.Context, project *models.Project, hostID string, task *models.Task, concurrency int) error {
	host, err := s.store.GetHost(ctx, hostID)
	if err != nil {
		return fmt.Errorf("failed to get host: %w", err)
	}
	
	if host.ProjectID != project.ID {
		return fmt.Errorf("host does not belong to project")
	}
	
	endpoints, err := s.store.ListEndpointsByProject(ctx, project.ID)
	if err != nil {
		return fmt.Errorf("failed to list endpoints: %w", err)
	}

	// Filter endpoints for this host
	var urls []string
	for _, endpoint := range endpoints {
		if endpoint.HostID == host.ID && endpoint.URL != "" {
			urls = append(urls, endpoint.URL)
		}
	}
	
	if len(urls) == 0 {
		s.logger.Info("No HTTP/HTTPS endpoints found for host %s", host.Value)
		return nil
	}
	
	s.logger.Info("Scanning %d endpoints for host %s", len(urls), host.Value)
	return s.runNucleiScan(ctx, project, urls, task, concurrency)
}

// scanEndpoint scans a specific endpoint
func (s *Service) scanEndpoint(ctx context.Context, project *models.Project, endpointID string, task *models.Task) error {
	endpoint, err := s.store.GetEndpoint(ctx, endpointID)
	if err != nil {
		return fmt.Errorf("failed to get endpoint: %w", err)
	}
	
	if endpoint.ProjectID != project.ID {
		return fmt.Errorf("endpoint does not belong to project")
	}
	
	// Check if endpoint is HTTP/HTTPS
	if !strings.HasPrefix(endpoint.URL, "http://") && !strings.HasPrefix(endpoint.URL, "https://") {
		return fmt.Errorf("can only scan HTTP/HTTPS endpoints")
	}
	
	s.logger.Info("Scanning endpoint: %s", endpoint.URL)
	
	return s.runNucleiScan(ctx, project, []string{endpoint.URL}, task, 1)
}

// scanURL scans a specific URL
func (s *Service) scanURL(ctx context.Context, project *models.Project, target string, task *models.Task) error {
	// Validate the URL format
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		// Try adding https://
		target = "https://" + target
	}
	
	// Check if URL is in scope
	if !project.Scope.IsInScope(models.AssetTypeURL, target) {
		return fmt.Errorf("URL is not in project scope")
	}
	
	s.logger.Info("Scanning URL: %s", target)
	return s.runNucleiScan(ctx, project, []string{target}, task, 1)
}

// runNucleiScan executes nuclei scanner on the given URLs
func (s *Service) runNucleiScan(ctx context.Context, project *models.Project, urls []string, task *models.Task, concurrency int) error {
	if len(urls) == 0 {
		return nil
	}

	// SSRF protection — drop URLs that resolve to internal IPs
	urls = filterSSRFURLs(urls, s.logger)
	if len(urls) == 0 {
		s.logger.Info("No external URLs remain after SSRF filtering")
		return nil
	}
	
	// Get the nuclei scanner
	scanner, err := s.scannerFactory.GetScanner("nuclei")
	if err != nil {
		return fmt.Errorf("failed to get nuclei scanner: %w", err)
	}
	
	// Prepare scan options
	options := map[string]interface{}{
		"templates": "technologies,exposures,misconfigurations,cves,vulnerabilities",
		"severity":  "low,medium,high,critical",
	}
	
	// Use semaphore for concurrency control when scanning multiple URLs
	sem := semaphore.NewWeighted(int64(concurrency))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var totalFindings int
	var scanErrors []error
	
	// Process URLs in batches
	batchSize := 50 // Process 50 URLs at a time
	for i := 0; i < len(urls); i += batchSize {
		end := i + batchSize
		if end > len(urls) {
			end = len(urls)
		}
		batch := urls[i:end]
		
		// Acquire semaphore
		if err := sem.Acquire(ctx, 1); err != nil {
			return fmt.Errorf("failed to acquire semaphore: %w", err)
		}
		
		wg.Add(1)
		go func(batch []string, batchIndex int) {
			defer wg.Done()
			defer sem.Release(1)
			
			// Run nuclei on this batch
			result, err := scanner.Scan(ctx, project, batch, options)
			if err != nil {
				mu.Lock()
				scanErrors = append(scanErrors, err)
				mu.Unlock()
				return
			}
			
			// Process results
			if results, ok := result.([]recon.NucleiResult); ok {
				mu.Lock()
				for _, finding := range results {
					if err := s.processFinding(ctx, project, finding); err != nil {
						s.logger.Error("Failed to process finding: %v", err)
					} else {
						totalFindings++
					}
				}
				
				// Update task progress
				progress := float64(batchIndex+batchSize) / float64(len(urls)) * 100
				if progress > 100 {
					progress = 100
				}
				task.Progress = int(progress)
				task.Metadata = map[string]interface{}{
					"urls_scanned":    batchIndex + len(batch),
					"total_urls":      len(urls),
					"findings_found":  totalFindings,
				}
				mu.Unlock()
				
				// Update task in storage
				if err := s.store.UpdateTask(ctx, task); err != nil {
					s.logger.Error("Failed to update task progress: %v", err)
				}
			}
		}(batch, i)
	}
	
	// Wait for all scans to complete
	wg.Wait()
	
	// Check for errors
	if len(scanErrors) > 0 {
		return fmt.Errorf("vulnerability scan failed: %w", scanErrors[0])
	}
	
	s.logger.Info("Vulnerability scan completed. Found %d findings across %d URLs", totalFindings, len(urls))
	
	return nil
}

// processFinding converts a nuclei result to a finding and stores it
func (s *Service) processFinding(ctx context.Context, project *models.Project, result recon.NucleiResult) error {
	// Map nuclei severity to our severity model
	severity := models.SeverityMedium
	switch strings.ToLower(result.Severity) {
	case "critical":
		severity = models.SeverityCritical
	case "high":
		severity = models.SeverityHigh
	case "medium":
		severity = models.SeverityMedium
	case "low":
		severity = models.SeverityLow
	case "info", "informational":
		severity = models.SeverityInfo
	}
	
	// Build evidence
	evidence := map[string]interface{}{
		"template_id":    result.TemplateID,
		"matcher_name":   result.MatcherName,
		"matched_at":     result.MatchedAt,
		"curl_command":   result.CurlCommand,
		"extracted_data": result.ExtractedData,
		"ip":             result.IP,
	}
	
	// Build metadata
	metadata := map[string]interface{}{
		"authors":     result.Info.Authors,
		"tags":        result.Info.Tags,
		"references":  result.Info.Reference,
		"template_id": result.TemplateID,
	}
	
	if result.Info.Classification.CVEIDs != nil {
		metadata["cve_ids"] = result.Info.Classification.CVEIDs
	}
	if result.Info.Classification.CVSSScore != "" {
		metadata["cvss_score"] = result.Info.Classification.CVSSScore
	}
	
	// Parse timestamp
	foundAt, err := time.Parse(time.RFC3339, result.Timestamp)
	if err != nil {
		foundAt = time.Now()
	}
	
	// Extract affected URL's domain for affected assets
	affectedAssets := []string{}
	if parsedURL, err := url.Parse(result.Host); err == nil && parsedURL.Host != "" {
		affectedAssets = append(affectedAssets, parsedURL.Host)
	}
	
	// Create the finding
	finding := &models.Finding{
		ProjectID:   project.ID,
		Type:        models.FindingTypeVulnerability,
		Title:       result.Info.Name,
		Description: result.Info.Description,
		Severity:    severity,
		Confidence:  models.ConfidenceHigh, // Nuclei findings are generally high confidence
		Status:      models.FindingStatusNew,
		URL:         result.Host,
		Evidence:    evidence,
		Metadata:    metadata,
		FoundAt:     foundAt,
		FoundBy:     "nuclei",
		AffectedAssets: affectedAssets,
	}
	
	return s.store.CreateFinding(ctx, finding)
}