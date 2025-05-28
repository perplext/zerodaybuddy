package recon

import (
	"context"
	"fmt"
	"sync"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/google/uuid"
)

// Results represents the results of reconnaissance
type Results struct {
	Subdomains []string
	LiveHosts  []*models.Host
	Endpoints  []*models.Endpoint
	Findings   []*models.Finding
}

// Service provides reconnaissance functionality
type Service struct {
	store        interface {
		CreateHost(ctx context.Context, host *models.Host) error
		GetHost(ctx context.Context, id string) (*models.Host, error)
		UpdateHost(ctx context.Context, host *models.Host) error
		ListHosts(ctx context.Context, projectID string) ([]*models.Host, error)
		CreateEndpoint(ctx context.Context, endpoint *models.Endpoint) error
		CreateFinding(ctx context.Context, finding *models.Finding) error
		CreateTask(ctx context.Context, task *models.Task) error
		UpdateTask(ctx context.Context, task *models.Task) error
	}
	config    config.ToolsConfig
	logger    *utils.Logger
	scanners  map[string]Scanner
	semaphore chan struct{}
}

// We're not defining Scanner here anymore as it's defined in scanner.go

// NewService creates a new reconnaissance service
func NewService(store interface {
	CreateHost(ctx context.Context, host *models.Host) error
	GetHost(ctx context.Context, id string) (*models.Host, error)
	UpdateHost(ctx context.Context, host *models.Host) error
	ListHosts(ctx context.Context, projectID string) ([]*models.Host, error)
	CreateEndpoint(ctx context.Context, endpoint *models.Endpoint) error
	CreateFinding(ctx context.Context, finding *models.Finding) error
	CreateTask(ctx context.Context, task *models.Task) error
	UpdateTask(ctx context.Context, task *models.Task) error
}, config config.ToolsConfig, logger *utils.Logger) *Service {
	service := &Service{
		store:     store,
		config:    config,
		logger:    logger,
		scanners:  make(map[string]Scanner),
		semaphore: make(chan struct{}, config.MaxThreads),
	}
	
	// Register scanners
	service.registerScanners()
	
	return service
}

// SetConcurrency sets the maximum number of concurrent tasks
func (s *Service) SetConcurrency(max int) {
	if max <= 0 {
		max = s.config.MaxThreads
	}
	
	// Create a new semaphore
	s.semaphore = make(chan struct{}, max)
}

// registerScanners registers all available scanners
func (s *Service) registerScanners() {
	// Use a scanner factory to manage scanner instances
	factory := NewScannerFactory(config.Config{Tools: s.config}, s.logger)
	
	// Get all scanners from the factory
	for _, scanner := range factory.ListScanners() {
		s.scanners[scanner.Name()] = scanner
	}
}

// ListScanners returns a list of all registered scanners
func (s *Service) ListScanners() []Scanner {
	scanners := make([]Scanner, 0, len(s.scanners))
	for _, scanner := range s.scanners {
		scanners = append(scanners, scanner)
	}
	return scanners
}

// RunAll runs all reconnaissance steps for a project
func (s *Service) RunAll(ctx context.Context, project *models.Project) (*Results, error) {
	s.logger.Info("Running all reconnaissance steps for project %s", project.Name)
	
	// Create a task to track progress
	task := &models.Task{
		ID:        uuid.New().String(),
		ProjectID: project.ID,
		Type:      "recon",
		Status:    "running",
		Progress:  0,
		Details: map[string]interface{}{
			"step": "starting",
		},
		StartedAt: utils.CurrentTime(),
		CreatedAt: utils.CurrentTime(),
		UpdatedAt: utils.CurrentTime(),
	}
	
	if err := s.store.CreateTask(ctx, task); err != nil {
		return nil, fmt.Errorf("failed to create task: %w", err)
	}
	
	results := &Results{
		Subdomains: make([]string, 0),
		LiveHosts:  make([]*models.Host, 0),
		Endpoints:  make([]*models.Endpoint, 0),
		Findings:   make([]*models.Finding, 0),
	}
	
	// Step 1: Subdomain discovery
	task.Details["step"] = "subdomain_discovery"
	task.Progress = 10
	if err := s.store.UpdateTask(ctx, task); err != nil {
		s.logger.Error("Failed to update task: %v", err)
	}
	
	domains := s.extractDomains(project)
	if len(domains) == 0 {
		s.logger.Warn("No domains found in project scope")
	} else {
		s.logger.Info("Discovering subdomains for %d root domains", len(domains))
		
		// Run subdomain discovery scanners
		for _, domain := range domains {
			subdomains, err := s.discoverSubdomains(ctx, project, domain)
			if err != nil {
				s.logger.Error("Failed to discover subdomains for %s: %v", domain, err)
				continue
			}
			
			results.Subdomains = append(results.Subdomains, subdomains...)
		}
		
		s.logger.Info("Discovered %d subdomains", len(results.Subdomains))
	}
	
	// Step 2: HTTP probing
	task.Details["step"] = "http_probing"
	task.Progress = 30
	if err := s.store.UpdateTask(ctx, task); err != nil {
		s.logger.Error("Failed to update task: %v", err)
	}
	
	if len(results.Subdomains) > 0 {
		s.logger.Info("Probing %d hosts for HTTP services", len(results.Subdomains))
		
		hosts, err := s.probeHosts(ctx, project, results.Subdomains)
		if err != nil {
			s.logger.Error("Failed to probe hosts: %v", err)
		} else {
			results.LiveHosts = append(results.LiveHosts, hosts...)
			s.logger.Info("Found %d live HTTP hosts", len(hosts))
		}
	}
	
	// Step 3: Port scanning (if configured)
	task.Details["step"] = "port_scanning"
	task.Progress = 50
	if err := s.store.UpdateTask(ctx, task); err != nil {
		s.logger.Error("Failed to update task: %v", err)
	}
	
	// Get IP targets from scope
	ipTargets := s.extractIPs(project)
	if len(ipTargets) > 0 {
		s.logger.Info("Scanning ports for %d IP targets", len(ipTargets))
		
		// Run port scanning
		ips, err := s.scanPorts(ctx, project, ipTargets)
		if err != nil {
			s.logger.Error("Failed to scan ports: %v", err)
		} else {
			// Add IP hosts to results
			results.LiveHosts = append(results.LiveHosts, ips...)
			s.logger.Info("Found %d live IP hosts with open ports", len(ips))
		}
	}
	
	// Step 4: Content discovery
	task.Details["step"] = "content_discovery"
	task.Progress = 70
	if err := s.store.UpdateTask(ctx, task); err != nil {
		s.logger.Error("Failed to update task: %v", err)
	}
	
	if len(results.LiveHosts) > 0 {
		s.logger.Info("Discovering content on %d hosts", len(results.LiveHosts))
		
		for _, host := range results.LiveHosts {
			// Skip non-web hosts
			if !isWebHost(host) {
				continue
			}
			
			endpoints, err := s.discoverEndpoints(ctx, project, host)
			if err != nil {
				s.logger.Error("Failed to discover endpoints for %s: %v", host.Value, err)
				continue
			}
			
			results.Endpoints = append(results.Endpoints, endpoints...)
		}
		
		s.logger.Info("Discovered %d endpoints", len(results.Endpoints))
	}
	
	// Step 5: Directory brute force
	task.Details["step"] = "directory_brute_force"
	task.Progress = 90
	if err := s.store.UpdateTask(ctx, task); err != nil {
		s.logger.Error("Failed to update task: %v", err)
	}
	
	if len(results.LiveHosts) > 0 {
		s.logger.Info("Brute forcing directories on %d hosts", len(results.LiveHosts))
		
		for _, host := range results.LiveHosts {
			// Skip non-web hosts
			if !isWebHost(host) {
				continue
			}
			
			endpoints, err := s.bruteForceDirectories(ctx, project, host)
			if err != nil {
				s.logger.Error("Failed to brute force directories for %s: %v", host.Value, err)
				continue
			}
			
			results.Endpoints = append(results.Endpoints, endpoints...)
		}
		
		s.logger.Info("Discovered %d additional endpoints via brute force", len(results.Endpoints))
	}
	
	// Update task status
	task.Status = "completed"
	task.Progress = 100
	task.CompletedAt = utils.CurrentTime()
	task.Details["step"] = "completed"
	task.Result = map[string]interface{}{
		"subdomains": len(results.Subdomains),
		"hosts":      len(results.LiveHosts),
		"endpoints":  len(results.Endpoints),
		"findings":   len(results.Findings),
	}
	
	if err := s.store.UpdateTask(ctx, task); err != nil {
		s.logger.Error("Failed to update task: %v", err)
	}
	
	s.logger.Info("Reconnaissance completed for project %s", project.Name)
	
	return results, nil
}

// RunSubdomainDiscovery runs subdomain discovery for a project
func (s *Service) RunSubdomainDiscovery(ctx context.Context, project *models.Project) ([]string, error) {
	s.logger.Info("Running subdomain discovery for project %s", project.Name)
	
	domains := s.extractDomains(project)
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains found in project scope")
	}
	
	var subdomains []string
	for _, domain := range domains {
		discovered, err := s.discoverSubdomains(ctx, project, domain)
		if err != nil {
			s.logger.Error("Failed to discover subdomains for %s: %v", domain, err)
			continue
		}
		
		subdomains = append(subdomains, discovered...)
	}
	
	s.logger.Info("Discovered %d subdomains", len(subdomains))
	
	return subdomains, nil
}

// RunHTTPProbing runs HTTP probing for a project
func (s *Service) RunHTTPProbing(ctx context.Context, project *models.Project, hosts []string) ([]*models.Host, error) {
	s.logger.Info("Running HTTP probing for project %s on %d hosts", project.Name, len(hosts))
	
	// Run HTTP probing
	return s.probeHosts(ctx, project, hosts)
}

// RunPortScanning runs port scanning for a project
func (s *Service) RunPortScanning(ctx context.Context, project *models.Project, targets []string) ([]*models.Host, error) {
	s.logger.Info("Running port scanning for project %s on %d targets", project.Name, len(targets))
	
	// Run port scanning
	return s.scanPorts(ctx, project, targets)
}

// RunContentDiscovery runs content discovery for a project
func (s *Service) RunContentDiscovery(ctx context.Context, project *models.Project, host *models.Host) ([]*models.Endpoint, error) {
	s.logger.Info("Running content discovery for project %s on host %s", project.Name, host.Value)
	
	// Skip non-web hosts
	if !isWebHost(host) {
		return nil, fmt.Errorf("host is not a web host")
	}
	
	// Run content discovery
	return s.discoverEndpoints(ctx, project, host)
}

// RunDirectoryBruteForce runs directory brute force for a project
func (s *Service) RunDirectoryBruteForce(ctx context.Context, project *models.Project, host *models.Host) ([]*models.Endpoint, error) {
	s.logger.Info("Running directory brute force for project %s on host %s", project.Name, host.Value)
	
	// Skip non-web hosts
	if !isWebHost(host) {
		return nil, fmt.Errorf("host is not a web host")
	}
	
	// Run directory brute force
	return s.bruteForceDirectories(ctx, project, host)
}

// extractDomains extracts domain targets from project scope
func (s *Service) extractDomains(project *models.Project) []string {
	domains := make([]string, 0)
	
	for _, asset := range project.Scope.InScope {
		if asset.Type == models.AssetTypeDomain {
			domains = append(domains, asset.Value)
		}
	}
	
	return utils.UniqueStrings(domains)
}

// extractIPs extracts IP targets from project scope
func (s *Service) extractIPs(project *models.Project) []string {
	ips := make([]string, 0)
	
	for _, asset := range project.Scope.InScope {
		if asset.Type == models.AssetTypeIP {
			ips = append(ips, asset.Value)
		}
	}
	
	return utils.UniqueStrings(ips)
}

// discoverSubdomains discovers subdomains for a domain
func (s *Service) discoverSubdomains(ctx context.Context, project *models.Project, domain string) ([]string, error) {
	s.logger.Debug("Discovering subdomains for domain %s", domain)
	
	var allSubdomains []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Use both subfinder and amass for discovery
	scanners := []string{"subfinder", "amass"}
	
	for _, scannerName := range scanners {
		scanner, ok := s.scanners[scannerName]
		if !ok {
			s.logger.Warn("Scanner %s not found", scannerName)
			continue
		}
		
		wg.Add(1)
		go func(scanner Scanner, domain string) {
			defer wg.Done()
			
			// Acquire semaphore
			s.semaphore <- struct{}{}
			defer func() { <-s.semaphore }()
			
			s.logger.Debug("Running %s for domain %s", scanner.Name(), domain)
			
			result, err := scanner.Scan(ctx, project, domain, nil)
			if err != nil {
				s.logger.Error("Failed to run %s for domain %s: %v", scanner.Name(), domain, err)
				return
			}
			
			subdomains, ok := result.([]string)
			if !ok {
				s.logger.Error("Unexpected result type from %s: %T", scanner.Name(), result)
				return
			}
			
			// Filter subdomains for scope
			var inScope []string
			for _, subdomain := range subdomains {
				if project.Scope.IsInScope(models.AssetTypeDomain, subdomain) {
					inScope = append(inScope, subdomain)
				}
			}
			
			s.logger.Debug("%s found %d subdomains (%d in scope) for domain %s", 
				scanner.Name(), len(subdomains), len(inScope), domain)
			
			// Add to all subdomains
			mu.Lock()
			allSubdomains = append(allSubdomains, inScope...)
			mu.Unlock()
		}(scanner, domain)
	}
	
	wg.Wait()
	
	// Deduplicate subdomains
	return utils.UniqueStrings(allSubdomains), nil
}

// probeHosts probes hosts for HTTP services
func (s *Service) probeHosts(ctx context.Context, project *models.Project, hosts []string) ([]*models.Host, error) {
	s.logger.Debug("Probing %d hosts for HTTP services", len(hosts))
	
	scanner, ok := s.scanners["httpx"]
	if !ok {
		return nil, fmt.Errorf("HTTP prober not found")
	}
	
	// Acquire semaphore
	s.semaphore <- struct{}{}
	defer func() { <-s.semaphore }()
	
	// Run HTTP probing
	result, err := scanner.Scan(ctx, project, hosts, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to probe hosts: %w", err)
	}
	
	discoveredHosts, ok := result.([]*models.Host)
	if !ok {
		return nil, fmt.Errorf("unexpected result type: %T", result)
	}
	
	// Save hosts to storage
	for _, host := range discoveredHosts {
		if err := s.store.CreateHost(ctx, host); err != nil {
			s.logger.Error("Failed to save host %s: %v", host.Value, err)
		}
	}
	
	return discoveredHosts, nil
}

// scanPorts scans ports for targets
func (s *Service) scanPorts(ctx context.Context, project *models.Project, targets []string) ([]*models.Host, error) {
	s.logger.Debug("Scanning ports for %d targets", len(targets))
	
	scanner, ok := s.scanners["naabu"]
	if !ok {
		return nil, fmt.Errorf("port scanner not found")
	}
	
	// Acquire semaphore
	s.semaphore <- struct{}{}
	defer func() { <-s.semaphore }()
	
	// Run port scanning
	result, err := scanner.Scan(ctx, project, targets, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to scan ports: %w", err)
	}
	
	discoveredHosts, ok := result.([]*models.Host)
	if !ok {
		return nil, fmt.Errorf("unexpected result type: %T", result)
	}
	
	// Save hosts to storage
	for _, host := range discoveredHosts {
		if err := s.store.CreateHost(ctx, host); err != nil {
			s.logger.Error("Failed to save host %s: %v", host.Value, err)
		}
	}
	
	return discoveredHosts, nil
}

// discoverEndpoints discovers endpoints for a host
func (s *Service) discoverEndpoints(ctx context.Context, project *models.Project, host *models.Host) ([]*models.Endpoint, error) {
	s.logger.Debug("Discovering endpoints for host %s", host.Value)
	
	var allEndpoints []*models.Endpoint
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Use both katana and waybackurls for discovery
	scanners := []string{"katana", "waybackurls"}
	
	for _, scannerName := range scanners {
		scanner, ok := s.scanners[scannerName]
		if !ok {
			s.logger.Warn("Scanner %s not found", scannerName)
			continue
		}
		
		wg.Add(1)
		go func(scanner Scanner, host *models.Host) {
			defer wg.Done()
			
			// Acquire semaphore
			s.semaphore <- struct{}{}
			defer func() { <-s.semaphore }()
			
			s.logger.Debug("Running %s for host %s", scanner.Name(), host.Value)
			
			result, err := scanner.Scan(ctx, project, host, nil)
			if err != nil {
				s.logger.Error("Failed to run %s for host %s: %v", scanner.Name(), host.Value, err)
				return
			}
			
			endpoints, ok := result.([]*models.Endpoint)
			if !ok {
				s.logger.Error("Unexpected result type from %s: %T", scanner.Name(), result)
				return
			}
			
			s.logger.Debug("%s found %d endpoints for host %s", scanner.Name(), len(endpoints), host.Value)
			
			// Save endpoints to storage
			for _, endpoint := range endpoints {
				if err := s.store.CreateEndpoint(ctx, endpoint); err != nil {
					s.logger.Error("Failed to save endpoint %s: %v", endpoint.URL, err)
				}
			}
			
			// Add to all endpoints
			mu.Lock()
			allEndpoints = append(allEndpoints, endpoints...)
			mu.Unlock()
		}(scanner, host)
	}
	
	wg.Wait()
	
	return allEndpoints, nil
}

// bruteForceDirectories performs directory brute forcing for a host
func (s *Service) bruteForceDirectories(ctx context.Context, project *models.Project, host *models.Host) ([]*models.Endpoint, error) {
	s.logger.Debug("Brute forcing directories for host %s", host.Value)
	
	scanner, ok := s.scanners["ffuf"]
	if !ok {
		return nil, fmt.Errorf("directory brute forcer not found")
	}
	
	// Acquire semaphore
	s.semaphore <- struct{}{}
	defer func() { <-s.semaphore }()
	
	// Run directory brute forcing
	result, err := scanner.Scan(ctx, project, host, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to brute force directories: %w", err)
	}
	
	endpoints, ok := result.([]*models.Endpoint)
	if !ok {
		return nil, fmt.Errorf("unexpected result type: %T", result)
	}
	
	// Save endpoints to storage
	for _, endpoint := range endpoints {
		if err := s.store.CreateEndpoint(ctx, endpoint); err != nil {
			s.logger.Error("Failed to save endpoint %s: %v", endpoint.URL, err)
		}
	}
	
	return endpoints, nil
}

// isWebHost checks if a host is a web host
func isWebHost(host *models.Host) bool {
	// Check if host has common web ports
	webPorts := []int{80, 443, 8080, 8443}
	
	for _, port := range host.Ports {
		for _, webPort := range webPorts {
			if port == webPort {
				return true
			}
		}
	}
	
	// If no ports are specified, assume it's a web host if it's a domain
	return host.Type == models.AssetTypeDomain
}
