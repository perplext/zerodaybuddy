package ratelimit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// HTTPClient is an HTTP client with built-in rate limiting and retry logic
type HTTPClient struct {
	client      *http.Client
	rateLimiter *RateLimiter
	retryConfig RetryConfig
	service     string
	logger      *utils.Logger
}

// HTTPClientConfig holds configuration for the HTTP client
type HTTPClientConfig struct {
	Service     string        // Service name for rate limiting
	Timeout     time.Duration // HTTP client timeout
	RetryConfig RetryConfig   // Retry configuration
	Logger      *utils.Logger // Logger instance
}

// NewHTTPClient creates a new HTTP client with rate limiting and retry logic
func NewHTTPClient(rateLimiter *RateLimiter, config HTTPClientConfig) *HTTPClient {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	
	return &HTTPClient{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		rateLimiter: rateLimiter,
		retryConfig: config.RetryConfig,
		service:     config.Service,
		logger:      config.Logger,
	}
}

// Do executes an HTTP request with rate limiting and retry logic
func (c *HTTPClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	
	// Create retryable function
	fn := func(ctx context.Context) error {
		// Apply rate limiting
		if err := c.rateLimiter.Wait(ctx, c.service); err != nil {
			return fmt.Errorf("rate limit wait failed: %w", err)
		}
		
		// Log the request
		if c.logger != nil && c.logger.IsLevelEnabled(utils.DEBUG) {
			c.logger.Debug("Making HTTP request to %s for service %s", req.URL.String(), c.service)
		}
		
		// Execute the request
		resp, err = c.client.Do(req.WithContext(ctx))
		if err != nil {
			return err
		}
		
		// Check for rate limit errors
		if resp.StatusCode == http.StatusTooManyRequests {
			// Try to extract retry-after header
			if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
				if c.logger != nil {
					c.logger.Warn("Rate limited by server for service %s, retry-after: %s", c.service, retryAfter)
				}
			}
			resp.Body.Close()
			return fmt.Errorf("rate limited by server (429)")
		}
		
		// Check for server errors that should be retried
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			return fmt.Errorf("server error: %d %s", resp.StatusCode, resp.Status)
		}
		
		return nil
	}
	
	// Execute with retry logic
	result, err := RetryWithBackoffAndMetrics(ctx, c.retryConfig, fn)
	
	// Log metrics
	if c.logger != nil && c.logger.IsLevelEnabled(utils.DEBUG) {
		if result.Success {
			c.logger.Debug("Request succeeded for service %s after %d attempts (latency: %v)", 
				c.service, result.Attempts, result.TotalLatency)
		} else {
			c.logger.Error("Request failed for service %s after %d attempts (latency: %v): %v", 
				c.service, result.Attempts, result.TotalLatency, err)
		}
	}
	
	return resp, err
}

// Get performs a GET request with rate limiting and retry logic
func (c *HTTPClient) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req)
}

// Post performs a POST request with rate limiting and retry logic
func (c *HTTPClient) Post(ctx context.Context, url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(ctx, req)
}

// DefaultRetryableErrors returns a function that determines if an error is retryable
func DefaultRetryableErrors() func(error) bool {
	return func(err error) bool {
		if err == nil {
			return false
		}
		
		// Retry on network errors
		errStr := err.Error()
		networkErrors := []string{
			"connection refused",
			"connection reset",
			"no such host",
			"timeout",
			"temporary failure",
			"EOF",
		}
		
		for _, netErr := range networkErrors {
			if strings.Contains(errStr, netErr) {
				return true
			}
		}
		
		// Retry on specific HTTP errors
		if strings.Contains(errStr, "429") || // Rate limited
		   strings.Contains(errStr, "server error") { // 5xx errors
			return true
		}
		
		return false
	}
}

// HTTPClientFactory creates HTTP clients with rate limiting
type HTTPClientFactory struct {
	rateLimiter *RateLimiter
	logger      *utils.Logger
}

// NewHTTPClientFactory creates a new HTTP client factory
func NewHTTPClientFactory(rateLimiter *RateLimiter, logger *utils.Logger) *HTTPClientFactory {
	return &HTTPClientFactory{
		rateLimiter: rateLimiter,
		logger:      logger,
	}
}

// CreateClient creates a new HTTP client for a specific service
func (f *HTTPClientFactory) CreateClient(service string, timeout time.Duration) *HTTPClient {
	config := HTTPClientConfig{
		Service: service,
		Timeout: timeout,
		RetryConfig: RetryConfig{
			MaxAttempts:     3,
			InitialDelay:    1 * time.Second,
			MaxDelay:        30 * time.Second,
			Multiplier:      2.0,
			JitterFactor:    0.1,
			RetryableErrors: DefaultRetryableErrors(),
		},
		Logger: f.logger,
	}
	
	return NewHTTPClient(f.rateLimiter, config)
}