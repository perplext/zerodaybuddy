package scan

import (
	"net"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestIsInternalIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		internal bool
	}{
		// Loopback (127.0.0.0/8)
		{"loopback 127.0.0.1", "127.0.0.1", true},
		{"loopback 127.255.255.255", "127.255.255.255", true},

		// RFC 1918 (10.0.0.0/8)
		{"rfc1918 10.0.0.1", "10.0.0.1", true},
		{"rfc1918 10.255.255.255", "10.255.255.255", true},

		// RFC 1918 (172.16.0.0/12)
		{"rfc1918 172.16.0.1", "172.16.0.1", true},
		{"rfc1918 172.31.255.255", "172.31.255.255", true},
		{"outside 172.32.0.1", "172.32.0.1", false},

		// RFC 1918 (192.168.0.0/16)
		{"rfc1918 192.168.0.1", "192.168.0.1", true},
		{"rfc1918 192.168.255.255", "192.168.255.255", true},

		// Link-local / cloud metadata (169.254.0.0/16)
		{"link-local 169.254.169.254", "169.254.169.254", true},
		{"link-local 169.254.0.1", "169.254.0.1", true},

		// "This" network (0.0.0.0/8)
		{"zero network 0.0.0.0", "0.0.0.0", true},
		{"zero network 0.255.255.255", "0.255.255.255", true},

		// Shared address space (100.64.0.0/10)
		{"shared 100.64.0.1", "100.64.0.1", true},
		{"shared 100.127.255.255", "100.127.255.255", true},
		{"outside shared 100.128.0.1", "100.128.0.1", false},

		// IETF protocol assignments (192.0.0.0/24)
		{"ietf 192.0.0.1", "192.0.0.1", true},

		// Benchmarking (198.18.0.0/15)
		{"benchmark 198.18.0.1", "198.18.0.1", true},
		{"benchmark 198.19.255.255", "198.19.255.255", true},
		{"outside benchmark 198.20.0.1", "198.20.0.1", false},

		// IPv6 loopback
		{"ipv6 loopback", "::1", true},

		// IPv6 ULA (fc00::/7)
		{"ipv6 ula", "fd00::1", true},
		{"ipv6 ula fc", "fc00::1", true},

		// IPv6 link-local (fe80::/10)
		{"ipv6 link-local", "fe80::1", true},

		// Public IPs — should NOT be blocked
		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 93.184.216.34", "93.184.216.34", false},
		{"public ipv6 2001:db8::1", "2001:db8::1", false},
		{"public 104.16.0.1", "104.16.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			assert.NotNil(t, ip, "failed to parse IP: %s", tt.ip)
			result := isInternalIP(ip)
			assert.Equal(t, tt.internal, result, "IP %s: expected internal=%v, got %v", tt.ip, tt.internal, result)
		})
	}
}

func TestIsInternalHost_RawIPs(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		internal bool
	}{
		// Raw IPs bypass DNS lookup
		{"loopback IP", "127.0.0.1", true},
		{"private 10.x", "10.0.0.1", true},
		{"private 192.168.x", "192.168.1.1", true},
		{"cloud metadata", "169.254.169.254", true},
		{"public IP", "8.8.8.8", false},
		{"ipv6 loopback", "::1", true},
		{"ipv6 public", "2001:db8::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isInternalHost(tt.host)
			assert.Equal(t, tt.internal, result, "host %s: expected internal=%v, got %v", tt.host, tt.internal, result)
		})
	}
}

func TestIsInternalHost_UnresolvableHostname(t *testing.T) {
	// Unresolvable hostnames should be blocked (fail closed)
	result := isInternalHost("this-host-does-not-exist-zzz.invalid")
	assert.True(t, result, "unresolvable hostname should be blocked (fail closed)")
}

func TestFilterSSRFURLs(t *testing.T) {
	logger := utils.NewLogger("test", false)

	tests := []struct {
		name     string
		urls     []string
		wantSafe []string
	}{
		{
			name:     "empty input",
			urls:     []string{},
			wantSafe: nil,
		},
		{
			name: "all safe URLs",
			urls: []string{
				"https://example.com/path",
				"https://google.com/search",
			},
			wantSafe: []string{
				"https://example.com/path",
				"https://google.com/search",
			},
		},
		{
			name: "filters internal IPs",
			urls: []string{
				"http://127.0.0.1/admin",
				"http://10.0.0.1/internal",
				"https://example.com/safe",
			},
			wantSafe: []string{
				"https://example.com/safe",
			},
		},
		{
			name: "filters cloud metadata endpoint",
			urls: []string{
				"http://169.254.169.254/latest/meta-data/",
				"https://example.com/ok",
			},
			wantSafe: []string{
				"https://example.com/ok",
			},
		},
		{
			name: "filters malformed URLs",
			urls: []string{
				"://not-a-url",
				"https://example.com/valid",
			},
			wantSafe: []string{
				"https://example.com/valid",
			},
		},
		{
			name: "filters ipv6 loopback",
			urls: []string{
				"http://[::1]/test",
				"https://example.com/ok",
			},
			wantSafe: []string{
				"https://example.com/ok",
			},
		},
		{
			name: "all internal — returns nil",
			urls: []string{
				"http://127.0.0.1/a",
				"http://192.168.1.1/b",
			},
			wantSafe: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterSSRFURLs(tt.urls, logger)
			assert.Equal(t, tt.wantSafe, got)
		})
	}
}

func TestInternalCIDRsInitialized(t *testing.T) {
	// Verify that the init() function populated internalCIDRs
	assert.NotEmpty(t, internalCIDRs, "internalCIDRs should be populated by init()")
	// We expect at least 12 CIDR ranges (9 IPv4 + 3 IPv6)
	assert.GreaterOrEqual(t, len(internalCIDRs), 12, "expected at least 12 blocked CIDR ranges")
}
