# Security Standards Research - Feb 2026

## Research Summary

Topics covered: SARIF v2.1.0, CVSS 4.0, Nuclei v3.2+ DAST, Scope Matching

## Key Findings

### SARIF
- go-sarif v3: `github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif`
- GitHub requires version 2.1.0, max 10MB gzipped
- security-severity property: 0.1-3.9=low, 4.0-6.9=medium, 7.0-8.9=high, 9.0+=critical
- partialFingerprints calculated by upload action if missing

### CVSS 4.0
- pandatix/go-cvss: supports v3.1 and v4.0
- goark/go-cvss: another Go option
- Vector: CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H
- New metrics: AT (Attack Requirements), Subsequent system impact, Supplemental group
- HackerOne added CVSS 4.0 API support Jan 2025

### Nuclei v3.2+
- `-dast` flag enables DAST mode
- `-input-mode openapi` for API schema import
- `-fuzzing-type` and `-fuzzing-mode` flags
- Go SDK: `github.com/projectdiscovery/nuclei/v3/lib`

### Scope Matching
- HackerOne asset types: url, cidr, mobile, android, apple, other, hardware, code, executable
- Bugcrowd: url, api, mobile, android, apple, other, hardware
- bbscope tool for aggregation
- Go stdlib: net.ParseCIDR + net.IPNet.Contains for CIDR
