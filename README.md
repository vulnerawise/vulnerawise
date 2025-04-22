# Vulnerawise

> Advanced vulnerability intelligence and management platform

Vulnerawise is a comprehensive tool designed to help security professionals search, analyze, and prioritize vulnerabilities based on real-world exploitation data. It combines multiple data sources to provide actionable intelligence for effective risk management.

## Features

- **Powerful Search Engine** - Filter vulnerabilities by CVE ID, severity, exploit maturity, and more
- **Policy-Based Auditing** - Evaluate vulnerabilities against security policies using SSVC framework
- **REST API** - Access vulnerability data programmatically
- **Scanner Integration** - Analyze reports from tools like Trivy, Grype, and Docker Scout
- **Trending Analysis** - Identify which vulnerabilities are actively being exploited
- **Multiple Output Formats** - Export results as JSON, CSV, or formatted tables

## Installation

Download precompiled binaries for your platform:

```bash
# Linux (amd64)
curl -L -o ./vulnerawise https://api.vulnerawise.ai/vulnerawise-linux-amd64
chmod +x ./vulnerawise

# macOS (arm64)
curl -L -o ./vulnerawise https://api.vulnerawise.ai/vulnerawise-darwin-arm64
chmod +x ./vulnerawise
```

See [CLI documentation](docs/cli.md) for more installation options.

## Quick Start

```bash
# Search for active high-severity vulnerabilities
vulnerawise search --maturity active --severity high

# Audit a vulnerability scanner report
vulnerawise audit trivy-report.json

# Check trending vulnerabilities
vulnerawise trending --limit 10
```

## Documentation

- [Install Guide](docs/install.md) - Complete command reference
- [Search Syntax](docs/search.md) - Advanced search capabilities
- [Check & Policy Evaluation](docs/check.md) - Vulnerability check system
- [API Documentation](docs/api.md) - REST API endpoints and usage
- [Exporting CVE Data](docs/export.md)
- [Viewing Trending CVEs](docs/trending.md)

## Example Use Cases

### Key Features
	•	Exploit maturity: none, poc, active
	•	Component-level context with fix versions
	•	SSVC-based prioritization (immediate, schedule, defer)
	•	Exposure and impact reasoning
	•	Lightweight CLI and fast API
	•	No login required, ready for air-gapped use

### Example Use Cases
	•	Vulnerability Prioritization – Focus remediation on vulnerabilities that are actively being exploited in the wild
	•	Security Compliance – Audit internal systems and assets against threat-informed security policies and patch SLAs
	•	Threat Intelligence – Track exploitation trends across CVEs, CWEs, and attacker TTPs for better situational awareness
	•	DevSecOps Integration – Use the CLI or API to embed threat-aware triage into CI/CD pipelines and code security gates
	•	Security Operations (SOC) – Enrich SIEM/SOAR alerts with exploit context to reduce alert fatigue and speed up response
	•	Government CERTs & Agencies – Monitor public sector exposure, automate patch guidance, and inform national cyber response