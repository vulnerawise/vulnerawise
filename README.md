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

## Documentation

- [Install Guide](docs/install.md) - Step-by-step instructions for installing Vulnerawise on your system.
- [Search Syntax](docs/search.md) - Detailed guide to advanced search filters, operators, and query examples.
- [Check & Policy Evaluation](docs/check.md) - How to use SSVC-based checks and enforce security policies on vulnerabilities.
- [API Documentation](docs/api.md) - Reference for all REST API endpoints, authentication, and integration tips.
- [Exporting CVE Data](docs/export.md) - Export vulnerability search results or audit findings in multiple formats for reporting or automation.
- [Viewing Trending CVEs](docs/trending.md) - Learn to identify, monitor, and analyze vulnerabilities that are trending or under active exploitation.

## Example Use Cases

### Key Features
	•	Exploit maturity: none, poc, active
	•	Component-level context with fix versions
	•	SSVC-based prioritization (immediate, schedule, defer)
	•	Exposure and impact reasoning
	•	Lightweight CLI and fast API

### Example Use Cases
	•	Vulnerability Prioritization – Focus remediation on vulnerabilities that are actively being exploited in the wild
	•	Security Compliance – Audit internal systems and assets against threat-informed security policies and patch SLAs
	•	Threat Intelligence – Track exploitation trends across CVEs, CWEs, and attacker TTPs for better situational awareness
	•	DevSecOps Integration – Use the CLI or API to embed threat-aware triage into CI/CD pipelines and code security gates
	•	Security Operations (SOC) – Enrich SIEM/SOAR alerts with exploit context to reduce alert fatigue and speed up response
	•	Government CERTs & Agencies – Monitor public sector exposure, automate patch guidance, and inform national cyber response