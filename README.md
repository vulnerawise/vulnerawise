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
curl -L -o ./vulnerawise https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-linux-amd64
chmod +x ./vulnerawise

# macOS (arm64)
curl -L -o ./vulnerawise https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-darwin-arm64
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

# Start the API server
vulnerawise serve
```

## Documentation

- [CLI Guide](docs/cli.md) - Complete command reference
- [Search Syntax](docs/search.md) - Advanced search capabilities
- [Audit & Policy Evaluation](docs/audit.md) - Vulnerability auditing system
- [API Documentation](docs/api.md) - REST API endpoints and usage

## Example Use Cases

- **Vulnerability Prioritization** - Focus on vulnerabilities actively being exploited
- **Security Compliance** - Audit systems against organization security policies
- **Threat Intelligence** - Track trends in vulnerability exploitation
- **DevSecOps Integration** - Use the API to integrate with CI/CD pipelines

## Version

Current version: v0.1.1

## License

This project is available under the [MIT License](LICENSE).
