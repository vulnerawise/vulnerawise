# **Vulnerawise CLI User Guide**

## **Introduction**
Vulnerawise is a command-line tool designed for querying and processing CVE exploitation data. It provides actionable intelligence for real-world threat prioritization. The CLI allows users to:

- Search for CVEs based on various filters
- Export vulnerability data to different formats
- Audit vulnerability scanner reports against security policies
- View trending CVEs
- Start an API server
- Update the local CVE database

---

## **Installation**
Ensure that you have downloaded and installed the tool properly. If needed, make sure to include the binary in your system's `$PATH` for easy access.

You can download precompiled binaries for your platform from the Vulnerawise GitHub Releases. Here are examples for several platforms:

### Linux (amd64 and arm64)

For **Linux (amd64)**:

```bash
curl -L -o ./vulnerawise https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-linux-amd64
chmod +x ./vulnerawise
```

For **Linux (arm64)**:

```bash
curl -L -o ./vulnerawise https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-linux-arm64
chmod +x ./vulnerawise
```

### macOS (Darwin)

For **macOS (amd64)**:

```bash
curl -L -o ./vulnerawise https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-darwin-amd64
chmod +x ./vulnerawise
```

For **macOS (arm64)**:

```bash
curl -L -o ./vulnerawise https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-darwin-arm64
chmod +x ./vulnerawise
```

### Windows

For **Windows (amd64)** and **Windows (arm64)**, download the appropriate binary from the releases page.

---

## **Commands Overview**

#### **1. Search for CVEs**
The `search` command allows users to filter and display CVEs based on multiple parameters.

##### **Usage:**
```sh
vulnerawise search [flags]
```

##### **Flags:**
- `--cve` → Search by specific CVE IDs (comma-separated)
- `--published-date-range` → Search within a date range (`YYYY-MM-DD:YYYY-MM-DD`)
- `--published` → Search for CVEs published in the last X days/hours
- `--last-modified` → Search by last modified date
- `--maturity` → Filter by exploit maturity (comma-separated, e.g., `active,weaponized,poc,none`)
- `--severity` → Filter by severity (comma-separated, e.g., `low,medium,high,critical`)
- `--description` → Filter by description substring (e.g., `microsoft`)
- `--epss` → Filter by EPSS score percentage (e.g., `>=50`, `<30`, `=70`)
- `--cisa-kev` → Filter by CISA KEV catalog
- `--ransomware` → Filter by ransomware association
- `--weaponized` → Filter for vulnerabilities with weaponized exploits
- `--print-exploit-only` → Print only exploit URLs
- `--limit` → Maximum number of results to return (default: `20`)
- `--page` → Pagination page number (default: `1`)
- `--format` → Output format (`table`, `json`, or `csv`)

#### **Example:**
```sh
vulnerawise search --severity high --maturity active --limit 10
```

---

### **2. Export CVE Data**
The `export` command allows users to export vulnerability data in JSON or CSV format.

#### **Usage:**
```sh
vulnerawise export [flags]
```

#### **Flags:**
- `--output-file` → File to export all results into
- `--output-dir` → Directory to organize exported results by year
- `--cve` → Comma-separated list of CVE IDs to export
- `--batch-size` → Group records into batch files of this size (default: `0` for individual files)
- `--format` → Export format (`json` or `csv`; CSV only supported with --output-file)

#### **Example:**
```sh
vulnerawise export --output-file cve_data.json
```

---

### **3. Audit Vulnerability Scanner Reports**
The `audit` command evaluates vulnerability scanner reports or individual CVEs against predefined security policies.

#### **Usage:**
```sh
vulnerawise audit [scanner-type] [scan-file] [flags]
```

#### **Flags:**
- `--cve` → Evaluate specific CVE IDs (comma-separated)
- `--attest-output` → Path to output attestation JSON file for container signing (not available with --cve)

#### **Supported Scanner Types:**
- `grype` - Audit Grype scanner json reports
- `trivy` - Audit Trivy scanner json reports
- `scout` - Audit Scout scanner gitlab reports

#### **Example:**
```sh
vulnerawise audit trivy-report.json
vulnerawise audit grype-report.json --attest-output attestation.json
vulnerawise audit scout-report.json
vulnerawise audit --cve CVE-2024-51567
```

**Note:** The attestation output option is not available for single CVE evaluations.

---

### **4. View Trending CVEs**
The `trending` command displays the most trending CVEs based on computed scores.

#### **Usage:**
```sh
vulnerawise trending [flags]
```

#### **Flags:**
- `--limit` → Number of trending results to return (default: `10`)
- `--offset` → Pagination offset (default: `0`)
- `--format` → Output format (`table` or `json`)

#### **Example:**
```sh
vulnerawise trending --limit 5 --format json
```

---

### **5. Start the API Server**
The `serve` command starts a REST API server that allows querying the CVE database programmatically.

#### **Usage:**
```sh
vulnerawise serve [flags]
```

#### **Flags:**
- `--port` → Port to run the API server on (default: `8080`)

#### **Example:**
```sh
vulnerawise serve --port 9090
```

---

### **6. Update the Local CVE Database**
The `updatedb` command downloads or updates the local CVE database.

#### **Usage:**
```sh
vulnerawise updatedb [flags]
```

#### **Flags:**
- `--from-url` → Custom URL to download the database from (default: service API endpoint)

#### **Example:**
```sh
vulnerawise updatedb
vulnerawise updatedb --from-url https://custom-mirror.example.com/updates/
```

---

## **Global Flags**
These flags are available for all commands:

- `--skip-update` → Skip automatic database update check

---

Vulnerawise is a powerful CLI tool for security professionals and researchers looking to track and analyze CVE exploitation data. Use the above commands to effectively gather insights, audit vulnerabilities, and prioritize threats.


