# **Vulnerawise CLI User Guide**

## **Introduction**
Vulnerawise is a command-line tool designed for querying and processing CVE exploitation data. It provides actionable intelligence for real-world threat prioritization. The CLI allows users to:

- Search for CVEs based on various filters
- Export exploitation intelligence data
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
wget -q -O ./vulnerawise https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-linux-amd64
chmod +x ./vulnerawise
```

For **Linux (arm64)**:

```bash
wget -q -O ./vulnerawise https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-linux-arm64
chmod +x ./vulnerawise
```

### macOS (Darwin)

For **macOS (amd64)**:

```bash
wget -q -O ./vulnerawise https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-darwin-amd64
chmod +x ./vulnerawise
```

For **macOS (arm64)**:

```bash
wget -q -O ./vulnerawise https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-darwin-arm64
chmod +x ./vulnerawise

```

### Windows

For **Windows (amd64)** and **Windows (arm64)**, download the appropriate binary from the releases page.

---

## **Commands Overview**

### **1. Search for CVEs**
The `search` command allows users to filter and display CVEs based on multiple parameters.

#### **Usage:**
```sh
vulnerawise search [flags]
```

#### **Flags:**
- `--cve` → Search by specific CVE IDs (comma-separated)
- `--published-date-range` → Search within a date range (`YYYY-MM-DD:YYYY-MM-DD`)
- `--published` → Search for CVEs published in the last X days/hours
- `--last-modified` → Search by last modified date
- `--maturity` → Filter by exploit maturity (`active,weaponized,poc,none`)
- `--severity` → Filter by severity (`low,medium,high`)
- `--description` → Filter by description substring (e.g., `microsoft`)
- `--epss` → Filter by EPSS score percentage (e.g., '>=50', '<30', '=70')
- `--limit` → Maximum number of results to return (default: `10`)
- `--offset` → Pagination offset (default: `0`)
- `--format` → Output format (`table` or `json`)

#### **Example:**
```sh
vulnerawise search --severity high --maturity weaponized
```

**Example Output:**
```sh
# (Replace with actual output)
```

---

### **2. Export CVE Data**
The `export` command allows users to export CVE intelligence data in JSON format.

#### **Usage:**
```sh
vulnerawise export --output-file <filename> | --output-dir <directory>
```

#### **Flags:**
- `--output-file` → File to export all results into
- `--output-dir` → Directory to organize exported results by year
- `--cve` → Comma-separated list of CVE IDs to export

#### **Example:**
```sh
vulnerawise export --output-file cve_data.json
```

**Example Output:**
```sh
# (Replace with actual output)
```

---

### **3. Audit Vulnerability Scanner Reports**
The `audit` command evaluates vulnerability scanner reports against predefined security policies.

#### **Usage:**
```sh
vulnerawise audit <integration> <scan-file>
```

#### **Supported Integrations:**
- `grype`
- `trivy`
- `stackrox`

#### **Example:**
```sh
vulnerawise audit trivy trivy-report.json
```

**Example Output:**
```sh
# (Replace with actual output)
```

---

### **4. View Trending CVEs**
The `trending` command displays the most trending CVEs based on a computed score.

#### **Usage:**
```sh
vulnerawise trending --limit <number>
```

#### **Flags:**
- `--limit` → Number of trending results to return (default: `10`)
- `--offset` → Pagination offset (default: `0`)
- `--format` → Output format (`table` or `json`)

#### **Example:**
```sh
vulnerawise trending --limit 5 --format json
```

**Example Output:**
```sh
# (Replace with actual output)
```

---

### **5. Start the API Server**
The `serve` command starts a REST API server that allows querying the CVE database programmatically.

#### **Usage:**
```sh
vulnerawise serve --port <port>
```

#### **Flags:**
- `--port` → Port to run the API server on (default: `8080`)

#### **Example:**
```sh
vulnerawise serve --port 9090
```

**Example Output:**
```sh
# (Replace with actual output)
```

---

### **6. Update the Local CVE Database**
The `updatedb` command downloads or updates the local CVE database.

#### **Usage:**
```sh
vulnerawise updatedb --from-url <url>
```

#### **Flags:**
- `--from-url` → Optional URL to download the database from (default: `https://api.vulnerawise.ai/`).
  - The web server hosting the updates must include:
    - `metadata.file` containing the metadata information.
    - A `.tgz` archive with the database file.
  - The CLI fetches these files and updates the local database accordingly.

#### **Example:**
```sh
vulnerawise updatedb
```

**Example Output:**
```sh
# (Replace with actual output)
```

---

## **Troubleshooting & FAQ**
### **Q: The `search` command returns no results.**
- Ensure the database is up-to-date by running:
  ```sh
  vulnerawise updatedb
  ```
- Check if your filters are too restrictive.

### **Q: The API server is not responding.**
- Ensure the server is running with:
  ```sh
  ps aux | grep vulnerawise
  ```
- Check if the correct port is used.

### **Q: How do I see all available commands?**
- Run:
  ```sh
  vulnerawise --help
  ```

---

Vulnerawise is a powerful CLI tool for security professionals and researchers looking to track and analyze CVE exploitation data. Use the above commands to effectively gather insights, audit vulnerabilities, and prioritize threats.


