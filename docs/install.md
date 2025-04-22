# Vulnerawise CLI Installation Guide

## Introduction
Vulnerawise is a command-line tool for querying and processing CVE exploitation data. It provides actionable intelligence for real-world threat prioritization.

---

## Installation
Ensure you have downloaded and installed the tool properly. Add the binary to your system's `$PATH` for easy access.

You can download precompiled binaries for your platform from the Vulnerawise GitHub Releases:

### Linux (amd64 and arm64)

For **Linux (amd64)**:
```bash
curl -L -o ./vulnerawise https://api.vulnerawise.ai/vulnerawise-linux-amd64
chmod +x ./vulnerawise
```
For **Linux (arm64)**:
```bash
curl -L -o ./vulnerawise https://api.vulnerawise.ai/vulnerawise-linux-arm64
chmod +x ./vulnerawise
```

### macOS (Darwin)
For **macOS (amd64)**:
```bash
curl -L -o ./vulnerawise https://api.vulnerawise.ai/vulnerawise-darwin-amd64
chmod +x ./vulnerawise
```
For **macOS (arm64)**:
```bash
curl -L -o ./vulnerawise https://api.vulnerawise.ai/vulnerawise-darwin-arm64
chmod +x ./vulnerawise
```

### Windows
For **Windows (amd64)** and **Windows (arm64)**, download the appropriate binary from the releases page.

---

## Next Steps
- [Exporting CVE Data](export.md)
- [Viewing Trending CVEs](trending.md)
- [Searching Vulnerabilities](search.md)
- [Checking Vulnerabilities & Policies](check.md)

---

## Update the Local CVE Database
The `updatedb` command downloads or updates the local CVE database.

**Usage:**
```sh
vulnerawise updatedb [flags]
```
**Flags:**
- `--from-url` → Custom URL to download the database from (default: service API endpoint)

**Example:**
```sh
vulnerawise updatedb
vulnerawise updatedb --from-url https://custom-mirror.example.com/updates/
```

---

## Global Flags
These flags are available for all commands:
- `--skip-update` → Skip automatic database update check

---

Vulnerawise is a powerful CLI tool for security professionals and researchers to track and analyze CVE exploitation data. Use the above commands to install and get started.


