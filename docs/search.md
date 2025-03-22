# Vulnerawise Search Syntax Guide

This guide explains the various search options available in the Vulnerawise CLI tool. The search command provides powerful filtering capabilities to help you find specific CVEs based on various criteria.

## Basic Search Syntax

The basic format for search commands is:

```bash
vulnerawise search [flags]
```

You must specify at least one filter to perform a search.

## Search by CVE ID

Search for specific CVE IDs using the `--cve` flag:

```bash
# Search for a single CVE
vulnerawise search --cve CVE-2023-1234

# Search for multiple CVEs (comma-separated)
vulnerawise search --cve CVE-2023-1234,CVE-2023-5678
```

## Search by Description

The `--description` flag uses SQLite's powerful Full-Text Search (FTS5) engine, allowing for advanced text search capabilities.

### Basic Search

Simple word or phrase searches:

```bash
# Search for vulnerabilities mentioning "microsoft"
vulnerawise search --description microsoft
```

### Exact Phrase Search

Find CVEs with an exact phrase in the description:

```bash
# Find CVEs with the exact phrase "remote code execution"
vulnerawise search --description '"remote code execution"'
```

**Note:** When using quoted phrases in your shell, you'll need to escape them:
- Use single quotes around the argument: `'"phrase"'`
- Or escape the quotes: `\"phrase\"`

### Boolean Operators

#### AND Operator
Multiple terms are treated as an AND condition by default, but you can make it explicit:

```bash
# Find CVEs containing both "apache" AND "2.4.49"
vulnerawise search --description '"apache" AND "2.4.49"'
```

#### OR Operator
Use OR to find CVEs matching any of the specified terms:

```bash
# Find CVEs containing either "apache" OR "nginx"
vulnerawise search --description '"apache" OR "nginx"'
```

#### Grouping with Parentheses
You can use parentheses to group terms and control operator precedence:

```bash
# Find CVEs about Apache that mention either version 2.4.49 or 2.4.50
vulnerawise search --description '"apache" AND (2.4.49 OR 2.4.50)'

# Find CVEs with either "XSS" or "cross-site scripting" that are related to PHP
vulnerawise search --description '("XSS" OR "cross-site scripting") AND "PHP"'
```

#### Operator Precedence
When combining operators:
- `AND` has higher precedence than `OR`
- Parentheses can override the default precedence

For example, the search:
```bash
vulnerawise search --description '"apache" OR "nginx" AND "vulnerability"'
```
is interpreted as:
```bash
"apache" OR ("nginx" AND "vulnerability")
```

To search for vulnerabilities with either "apache" or "nginx" that also contain "vulnerability", use:

```bash
vulnerawise search --description '("apache" OR "nginx") AND "vulnerability"'
```

### Examples of Complex Description Searches

```bash
# Find buffer overflow vulnerabilities in either OpenSSL or LibreSSL
vulnerawise search --description '"buffer overflow" AND ("OpenSSL" OR "LibreSSL")'

# Find authentication bypass issues in Spring or Spring Boot frameworks
vulnerawise search --description '("authentication bypass" OR "auth bypass") AND ("Spring" OR "Spring Boot")'

# Find SQL injection vulnerabilities in WordPress plugins
vulnerawise search --description '"SQL injection" AND "WordPress" AND "plugin"'
```

### Combining with Other Filters

These description search patterns can be combined with other filters for even more precise results:

```bash
# Find high severity remote code execution vulnerabilities in Apache
vulnerawise search --description '"remote code execution" AND "apache"' --severity high

# Find recently published authentication bypass vulnerabilities
vulnerawise search --description '"authentication bypass"' --published "last 30 days"
```

## Search by Severity & Exploit Maturity

### Severity Levels

Vulnerabilities are categorized into severity levels based on their impact:

- `low`: Minimal impact or requires significant conditions for exploitation.
- `medium`: Moderate impact, may require some conditions for exploitation.
- `high`: Severe impact, easy to exploit, or affects critical systems.
- `critical`: Extreme impact, typically allowing full system compromise or widespread damage with minimal effort.

Example:

```bash
# Search for high severity vulnerabilities
vulnerawise search --severity high

# Search for multiple severity levels
vulnerawise search --severity medium,high
```

### Exploit Maturity Levels

Exploit maturity defines the likelihood of exploitation:

- `none`: No public exploit available.
- `poc`: Proof-of-concept exploit exists.
- `active`: Evidence of active exploitation in the wild.

Example:

```bash
# Find CVEs with active exploitation in the wild
vulnerawise search --maturity active

# Find CVEs with multiple maturity levels
vulnerawise search --maturity active,poc
```

### Weaponized Filter

Filter vulnerabilities that are marked with weaponized exploits. This flag targets vulnerabilities involving advanced exploitation techniques.

```bash
# Find vulnerabilities with weaponized exploits
vulnerawise search --weaponized

# Combine with other filters for more focused results
vulnerawise search --weaponized --severity high
vulnerawise search --weaponized --description apache
```

### Ransomware Filter

Filter vulnerabilities that are known to be exploited by ransomware groups:

```bash
# Find all vulnerabilities exploited by ransomware groups
vulnerawise search --ransomware

# Combine with other filters to focus on specific ransomware threats
vulnerawise search --ransomware --severity high
vulnerawise search --ransomware --description apache
```

### CISA KEV Catalog

Filter vulnerabilities that are included in the CISA Known Exploited Vulnerabilities (KEV) catalog:

```bash
# Find all vulnerabilities in the CISA KEV catalog
vulnerawise search --cisa-kev

# Find recently added CISA KEV entries
vulnerawise search --cisa-kev --published "last 30 days"

# Find critical severity CISA KEV entries
vulnerawise search --cisa-kev --severity critical
```

## Additional Filters

Other filters available include:

- `--epss`: Filter by EPSS score percentage (e.g., `>=50`, `<30`, `=70`)
- `--exploit-published`: Filter CVEs by the published date of associated exploit data (e.g., `last 7 days`, `last 24 hours`)
- `--last-modified`: Filter by last modified date (e.g., `last 7 days` or `YYYY-MM-DD:YYYY-MM-DD`)
- `--page`: Pagination page number (default is 1)
- `--limit`: Maximum number of results to return (default is 20)
- `--print-exploit-only`: Print only exploit URLs
- `--published`: Filter by CVEs published in a relative time span (e.g., `last 7 days`, `last 24 hours`)
- `--published-date-range`: Filter by a specific published date range (e.g., `2024-01-01:2024-01-31`)
- `--format`: Output format; options are `table`, `json`, or `csv` (default is `table`)

## Results Pagination and Format

```bash
# Limit to 20 results
vulnerawise search --description apache --limit 20

# Retrieve the next page of results (using offset method)
vulnerawise search --description apache --limit 20 --offset 20

# Format output as JSON
vulnerawise search --description apache --format json
```

## Examples of Common Searches

```bash
# Find critical vulnerabilities for immediate action
vulnerawise search --maturity active --severity high

# Monitor new exploits in the last week
vulnerawise search --exploit-published "last 7 days"

# Check for vulnerabilities in a specific technology
vulnerawise search --description kubernetes --published "last 90 days"

# Generate a report of all high-severity issues from last quarter
vulnerawise search --severity high --published-date-range 2023-01-01:2023-03-31 --format json
```
