# Vulnerawise API Documentation

The Vulnerawise API provides access to vulnerability data filtered by various criteria (e.g., CVE IDs, date ranges, description, feed, etc.) with built-in pagination. This guide will help you download, start, and use the API.

---

## API Endpoints

### Health Check
```
GET /v1/health
```
Returns the health status of the API.

### Search Vulnerabilities
```
GET /v1/vuln
```

#### Query Parameters

| Parameter               | Type    | Description                                         | Example                           |
|-------------------------|---------|-----------------------------------------------------|-----------------------------------|
| cve                     | string  | Comma-separated list of CVE IDs                     | CVE-2023-1234,CVE-2023-5678         |
| published_date_range    | string  | Date range filter in format YYYY-MM-DD:YYYY-MM-DD   | 2023-01-01:2023-01-31              |
| published               | string  | Filter for CVEs published relative to now           | last 10 days                       |
| last_modified           | string  | Filter for CVEs last modified                       | last 30 days                       |
| maturity                | string  | Filter by exploit maturity                          | active,weaponized,poc,none         |
| severity                | string  | Filter by severity                                  | high,critical                     |
| exploit_published       | string  | Filter by exploit published date                    | last 7 days                        |
| description             | string  | Filter by description substring                   | remote code execution              |
| epss                    | string  | EPSS score filter                                   | >=50                               |
| kev                     | boolean | Filter by CISA KEV catalog                          | true                               |
| ransomware              | boolean | Filter by ransomware usage                          | true                               |
| weaponized              | boolean | Filter for vulnerabilities with weaponized exploits | true                               |
| cwe                     | string  | Filter by CWE (e.g., CWE-79 or comma-separated list) | CWE-79,CWE-89                     |
| page                    | integer | Page number for pagination                          | 1                                  |
| limit                   | integer | Results per page (max 100)                          | 50                                 |

#### Example Requests

Basic search:
```
GET /v1/vuln?description=kubernetes&severity=high&limit=10
```

Search for vulnerabilities in CISA KEV catalog:
```
GET /v1/vuln?kev=true&published=last%2030%20days
```

Search for vulnerabilities used in ransomware:
```
GET /v1/vuln?ransomware=true&severity=critical
```

Search for weaponized vulnerabilities:
```
GET /v1/vuln?weaponized=true
```

Search for vulnerabilities by CWE:
```
GET /v1/vuln?cwe=CWE-79
```

Search for multiple CWEs and combine with other filters:
```
GET /v1/vuln?cwe=CWE-79,CWE-89&severity=high&kev=true
```

#### Response Format

```json
{
  "metadata": {
    "timestamp": "2023-05-15T09:45:00Z"
  },
  "data": [
    {
      "cve": {
        "id": "CVE-2023-1234",
        "description": "A vulnerability in Example Software...",
        "metadata": {
          "publishedDate": "2023-05-10T15:30:00Z",
          "lastModifiedDate": "2023-05-15T09:45:00Z",
          "confidenceLevel": "high",
          "severity": "high"
        },
        "impact": {
          "cisa_kev": true,
          "known_ransomware_campaign_use": false,
          "weaponized": true,
          "reported_exploited": true,
          "exploit_maturity": "active",
          "automatable": true
        },
        "epss": {
          "score": 0.75,
          "percentile": 95.4
        }
      }
    }
  ],
  "page": 1,
  "limit": 10,
  "returned": 1
}
```

### Audit Vulnerabilities

#### Audit Individual CVEs
```
GET /v1/check
```

Audit a specific CVE against security policies.

#### Query Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| cve | string | The CVE ID to evaluate | CVE-2023-1234 |
| impact | string | Optional impact level override | high |
| exposure | string | Optional exposure level override | open |

#### Example Request

```
GET /v1/check?cve=CVE-2023-4966,CVE-2025-0655&impact=high&exposure=open
```

#### Response Format

```json
{
  "passed": false,
  "results": {
    "CVE-2023-4966": {
      "cve_id": "CVE-2023-4966",
      "decision": {
        "decision": "immediate",
        "enforced": true,
        "passed_all": false,
        "policy": "ssvc-immediate-policy"
      }
    },
    "CVE-2025-0655": {
      "cve_id": "CVE-2025-0655",
      "decision": {
        "decision": "immediate",
        "enforced": true,
        "passed_all": false,
        "policy": "ssvc-immediate-policy"
      }
    }
  },
  "timestamp": "2025-03-23T17:08:20Z"
}
```

#### Upload Scanner Reports
```
POST /v1/check
```

Upload vulnerability scanner output (like Trivy, Grype) for policy evaluation.

##### Request Format

The request body should contain the raw JSON output from a supported vulnerability scanner.

##### Example - Uploading Trivy Repository Scan Results

You can pipe Trivy scan results directly to the API:

```bash
trivy repository github.com/ralvares/santa --format json | curl -X POST \
  -H "Content-Type: application/json" \
  -d @- \
  http://localhost:8080/v1/check
```

##### Response Format

```json
{
  "violations": [
    {
      "cve_id": "CVE-2021-45046",
      "component": "org.apache.logging.log4j:log4j-core",
      "version": "2.14.1",
      "fix_version": "2.16.0, 2.12.2",
      "outcome": "SSVC Priority: Immediate - Vulnerability: CVE-2021-45046 (critical) - Description: It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations...",
      "decision": "immediate",
      "policy": "ssvc-immediate-policy",
      "enforced": true,
      "path": ""
    },
    {
      "cve_id": "CVE-2021-44228",
      "component": "org.apache.logging.log4j:log4j-core",
      "version": "2.14.1",
      "fix_version": "2.15.0, 2.3.1, 2.12.2",
      "outcome": "SSVC Priority: Immediate - Vulnerability: CVE-2021-44228 (critical) - Description: Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints...",
      "decision": "immediate",
      "policy": "ssvc-immediate-policy",
      "enforced": true,
      "path": ""
    }
  ],
  "timestamp": "2025-03-21T08:22:12Z",
  "passed_all_policies": false
}
```

The response contains:
- `violations`: Array of policy violations detected in the scan
  - `cve_id`: The CVE identifier
  - `component`: The affected component
  - `version`: Current version of the component
  - `fix_version`: Version(s) that fix the vulnerability
  - `outcome`: Detailed explanation of the vulnerability and assessment
  - `decision`: Policy decision (immediate, scheduled, out-of-cycle, defer)
  - `policy`: The policy applied for evaluation
  - `enforced`: Whether the policy is enforced
- `timestamp`: When the evaluation was performed
- `passed_all_policies`: Whether all vulnerabilities passed policy checks

## Rate Limiting

The API includes rate limiting to prevent abuse. By default, it has request limits in place.

## Error Codes

| Status Code | Description |
|-------------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid parameters |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |

## Example API Usage

### Using curl

```bash
# Search for high severity vulnerabilities
curl "http://localhost:8080/v1/vuln?severity=high&limit=5"

# Search for vulnerabilities in CISA KEV catalog
curl "http://localhost:8080/v1/vuln?kev=true"

# Search for vulnerabilities used by ransomware groups
curl "http://localhost:8080/v1/vuln?ransomware=true"

# Search with multiple filters
curl "http://localhost:8080/v1/vuln?description=apache&maturity=active&published=last%2030%20days"

# Search for vulnerabilities by CWE
curl "http://localhost:8080/v1/vuln?cwe=CWE-79"

# Search for multiple CWEs and high severity
curl "http://localhost:8080/v1/vuln?cwe=CWE-79,CWE-89&severity=high"

# Combine CWE with CISA KEV
curl "http://localhost:8080/v1/vuln?cwe=CWE-79&kev=true"
```

### Using Python

```python
import requests
import json

# Search for high severity vulnerabilities
response = requests.get(
    'http://localhost:8080/v1/vuln',
    params={
        'severity': 'high',
        'limit': 5
    }
)

results = response.json()
print(json.dumps(results, indent=2))

# Search for vulnerabilities in CISA KEV catalog with ransomware involvement
response = requests.get(
    'http://localhost:8080/v1/vuln',
    params={
        'kev': 'true',
        'ransomware': 'true'
    }
)

results = response.json()
print(json.dumps(results, indent=2))

# Search for vulnerabilities by CWE
response = requests.get(
    'http://localhost:8080/v1/vuln',
    params={
        'cwe': 'CWE-79',
        'severity': 'high'
    }
)
print(json.dumps(response.json(), indent=2))
```


