# Vulnerawise API Documentation

The Vulnerawise API provides access to vulnerability data filtered by various criteria (e.g., CVE IDs, date ranges, description, feed, etc.) with built-in pagination. This guide will help you download, start, and use the API.

---

## Installation and Starting the API

You can download precompiled binaries for your platform from the Vulnerawise GitHub Releases. Here are examples for several platforms:

### Linux (amd64 and arm64)

For **Linux (amd64)**:

```bash
wget -q -O ./vulnerawise-linux-amd64 https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-linux-amd64
chmod +x ./vulnerawise-linux-amd64
./vulnerawise-linux-amd64 serve
```

For **Linux (arm64)**:

```bash
wget -q -O ./vulnerawise-linux-arm64 https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-linux-arm64
chmod +x ./vulnerawise-linux-arm64
./vulnerawise-linux-arm64 serve
```

### macOS (Darwin)

For **macOS (amd64)**:

```bash
wget -q -O ./vulnerawise-darwin-amd64 https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-darwin-amd64
chmod +x ./vulnerawise-darwin-amd64
./vulnerawise-darwin-amd64 serve
```

For **macOS (arm64)**:

```bash
wget -q -O ./vulnerawise-darwin-arm64 https://github.com/vulnerawise/vulnerawise/releases/download/v0.1/vulnerawise-darwin-arm64
chmod +x ./vulnerawise-darwin-arm64
./vulnerawise-darwin-arm64 serve
```

### Windows

For **Windows (amd64)** and **Windows (arm64)**, download the appropriate binary from the releases page. Then, from the Command Prompt or PowerShell, run:

```cmd
vulnerawise-windows-amd64.exe serve
```

or

```cmd
vulnerawise-windows-arm64.exe serve
```
---

## Endpoint

**GET /v1/vuln**

### Query Parameters

- **cve** (string, optional)
  Comma-separated list of CVE IDs (e.g., `CVE-2024-12345,CVE-2024-23456`).

- **published_date_range** (string, optional)
  Date range filter in the format `YYYY-MM-DD:YYYY-MM-DD`.

- **published** (string, optional)
  Filter for CVEs published relative to now (e.g., `last 10 days`).

- **last_modified** (string, optional)
  Filter for CVEs last modified either relatively (e.g., `last 30 days`) or by a date range (`YYYY-MM-DD:YYYY-MM-DD`).

- **maturity** (string, optional)
  Filter by exploit maturity (values like `active`, `weaponized`, `poc`, or `none`).

- **severity** (string, optional)
  Filter by severity (e.g., `low`, `medium`, `high`).

- **exploit_published** (string, optional)
  Filter by the published date of associated exploit data (e.g., `last 7 days`).

- **description** (string, optional)
  Filter by a substring in the vulnerability description.

- **feed** (string, optional)
  Filter by timeline reference source (e.g., `metasploit`).

- **page** (integer, optional)
  Page number for pagination (default is `1`).

- **limit** (integer, optional)
  Number of records per page (default is `100`, maximum is `100`).

### Response Structure

The API returns a JSON object that includes:

- **metadata**: Contains metadata such as the timestamp.
- **data**: An array of vulnerability objects.
- **page**: The current page number.
- **limit**: The number of records returned per page.
- **returned**: The count of records returned in this response.

Example snippet:

```json
{
  "metadata": {
    "timestamp": "2025-02-22T15:04:05Z"
  },
  "data": [
    {
      "cve": {
        "id": "CVE-2024-12345",
        "description": "Example vulnerability description.",
        "metadata": {
          "publishedDate": "2024-01-15",
          "lastModifiedDate": "2024-02-01",
          "confidenceLevel": "high",
          "severity": "medium"
        },
        "impact": {
          "cisa_kev": false,
          "reported_exploited": true,
          "exploit_maturity": "poc",
          "automatable": false
        },
        "counts": {
          "public_exploit_count": 2
        },
        "epss": {
          "score": 3.4,
          "percentile": 85.2
        },
        "metrics": [
          {
            "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        ],
        "timeline": {}
      }
    }
  ],
  "page": 1,
  "limit": 100,
  "returned": 100
}
```

---

## Example Usage

### Bash (curl)

```bash
curl "http://localhost:8080/v1/vuln?published=last%2020%20days&description=microsoft&maturity=active&page=1&limit=50"
```

### Python (using requests)

```python
import requests

# Define query parameters.
params = {
    "published": "last 20 days",
    "description": "microsoft",
    "maturity": "active",
    "page": 1,
    "limit": 50
}

# Make the GET request.
response = requests.get("http://localhost:8080/v1/vuln", params=params)

# Check for successful response.
if response.ok:
    data = response.json()
    print("Response JSON:", data)
else:
    print("Error:", response.status_code, response.text)
```

### Golang (using net/http)

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

type Response struct {
	Metadata struct {
		Timestamp string `json:"timestamp"`
	} `json:"metadata"`
	Data     []interface{} `json:"data"`
	Page     int           `json:"page"`
	Limit    int           `json:"limit"`
	Returned int           `json:"returned"`
}

func main() {
	baseURL := "http://localhost:8080/v1/vuln"
	params := url.Values{}
	params.Add("published", "last 10 days")
	params.Add("description", "microsoft")
	params.Add("feed", "metasploit")
	params.Add("page", strconv.Itoa(1))
	params.Add("limit", strconv.Itoa(50))

	fullURL := baseURL + "?" + params.Encode()

	resp, err := http.Get(fullURL)
	if err != nil {
		log.Fatalf("Error fetching data: %v", err)
	}
	defer resp.Body.Close()

	var result Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("Error decoding JSON: %v", err)
	}

	fmt.Printf("Response: %+v\n", result)
}
```


