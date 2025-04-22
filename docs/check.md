# **Vulnerability Check & Policy Evaluation**

## **Overview**
The vulnerability check and policy evaluation system helps security teams assess CVEs against organizational security policies. The system can evaluate both scan reports (containing multiple vulnerabilities) and individual CVEs to determine if they comply with your security requirements.

This document explains how to use the check capabilities via both API and CLI, interpret results, and understand the underlying policy evaluation process. For troubleshooting common check issues, refer to the FAQ section at the end of this document.

---

## **Using the CLI**

You can also evaluate CVEs and scan reports directly from the command line.

### **Evaluating Individual CVEs**
```bash
# Basic evaluation of a CVE
vulnerawise check --cve CVE-2023-4966

# Evaluation with specific impact and exposure levels
vulnerawise check --cve CVE-2023-4966 --impact high --exposure open
```

#### **Parameters:**
- **--cve** (required): The CVE ID to evaluate (e.g., CVE-2023-4966)
- **--impact** (optional): Override the default impact level (critical, high, medium, low)
- **--exposure** (optional): Define the exposure level (open, controlled, small)
- **--format** (optional): Output format (table or json, default: table)

### **Evaluating Container Images**
Scan container images for vulnerabilities and evaluate them against security policies:

```bash
# Scan a container image
vulnerawise check --image alpine:latest

# Scan with custom impact level
vulnerawise check --image nginx:1.21 --impact high
```

### **Processing SBOM Files**
Evaluate Software Bill of Materials (SBOM) files against security policies:

```bash
# Process an SBOM file
vulnerawise check --sbom path/to/sbom.json

# Process SBOM from stdin
cat sbom.json | vulnerawise check --sbom -
```

### **Scanning Local Directories**
Scan local directories for vulnerabilities in dependencies:

```bash
# Scan a local project directory
vulnerawise check --path /path/to/project

# Scan with custom policy options
vulnerawise check --path /path/to/project --exposure open
```

### **Evaluating Scanner Results**
For bulk vulnerability assessment, you can process existing scanner reports:

```bash
# Process scanner results
vulnerawise check --scan-results grype.json

# Process scanner results with custom policy fields
vulnerawise check --scan-results trivy.json --impact high --exposure open
```

#### **Common CLI Options:**
- **--format** (optional): Output format (table or json, default: table)
- **--server** (optional): Server URL for vulnerability scanning (default: http://localhost:8080)
- **--decision** (optional): Filter results by decision type (immediate, out-of-cycle, scheduled, defer)

#### **Supported Scan Report Formats:**
- Grype (JSON format)
- Trivy (JSON format)

---

## **Understanding Output**

### **Table Format Output**
When using the default table format, results are presented in a tabular form:

```
=== Policy Check Results ===
+--------------------------------+---------------------------+-----------------+------------+
| CVE ID                         | POLICY                    | DECISION        | ENFORCED   |
+--------------------------------+---------------------------+-----------------+------------+
| CVE-2021-44832                 | ssvc_scheduled            | scheduled       | No         |
| CVE-2021-45105                 | ssvc_scheduled            | scheduled       | No         |
| CVE-2021-45046                 | ssvc_out_of_cycle         | out-of-cycle    | No         |
| CVE-2021-44228                 | ssvc_immediate            | immediate       | Yes        |
+--------------------------------+---------------------------+-----------------+------------+

=== Policy Check Summary ===
Total vulnerabilities checked: 4
Vulnerabilities with policy matches: 4
Total policy matches: 4

Breakdown by decision:
  Immediate: 1
  Out-Of-Cycle: 1
  Scheduled: 2

Breakdown by severity:
  No severity data available

FAIL: At least one enforced policy was matched
```

- **CVE ID**: The identifier of the vulnerability
- **POLICY**: The policy that matched this vulnerability
- **DECISION**: The recommended action (immediate, out-of-cycle, scheduled, defer)
- **ENFORCED**: Whether the policy is enforced (Yes/No)

### **JSON Format Output**
When using `--format json`, results are returned in a structured JSON format:

```json
{
  "results": [
    {
      "cve": "CVE-2021-44832",
      "matches": [
        {
          "decision": "scheduled",
          "enforced": false,
          "outcome": "Priority: scheduled - Vulnerability: CVE-2021-44832",
          "policy": "ssvc_scheduled"
        }
      ]
    },
    {
      "cve": "CVE-2021-45105",
      "matches": [
        {
          "decision": "scheduled",
          "enforced": false,
          "outcome": "Priority: scheduled - Vulnerability: CVE-2021-45105",
          "policy": "ssvc_scheduled"
        }
      ]
    },
    {
      "cve": "CVE-2021-45046",
      "matches": [
        {
          "decision": "out-of-cycle",
          "enforced": false,
          "outcome": "Priority: out-of-cycle - Vulnerability: CVE-2021-45046",
          "policy": "ssvc_out_of_cycle"
        }
      ]
    },
    {
      "cve": "CVE-2021-44228",
      "matches": [
        {
          "decision": "immediate",
          "enforced": true,
          "outcome": "Priority: immediate - Vulnerability: CVE-2021-44228",
          "policy": "ssvc_immediate"
        }
      ]
    }
  ],
  "total_checks": 4,
  "total_matches": 4,
  "enforced": true,
  "overrides": {
    "exposure": "small",
    "impact": "critical"
  }
}
```

---

## **Decision Policy Framework**

Our vulnerability evaluation uses a structured decision policy based on the Stakeholder-Specific Vulnerability Categorization (SSVC) framework, which considers these key factors:

### **1. Exploitation Status**
- **none**: No evidence of active exploitation or public proof of concept (PoC)
- **poc**: Public proof-of-concept exists (sources such as ExploitDB or Metasploit)
- **active**: Reliable evidence of active exploitation in the wild

### **2. Weaponized**
Indicates whether the vulnerability has been packaged into a deliverable exploit:
- **false**: Not weaponized
- **true**: Packaged into a re-usable exploit (e.g., incorporated into widely available exploitation frameworks or malware kits)

### **3. Accessible Attack Surface**
- **small**: Local service or program; highly controlled environment
- **controlled**: Networked service with access restrictions or mitigations in place
- **open**: Internet or similarly exposed network without plausible access restrictions

### **4. Automatable**
Determines if the exploit can be automatically leveraged across multiple targets:
- **false**: Requires manual intervention or target-specific customization
- **true**: Can be automated using scripts or tools for broad exploitation

### **5. Impact**
Reflects the potential consequences on the organization:
- **low**: No significant impact on mission-critical operations
- **medium**: Partial degradation of mission capability
- **high**: Significant reduction in organizational capabilities
- **critical**: Complete disruption of mission-critical operations

---

## **Policy Decisions**

Based on these factors, the following decisions are made:

| **Decision**     | **Description**                                         | **Recommended Action**                                                                           |
|------------------|---------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| **Defer**        | No immediate action required                            | Address during scheduled maintenance cycles                                                     |
| **Scheduled**    | Action required during planned update cycles            | Patch in the next planned update cycle                                                          |
| **Out-of-Cycle** | Requires prompt remediation beyond regular updates      | Apply targeted mitigation as soon as feasible                                                   |
| **Immediate**    | Critical risk demanding urgent action                   | Prioritize fix deployment immediately, potentially pausing normal operations if necessary         |

---

## **Best Practices**

1. **Regular Scanning:** Schedule frequent vulnerability scans and consistently check the results.
2. **Prioritize by Decision:** Address vulnerabilities beginning with those marked "immediate."
3. **Override When Needed:** Use impact and exposure parameters in what-if analyses to test alternate risk scenarios.
4. **Policy Adjustments:** Regularly review and adjust policies with your security teams as your risk tolerance evolves.
5. **Pipeline Integration:** Integrate vulnerability checks into CI/CD pipelines for early detection.
6. **Exit Code Usage:** Use the exit code (0=success, 1=policy violation) to automate build decisions.

---

## **FAQ**

### **Why do I get different decisions for the same CVE?**
Decisions can vary based on:
- Exploitation status changes (e.g., a PoC was released)
- Your override settings for exposure or impact
- Changes in policy definitions

### **How do I interpret the "enforced" status?**
- **Yes**: Policy is enforced and violations will cause an exit code of 1, which can be used to fail builds in CI/CD
- **No**: Policy is advisory only and won't cause failures in automated systems

### **How do I update the vulnerability database?**
Use `vulnerawise updatedb` to ensure you have the latest vulnerability data.

