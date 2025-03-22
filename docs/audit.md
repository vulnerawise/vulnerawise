# **Vulnerability Audit & Policy Evaluation**

## **Overview**
The vulnerability audit and policy evaluation system helps security teams assess CVEs against organizational security policies. The system can evaluate both scan reports (containing multiple vulnerabilities) and individual CVEs to determine if they comply with your security requirements.

This document explains how to use the audit capabilities via both API and CLI, interpret results, and understand the underlying policy evaluation process. For troubleshooting common audit issues, refer to the FAQ section at the end of this document.

---

## **Using the API**

### **Evaluating Individual CVEs**
You can quickly check if a specific CVE passes your security policies using a simple API request:

```bash
# Basic evaluation of a CVE
curl "https://api.vulnerawise.ai/v1/audit?cve=CVE-2023-4966"

# Evaluation with specific impact and exposure levels
curl "https://api.vulnerawise.ai/v1/audit?cve=CVE-2023-4966&impact=high&exposure=open"
```

---

## **Using the CLI**

You can also evaluate CVEs and scan reports directly from the command line.

### **Evaluating Individual CVEs**
```bash
# Basic evaluation of a CVE
vulnerawise audit cve CVE-2023-4966

# Evaluation with specific impact and exposure levels
vulnerawise audit cve CVE-2023-4966 --impact high --exposure open

# Get detailed output in JSON format
vulnerawise audit cve CVE-2023-4966 --format json
```

#### **Parameters:**
- **cve** (required): The CVE ID to evaluate (e.g., CVE-2023-4966)
- **impact** (optional): Override the default impact level (critical, high, medium, low)
- **exposure** (optional): Define the exposure level (open, controlled, small)
- **--format** (optional): Output format (e.g., json, table)

### **Evaluating Scan Reports**
For bulk vulnerability assessment, you can upload scan reports in supported formats.

```bash
# API: Upload a vulnerability scan report
curl -X POST "https://api.vulnerawise.ai/v1/audit" \
  -H "Content-Type: application/json" \
  -d @your-scan-report.json

# CLI: Evaluate a scan report
vulnerawise audit your-scan-report.json

# CLI: Evaluate a scan report with custom policy fields
vulnerawise audit your-scan-report.json --impact high --exposure open
```

Supported scan report formats include:
- Grype (JSON format)
- Trivy (JSON format)
- Docker Scout (GitLab format)

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
| **Immediate**    | Critical risk demanding urgent action                  | Prioritize fix deployment immediately, potentially pausing normal operations if necessary         |

---

## **Best Practices**

1. **Regular Scanning:** Schedule frequent vulnerability scans and consistently audit the results.
2. **Prioritize by Decision:** Address vulnerabilities beginning with those marked “immediate.”
3. **Override When Needed:** Use impact and exposure parameters in what-if analyses to test alternate risk scenarios.
4. **Policy Adjustments:** Regularly review and adjust policies with your security teams as your risk tolerance evolves.

---

## **Troubleshooting & FAQ**

- **Q:** Why am I not getting JSON output?
  **A:** Make sure to include the `--format json` flag when running CLI audits.
- **Q:** What do I do if my scan report isn’t recognized?
  **A:** Verify that your scan report matches one of the supported formats (Grype, Trivy, or Docker Scout). Consult the tool’s release notes for updates on supported formats.

By following this structured approach and best practices, you can efficiently evaluate vulnerabilities and prioritize remediation based on organizational risk.

