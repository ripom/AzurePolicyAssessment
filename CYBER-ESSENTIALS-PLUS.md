# Cyber Essentials & CE+ Compliance Assessment

> ⚠️ **CRITICAL DISCLAIMERS - PLEASE READ**

### This Tool Is NOT Official
- **NOT an official Microsoft tool** - Community-developed, no official support
- **NOT endorsed by Microsoft or UK NCSC** - Use at your own risk
- **Best-effort support only** - No warranties or guarantees provided
- **Results may be inaccurate** - Always verify with official sources

### This Feature Is Experimental
- **EXPERIMENTAL/PREVIEW STATUS** - Compliance checks and tests are in development
- **NOT 100% accurate** - Automated checks may not cover all scenarios
- **NOT for certification** - Does not certify or attest CE or CE+ compliance
- **Guidance only** - Use as a starting point, not definitive assessment
- **Community feedback needed** - Help us improve the checks

## Reference Documentation

The CE & CE+ compliance checks and tests in this tool are based on the following official documentation:

| Source | Link |
|---|---|
| **NCSC CE+ v3.2 Test Specification** | [cyber-essentials-plus-test-specification-v3-2.pdf](https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf) |
| **Azure CE+ Compliance Offering** | [Azure Compliance - UK Cyber Essentials Plus](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus) |

## Overview

The Cyber Essentials (CE) & CE+ compliance assessment feature uses the **built-in "UK NCSC Cyber Essentials v3.1" Azure Policy Initiative** (policy set definition) to evaluate your Azure environment against CE requirements. This provides accurate, Microsoft-maintained mappings of CE controls to Azure policies.

Additionally, the **`-CEP Test`** parameter (or legacy **`-RunCEPTests`** switch) executes automated tests based on the **[NCSC Cyber Essentials Plus v3.2 Test Specification](https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf)**, mapping the official test cases (TC1–TC5) to Azure Resource Graph queries where automatable, and flagging manual/physical subtests for the assessor.

**What This Tool Provides**: Initiative-based CE compliance assessment, gap analysis, and automated CE+ v3.2 test execution to help identify potential policy and configuration gaps against CE & CE+ requirements.

---

## ⚠️ Important Disclaimer

### Accuracy Notice
- **Initiative-based** — Compliance is evaluated using the built-in "UK NCSC Cyber Essentials v3.1" initiative, which is maintained by Microsoft
- **CE+ v3.2 tests are automated where possible** — Some subtests require physical/interactive verification and are flagged as MANUAL
- **Display names may vary** — Azure policies can have different names depending on initiative version or custom assignments
- **Partial coverage** — Some CE/CE+ requirements require manual processes outside of Azure Policy
- **Not certification** — This tool **does not certify** CE+ compliance; it provides guidance only

### What This Tool Does
✅ Evaluates the built-in "UK NCSC Cyber Essentials v3.1" Azure Policy Initiative compliance  
✅ Maps initiative policies to CE control groups (Firewalls, Secure Config, Malware, Access Control, Patching)  
✅ Runs automated CE+ v3.2 test specification checks (TC1–TC5) via Azure Resource Graph  
✅ Identifies PASS / FAIL / WARN / SKIP / MANUAL status for each test  
✅ Shows per-policy compliance state, enforcement status, and non-compliant resource counts  
✅ Flags manual/physical subtests for assessor completion  
✅ Generates actionable recommendations  
✅ Exports compliance data to CSV for reporting  

### What This Tool Does NOT Do
❌ Provide official CE+ certification  
❌ Cover all CE/CE+ requirements (some are physical/procedural — flagged as MANUAL)  
❌ Replace a formal security audit by a CREST-certified assessor  
❌ Guarantee 100% accuracy for all environments  
❌ Test on-premises or hybrid components  

---

## CE/CE+ Compliance Approach

### Initiative-Based Assessment (`-ShowCEPCompliance`)

The tool uses the **built-in "UK NCSC Cyber Essentials v3.1" Azure Policy Initiative** rather than static policy name matching. This provides:

- **Microsoft-maintained mappings** — Policy-to-CE control mappings are defined by Microsoft inside the initiative
- **Automatic updates** — When Microsoft updates the initiative, the tool picks up changes
- **Accurate grouping** — Policies are grouped by CE control areas via initiative metadata:

| CE Control Group | Initiative Group ID | Policies |
|---|---|---|
| **1. Firewalls & Internet Gateways** | `Cyber_Essentials_v3.1_1` | Network access, NSG, port restrictions |
| **2. Secure Configuration** | `Cyber_Essentials_v3.1_2` | Baselines, TLS, HTTPS, secure defaults |
| **3. Malware Protection** | `Cyber_Essentials_v3.1_3` | Endpoint protection, Defender, anti-malware |
| **4. Access Control** | `Cyber_Essentials_v3.1_4` | MFA, RBAC, privileged access, legacy auth |
| **5. Patch Management** | `Cyber_Essentials_v3.1_5` | System updates, vulnerability remediation |
| **General Requirements** | `Cyber_Essentials_v3.1_` | Cross-cutting requirements |

### CE+ v3.2 Test Specification (`-RunCEPTests`)

When `-RunCEPTests` is specified, the tool executes two phases of testing:

#### Phase 1 — Initiative Compliance Tests (T1–T5+)

| Test | Description | Method |
|---|---|---|
| **T1** | CE v3.1 initiative exists in tenant | Policy Set Definition lookup |
| **T2** | Initiative is assigned at appropriate scope | Assignment query |
| **T3** | On-demand compliance evaluation (optional) | `Start-AzPolicyComplianceScan` |
| **T4** | Per-policy compliance state within initiative | Azure Resource Graph |
| **T5+** | Per-control-group compliance evaluation | ARG grouped by CE area |

#### Phase 2 — CE+ v3.2 Test Specification (TC1–TC5)

Based on the [NCSC CE+ v3.2 Test Specification](https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf):

| Test Case | Title | Automated Checks | Manual Checks |
|---|---|---|---|
| **TC1** | Remote Vulnerability Assessment | Public IPs, open admin ports (RDP/SSH), vulnerability scan results | External scan tool verification |
| **TC2** | Patching / Authenticated Scan | Missing OS patches, CVSS ≥7.0 vulnerabilities, 14-day remediation window | Physical device patching |
| **TC3** | Malware Protection | Endpoint protection coverage, anti-malware agent status, signature currency | USB/download malware test |
| **TC4** | MFA Configuration | Conditional Access policies, MFA enforcement for users and admins | Interactive MFA prompt test |
| **TC5** | Account Separation | Admin vs standard role assignments, dedicated admin account checks | Privilege escalation test |

> **Note**: Subtests requiring physical or interactive verification are flagged as **MANUAL** in the output, with guidance for the assessor.

---

## How to Use

> **Note**: Since v3.0.0, the new `-CEP` parameter is the recommended interface. Legacy switches (`-ShowCEPCompliance`, `-RunCEPTests`, `-ExportCEPCompliance`) still work for backward compatibility.

### Show CE Compliance (Initiative-Based)
```powershell
# New way (recommended)
.\Get-PolicyAssignments.ps1 -CEP Show

# Legacy way (still works)
.\Get-PolicyAssignments.ps1 -ShowCEPCompliance
```

### Run CE+ v3.2 Test Specification
```powershell
# New way (recommended)
.\Get-PolicyAssignments.ps1 -CEP Test

# Legacy way (still works)
.\Get-PolicyAssignments.ps1 -RunCEPTests
```

### Export CE Compliance to CSV
```powershell
# New way (recommended)
.\Get-PolicyAssignments.ps1 -CEP Export

# Legacy way (still works)
.\Get-PolicyAssignments.ps1 -ExportCEPCompliance
```

### Combined Usage
```powershell
# Full CE+ assessment (new way)
.\Get-PolicyAssignments.ps1 -CEP Full

# Legacy way (still works)
.\Get-PolicyAssignments.ps1 -ShowRecommendations -RunCEPTests -ExportCEPCompliance
```

### Parameter Summary

| New (v3.0+) | Legacy (still works) | Description |
|---|---|---|
| `-CEP Show` | `-ShowCEPCompliance` | Shows CE initiative compliance grouped by control area |
| `-CEP Test` | `-RunCEPTests` | Runs Phase 1 (initiative tests T1-T5+) and Phase 2 (v3.2 spec TC1-TC5). Implies Show |
| `-CEP Export` | `-ExportCEPCompliance` | Exports CE compliance data to CSV. Implies Show |
| `-CEP Full` | All three switches | All of the above |

**Output File**: `CyberEssentialsPlus_Compliance_YYYYMMDD_HHMMSS.csv`

### CSV Export Format

| Column | Description |
|---|---|
| **CE Category** | The CE control area (e.g., "1. Firewalls & Internet Gateways") |
| **Required Control** | The Azure Policy display name from the initiative |
| **Status** | `Deployed` or `Missing` |
| **Assignment Name** | The actual policy assignment name (if deployed) |
| **Enforcement Mode** | `Default` or `DoNotEnforce` |
| **Non-Compliant Resources** | Count of non-compliant resources (if deployed) |
| **Recommendation** | Action to take (e.g., "Enable enforcement", "Assign this policy") |

---

## Interpreting Results

### CE Compliance Output (`-ShowCEPCompliance`)

```
🇬🇧 CYBER ESSENTIALS COMPLIANCE (Initiative-Based):

   📋 1. Firewalls & Internet Gateways
      ✓ [Azure Policy Name] ── Compliant (0 non-compliant)
      ⚠ [Azure Policy Name] ── Non-compliant (3 non-compliant resources)
      ✗ [Azure Policy Name] ── Not assigned

   📊 COMPLIANCE SUMMARY:
      Total CE Controls: 42
      Compliant: 35
      Non-Compliant: 5
      Not Assigned: 2
      Compliance Score: 83.3%
```

### CE+ v3.2 Test Results (`-RunCEPTests`)

```
═══════════════════════════════════════════════════════════════
 PHASE 1 — Initiative Compliance Tests
═══════════════════════════════════════════════════════════════
 [PASS] T1: CE v3.1 initiative exists in tenant
 [PASS] T2: Initiative is assigned (2 assignments found)
 [SKIP] T3: On-demand compliance scan (skipped)
 [PASS] T4: Per-policy compliance evaluated
 [WARN] T5: 2. Secure Configuration — 2 non-compliant policies

═══════════════════════════════════════════════════════════════
 PHASE 2 — CE+ v3.2 Test Specification
═══════════════════════════════════════════════════════════════
 TC1: Remote Vulnerability Assessment
   [PASS]   TC1.1 — No public IPs with open admin ports (RDP/SSH)
   [WARN]   TC1.2 — 3 VMs missing vulnerability assessment
   [MANUAL] TC1.3 — External vulnerability scan (requires external tool)
 
 TC2: Patching / Authenticated Scan
   [PASS]   TC2.1 — All machines have system updates installed
   [FAIL]   TC2.2 — 5 high-severity vulnerabilities (CVSS ≥ 7.0) older than 14 days
   [MANUAL] TC2.3 — Physical device patch verification
 ...
```

### Test Result Statuses

| Status | Meaning |
|---|---|
| **PASS** | Check passed — requirement met |
| **FAIL** | Check failed — action required |
| **WARN** | Partial compliance — review recommended |
| **SKIP** | Test skipped (e.g., prerequisite not met) |
| **MANUAL** | Requires physical/interactive verification by assessor |

### Compliance Score Interpretation

| Score | Color | Interpretation |
|---|---|---|
| **80-100%** | 🟢 Green | Strong CE alignment |
| **50-79%** | 🟡 Yellow | Moderate coverage, gaps exist |
| **0-49%** | 🔴 Red | Significant gaps, action required |

---

## Known Limitations

### 1. Initiative Availability
The tool relies on the **built-in "UK NCSC Cyber Essentials v3.1" initiative**. If this initiative:
- Is not available in your Azure region/cloud — the CE compliance features will not work
- Is updated by Microsoft — groupings or policy mappings may change

**Mitigation**: The tool checks for initiative existence (Test T1) and reports if it's missing.

### 2. Assignment Scope
The initiative must be **assigned** at an appropriate scope (management group, subscription, or resource group) for compliance data to be available.

**Mitigation**: Test T2 checks for assignments. If missing, the tool provides guidance on how to assign it.

### 3. Compliance Evaluation Delay
Azure Policy compliance evaluation is **not instantaneous**. New assignments may take up to 24 hours for initial evaluation.

**Mitigation**: Use `-RunCEPTests` which can trigger an on-demand scan (Test T3), though this also takes time.

### 4. Manual/Physical Test Cases
The CE+ v3.2 test specification includes subtests that **cannot be automated** via Azure:
- **TC1.3** — External vulnerability scanning with a dedicated tool
- **TC2.3** — Physical device patch verification
- **TC3.3** — USB/download malware interception test
- **TC4.3** — Interactive MFA prompt verification
- **TC5.3** — Privilege escalation attempt

These are flagged as **MANUAL** in the output for the assessor to complete.

**Reference**: [NCSC CE+ v3.2 Test Specification](https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf)

### 5. Enforcement vs. Compliance
- A policy may be **deployed** but set to `DoNotEnforce` mode
- The tool flags this but counts it separately
- Actual CE/CE+ certification requires **active enforcement**

**Mitigation**: Review policies marked as warnings and enable enforcement.

### 6. Azure Resource Graph Limitations
- ARG queries may have slight delays in reflecting the latest state
- Some resource types may not be fully indexed in ARG
- Tenant-scope queries require appropriate RBAC permissions

---

## Providing Feedback

### How to Contribute

This is an **experimental feature** and we welcome feedback:

1. **Report Test Inaccuracies**  
   If a test result doesn't match your environment, open an issue with:
   - Test case ID (e.g., TC2.1)
   - Expected vs actual result
   - Relevant Azure configuration details

2. **Suggest Additional Checks**  
   If you know of Azure Resource Graph queries that better map to CE+ v3.2 requirements, share them!

3. **Report Initiative Changes**  
   If Microsoft updates the "UK NCSC Cyber Essentials v3.1" initiative and the tool doesn't reflect it, let us know.

### Roadmap

Potential future enhancements:
- [x] Initiative-based CE compliance assessment (v3.0.0)
- [x] CE+ v3.2 test specification automated checks TC1-TC5 (v3.0.0)
- [x] MANUAL test flagging for assessor completion (v3.0.0)
- [x] Exemption awareness and scope coverage analysis (v3.0.0)
- [ ] HTML report generation with test evidence
- [ ] Integration with Microsoft Defender for Cloud recommendations
- [ ] CE/CE+ certification readiness checklist / scorecard
- [ ] Support for future NCSC test specification versions

---

## Frequently Asked Questions

### Q: Does this tool certify my environment for CE+?
**A:** No. This tool provides **guidance** and **gap analysis**. Official CE+ certification requires an external audit by a CREST-certified assessor. See the [NCSC CE+ v3.2 Test Specification](https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf) for the full certification requirements.

### Q: What Azure Policy Initiative does this tool use?
**A:** The built-in **"UK NCSC Cyber Essentials v3.1"** initiative (policy set definition), maintained by Microsoft. This covers **Cyber Essentials (CE) basic** requirements. See [Azure CE+ Compliance Offering](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus) for details.

### Q: What are the MANUAL test results?
**A:** Some CE+ v3.2 test subtests require physical or interactive verification (e.g., plugging in a USB drive with malware, verifying an MFA prompt appears). These cannot be automated via Azure APIs and are flagged for an assessor to complete manually.

### Q: Why do some tests show as SKIP?
**A:** Tests are skipped when prerequisites aren't met. For example, if the CE initiative isn't assigned (T2 fails), per-policy compliance tests (T4/T5) are skipped because there's no compliance data to evaluate.

### Q: What permissions do I need?
**A:** You need:
- **Reader** access at management group or subscription scope
- **Resource Policy Contributor** if triggering on-demand compliance scans
- Azure Resource Graph access for the v3.2 test specification queries

### Q: Can I run just the v3.2 test specification without the initiative compliance?
**A:** No. `-RunCEPTests` runs both Phase 1 (initiative compliance) and Phase 2 (v3.2 test specification) together. Phase 1 results inform Phase 2 context.

### Q: Is this tool officially supported by Microsoft or NCSC?
**A:** No. This is a **community tool** for guidance purposes. It is not endorsed by Microsoft or the UK National Cyber Security Centre.

---

## Additional Resources

### CE/CE+ Reference Documentation
- 📄 [NCSC CE+ v3.2 Test Specification (PDF)](https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf) — Official test cases this tool implements
- 🔗 [Azure Compliance - UK Cyber Essentials Plus](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus) — Microsoft's CE+ compliance offering page

### General Resources
- [UK NCSC Cyber Essentials Scheme](https://www.ncsc.gov.uk/cyberessentials/overview)
- [Azure Policy Documentation](https://learn.microsoft.com/en-us/azure/governance/policy/)
- [Azure Resource Graph Documentation](https://learn.microsoft.com/en-us/azure/governance/resource-graph/)
- [Azure Security Baseline](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)

---

## Version History

| Version | Date | Changes |
|---|---|---|
| 3.0.0 | 2026-02-19 | Policy exemptions support, Landing Zone Analysis in HTML report, `-CEP` parameter, YAML delta |
| 3.0.0 | 2026-02-10 | Consolidated into v3.0 — `-CEP` parameter replaces legacy switches, initiative-based compliance, CE+ v3.2 test specification (TC1-TC5) |
| 2.2.0 | 2026-02-05 | Initial CE compliance mapping (experimental) |

---

**Last Updated**: February 19, 2026  
**Script Version**: 3.0.0  
**Status**: Experimental - Feedback Welcome 🙏  
**Based on**: [NCSC CE+ v3.2 Test Specification](https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf) | [Azure CE+ Compliance Offering](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus)
