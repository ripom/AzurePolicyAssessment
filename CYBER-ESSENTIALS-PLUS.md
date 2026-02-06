# Cyber Essentials Plus Compliance Assessment

> ⚠️ **CRITICAL DISCLAIMERS - PLEASE READ**

### This Tool Is NOT Official
- **NOT an official Microsoft tool** - Community-developed, no official support
- **NOT endorsed by Microsoft or UK NCSC** - Use at your own risk
- **Best-effort support only** - No warranties or guarantees provided
- **Results may be inaccurate** - Always verify with official sources

### This Feature Is Experimental
- **EXPERIMENTAL/PREVIEW STATUS** - Policy mappings are in development
- **NOT 100% accurate** - Approximate mappings only, subject to errors
- **NOT for certification** - Does not certify or attest CE+ compliance
- **Guidance only** - Use as a starting point, not definitive assessment
- **Community feedback needed** - Help us improve the mappings

**Reference**: [Azure Compliance - UK Cyber Essentials Plus](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus?utm_source=copilot.com)

## Overview

The Cyber Essentials Plus (CE+) compliance assessment feature maps UK NCSC Cyber Essentials Plus requirements to Azure Policy assignments. This helps organizations understand their Azure environment's alignment with CE+ certification requirements.

**What This Tool Provides**: Guidance and gap analysis to help identify potential policy gaps against CE+ requirements.

---

## ⚠️ Important Disclaimer

### Accuracy Notice
- **Policy mappings are approximate** - Not all CE+ requirements have direct Azure Policy equivalents
- **Display names may vary** - Azure policies can have different names depending on how they were assigned
- **Custom policies** - If using custom policy definitions, they may not match the standard naming
- **Partial coverage** - Some CE+ requirements require manual processes outside of Azure Policy
- **Not certification** - This tool **does not certify** CE+ compliance; it provides guidance only

### What This Tool Does
✅ Maps CE+ requirements to common Azure Policy names  
✅ Identifies which policies are deployed vs. missing  
✅ Shows enforcement status and non-compliant resources  
✅ Generates actionable recommendations  
✅ Exports compliance data to CSV for reporting  

### What This Tool Does NOT Do
❌ Provide official CE+ certification  
❌ Cover all CE+ requirements (some are procedural)  
❌ Replace a formal security audit  
❌ Guarantee 100% accurate mapping to all policy variations  

---

## CE+ Requirements to Azure Policy Mapping

### 1️⃣ Patch Management

| CE+ Requirement | Azure Policy Name |
|---|---|
| OS must be fully patched | `System updates should be installed on your machines` |
| Updates must be applied promptly | `Missing system updates should be remediated` |
| Update mechanism must exist | `Machines should be configured to automatically install updates` |
| Centralised patching | `Update Manager should be enabled for all VMs` |

---

### 2️⃣ Firewalls & Internet Boundary

| CE+ Requirement | Azure Policy Name |
|---|---|
| Boundary firewall / traffic restriction | `Network Security Groups should be applied to all subnets` |
| Boundary firewall / traffic restriction | `Network Security Groups should be applied to all NICs` |
| Prevent unnecessary public exposure | `Public network access should be disabled for PaaS services` |
| Protect admin ports | `Just-In-Time network access should be enabled on VMs` |
| Perimeter firewall (if used) | `Azure Firewall should be deployed` |

---

### 3️⃣ Secure Configuration

| CE+ Requirement | Azure Policy Name |
|---|---|
| Secure OS configuration | `Windows machines should meet security baseline` |
| Secure OS configuration | `Linux machines should meet security baseline` |
| Enforce secure protocols | `TLS version should be set to 1.2 or higher` |
| Secure storage configuration | `Secure transfer to storage accounts should be enabled` |
| Enforce HTTPS | `App Service apps should only be accessible over HTTPS` |
| Encryption in transit | `Enforce encryption in transit for PaaS services` |

---

### 4️⃣ Malware Protection

| CE+ Requirement | Azure Policy Name |
|---|---|
| Anti-malware installed | `Endpoint protection should be installed on all VMs` |
| Real-time protection | `Microsoft Defender for Endpoint should be enabled` |
| Server protection | `Azure Defender for Servers (Plan 1 or 2) should be enabled` |
| Vulnerability scanning | `Vulnerability assessment should be enabled on machines` |

---

### 5️⃣ Access Control

| CE+ Requirement | Azure Policy Name |
|---|---|
| MFA for all users | `MFA should be enabled for all Azure AD users` |
| MFA for privileged roles | `MFA should be enabled for accounts with write permissions` |
| Privileged access control | `Privileged Identity Management should be enabled` |
| Least privilege | `Role assignments should not use wildcard permissions` |
| Remove legacy auth | `Legacy authentication protocols should be blocked` |

---

## How to Use

### Basic Usage (Console Output Only)
```powershell
# Run with CE+ compliance check
.\Get-PolicyAssignments.ps1 -ShowRecommendations
```

The CE+ compliance section will automatically appear when using `-ShowRecommendations`.

### Export to CSV
```powershell
# Export CE+ compliance data to CSV
.\Get-PolicyAssignments.ps1 -ShowRecommendations -ExportCEPCompliance
```

**Output**: `CyberEssentialsPlus_Compliance_YYYYMMDD_HHMMSS.csv`

### CSV Export Format

| Column | Description |
|---|---|
| **CE+ Category** | The CE+ requirement area (e.g., "Patch Management") |
| **Required Control** | The Azure Policy display name |
| **Status** | `Deployed` or `Missing` |
| **Assignment Name** | The actual policy assignment name (if deployed) |
| **Enforcement Mode** | `Default` or `DoNotEnforce` |
| **Non-Compliant Resources** | Count of non-compliant resources (if deployed) |
| **Recommendation** | Action to take (e.g., "Enable enforcement", "Assign this policy") |

---

## Interpreting Results

### Console Output

```
🇬🇧 CYBER ESSENTIALS PLUS COMPLIANCE:

   📋 Patch Management
      ✓ System updates should be installed on your machines
      ✓ Missing system updates should be remediated (NOT ENFORCED)
      ✗ Machines should be configured to automatically install updates (MISSING)
      ✗ Update Manager should be enabled for all VMs (MISSING)

   📊 COMPLIANCE SUMMARY:
      Total CE+ Controls Mapped: 24
      Deployed: 18
      Missing: 6
      Compliance Score: 75.0%
```

### Compliance Score Interpretation

| Score | Color | Interpretation |
|---|---|---|
| **80-100%** | 🟢 Green | Strong CE+ alignment |
| **50-79%** | 🟡 Yellow | Moderate coverage, gaps exist |
| **0-49%** | 🔴 Red | Significant gaps, action required |

---

## Known Limitations

### 1. Policy Naming Variations
Azure policies can be assigned with custom display names. The tool uses pattern matching (`-like "*PolicyName*"`) which may:
- **Miss** policies with heavily customized names
- **Match** unrelated policies with similar names

**Mitigation**: Review the exported CSV and cross-reference with your actual policy assignments.

### 2. Built-In vs. Custom Policies
- The tool maps to **built-in Azure Policy display names**
- If you use **custom policy definitions**, they may not be detected
- **Azure Landing Zone (ALZ)** policies use different naming conventions

**Mitigation**: Manually verify custom policies against CE+ requirements.

### 3. Enforcement vs. Compliance
- A policy may be **deployed** but set to `DoNotEnforce` mode
- The tool flags this as a warning but counts it as "deployed"
- Actual CE+ certification requires **active enforcement**

**Mitigation**: Review policies marked as `(NOT ENFORCED)` and enable enforcement.

### 4. Out-of-Scope CE+ Requirements
CE+ includes requirements that cannot be fully validated by Azure Policy alone:
- **Physical security** of on-premises devices
- **User awareness training**
- **Incident response procedures**
- **Asset management processes**

**Mitigation**: Use this tool as part of a broader CE+ compliance program.

### 5. Policy Assignment Scope
The tool checks if a policy **exists anywhere** in your environment. It does not verify:
- **Complete coverage** across all subscriptions/resources
- **Exemptions** that may exclude critical resources
- **Inheritance** from management groups

**Mitigation**: Review the standard export (`-Export`) to verify scope coverage.

---

## Providing Feedback

### How to Contribute

This is an **experimental feature** and we welcome feedback:

1. **Report Inaccurate Mappings**  
   If you find a policy name mismatch, open an issue with:
   - Expected CE+ requirement
   - Actual Azure Policy name you're using
   - Screenshot or policy definition link

2. **Suggest Additional Mappings**  
   If you know of better Azure policies that map to CE+ requirements, share them!

3. **Share Custom Policy Definitions**  
   If you've built custom policies for CE+ compliance, we'd love to see them.

### Roadmap

Potential future enhancements:
- [ ] Support for Azure Landing Zone (ALZ) policy naming conventions
- [ ] Detection of custom policy definitions
- [ ] Scope coverage analysis (per subscription/management group)
- [ ] Integration with Azure Security Center/Defender recommendations
- [ ] Exemption awareness
- [ ] CE+ certification readiness checklist

---

## Frequently Asked Questions

### Q: Does this tool certify my environment for CE+?
**A:** No. This tool provides **guidance** and **gap analysis**. Official CE+ certification requires an external audit by a CREST-certified body.

### Q: Why do some policies show as "MISSING" when I know they're assigned?
**A:** Possible reasons:
- Policy has a custom display name
- Using a custom policy definition (not built-in)
- Policy is assigned at a different scope (check with `-IncludeSubscriptions`)
- Pattern matching failed due to name variations

### Q: What if I use Azure Landing Zone (ALZ) policies?
**A:** ALZ policies often have different naming (e.g., `Deny-PublicIP` vs. `Public IPs should be denied`). The tool may not detect these. We're working on ALZ support.

### Q: Can I customize the policy mappings?
**A:** Currently, no. The mappings are hardcoded in the script. Future versions may support custom mapping files.

### Q: Is this tool officially supported by Microsoft or NCSC?
**A:** No. This is a **community tool** for guidance purposes. It is not endorsed by Microsoft or the UK National Cyber Security Centre.

---

## Additional Resources

- [UK NCSC Cyber Essentials Scheme](https://www.ncsc.gov.uk/cyberessentials/overview)
- [Azure Compliance - UK Cyber Essentials Plus](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus?utm_source=copilot.com)
- [Azure Policy Documentation](https://learn.microsoft.com/en-us/azure/governance/policy/)
- [Azure Security Baseline](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [Azure Landing Zone Policies](https://github.com/Azure/Enterprise-Scale/wiki/ALZ-Policies)

---

## Version History

| Version | Date | Changes |
|---|---|---|
| 2.2.0 | 2026-02-05 | Initial CE+ compliance mapping (experimental) |

---

**Last Updated**: February 5, 2026  
**Status**: Experimental - Feedback Welcome 🙏
