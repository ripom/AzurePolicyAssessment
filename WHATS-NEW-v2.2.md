# What's New in Version 2.2.0

> ⚠️ **IMPORTANT NOTICES**
>
> **General Disclaimer**: This tool is **NOT an official Microsoft product**. It is provided as-is with no warranties. Support is best-effort only. Results may not be 100% accurate—always verify with official tools.
>
> **CE+ Feature Disclaimer**: The Cyber Essentials Plus mapping is **EXPERIMENTAL**. Policy mappings are approximate and NOT 100% accurate. This tool does NOT certify compliance—use for guidance only.

## 🇬🇧 Cyber Essentials Plus Compliance Mapping (Experimental)

Version 2.2.0 introduces an **experimental feature** to help UK organizations assess their Azure environments against **Cyber Essentials Plus (CE+)** requirements. This feature maps the 5 core CE+ control areas to 24 Azure Policy assignments, providing gap analysis and compliance scoring.

---

## 🎯 Key Features

### 1️⃣ Automated CE+ Mapping

The script now automatically maps **24 Azure policies** to the **5 Cyber Essentials Plus requirement areas**:

| CE+ Category | Policy Controls | Coverage |
|--------------|-----------------|----------|
| **Patch Management** | 4 policies | OS updates, automatic patching, Update Manager |
| **Firewalls & Internet Boundary** | 5 policies | NSGs, public access restrictions, JIT, Azure Firewall |
| **Secure Configuration** | 6 policies | Security baselines, TLS 1.2+, HTTPS, encryption |
| **Malware Protection** | 4 policies | Endpoint protection, Defender, vulnerability scanning |
| **Access Control** | 5 policies | MFA, PIM, least privilege, legacy auth blocking |

### 2️⃣ Gap Analysis & Compliance Scoring

**Console Output** (when using `-ShowRecommendations`):
```
🇬🇧 CYBER ESSENTIALS PLUS COMPLIANCE:
   Mapping UK Cyber Essentials Plus requirements to deployed Azure policies...

   📋 Patch Management
      ✓ System updates should be installed on your machines
      ✓ Missing system updates should be remediated (NOT ENFORCED)
      ✗ Machines should be configured to automatically install updates (MISSING)
      ✗ Update Manager should be enabled for all VMs (MISSING)

   📋 Firewalls & Internet Boundary
      ✓ Network Security Groups should be applied to all subnets
      ✓ Network Security Groups should be applied to all NICs
      ✗ Public network access should be disabled for PaaS services (MISSING)
      ✗ Just-In-Time network access should be enabled on VMs (MISSING)
      ✗ Azure Firewall should be deployed (MISSING)

   📊 COMPLIANCE SUMMARY:
      Total CE+ Controls Mapped: 24
      Deployed: 15
      Missing: 9
      Compliance Score: 62.5%

   ⚠️  RECOMMENDED ACTIONS:
      1. Review and assign missing policy controls listed above
      2. Focus on high-priority categories: Firewalls and Access Control
      3. Reference: https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus?utm_source=copilot.com
```

### 3️⃣ CSV Export for Reporting

**New Parameter**: `-ExportCEPCompliance`

```powershell
# Export CE+ compliance report to CSV
.\Get-PolicyAssignments.ps1 -ShowRecommendations -ExportCEPCompliance
```

**Output**: `CyberEssentialsPlus_Compliance_YYYYMMDD_HHMMSS.csv`

**CSV Columns**:
- **CE+ Category**: The requirement area (e.g., "Patch Management")
- **Required Control**: Azure Policy display name
- **Status**: `Deployed` or `Missing`
- **Assignment Name**: Actual policy assignment name (if deployed)
- **Enforcement Mode**: `Default` or `DoNotEnforce`
- **Non-Compliant Resources**: Count of non-compliant resources
- **Recommendation**: Actionable guidance (e.g., "Enable enforcement", "Assign this policy")

---

## 📋 CE+ Requirements to Azure Policy Mapping

### Patch Management

| CE+ Requirement | Azure Policy Name |
|----------------|-------------------|
| OS must be fully patched | System updates should be installed on your machines |
| Updates must be applied promptly | Missing system updates should be remediated |
| Update mechanism must exist | Machines should be configured to automatically install updates |
| Centralised patching (Azure equivalent) | Update Manager should be enabled for all VMs |

### Firewalls & Internet Boundary

| CE+ Requirement | Azure Policy Name |
|----------------|-------------------|
| Boundary firewall / traffic restriction | Network Security Groups should be applied to all subnets |
| Boundary firewall / traffic restriction | Network Security Groups should be applied to all NICs |
| Prevent unnecessary public exposure | Public network access should be disabled for PaaS services |
| Protect admin ports | Just-In-Time network access should be enabled on VMs |
| Perimeter firewall (if used) | Azure Firewall should be deployed |

### Secure Configuration

| CE+ Requirement | Azure Policy Name |
|----------------|-------------------|
| Secure OS configuration | Windows machines should meet security baseline |
| Secure OS configuration | Linux machines should meet security baseline |
| Enforce secure protocols | TLS version should be set to 1.2 or higher |
| Secure storage configuration | Secure transfer to storage accounts should be enabled |
| Enforce HTTPS | App Service apps should only be accessible over HTTPS |
| Encryption in transit | Enforce encryption in transit for PaaS services |

### Malware Protection

| CE+ Requirement | Azure Policy Name |
|----------------|-------------------|
| Anti-malware installed | Endpoint protection should be installed on all VMs |
| Real-time protection | Microsoft Defender for Endpoint should be enabled |
| Server protection | Azure Defender for Servers (Plan 1 or 2) should be enabled |
| Vulnerability scanning (Azure equivalent) | Vulnerability assessment should be enabled on machines |

### Access Control

| CE+ Requirement | Azure Policy Name |
|----------------|-------------------|
| MFA for all users | MFA should be enabled for all Azure AD users |
| MFA for privileged roles | MFA should be enabled for accounts with write permissions |
| Privileged access control | Privileged Identity Management should be enabled |
| Least privilege | Role assignments should not use wildcard permissions |
| Remove legacy auth | Legacy authentication protocols should be blocked |

---

## 🔍 How It Works

### Pattern Matching Logic

The script uses PowerShell's `-like` operator to match policies:

```powershell
foreach ($ceCategory in $CyberEssentialsPlusMapping.Keys) {
    foreach ($cePolicy in $CyberEssentialsPlusMapping[$ceCategory]) {
        $matchingPolicy = $results | Where-Object { 
            $_.'Policy Name' -like "*$cePolicy*" -or 
            $_.'Assignment Name' -like "*$cePolicy*" -or 
            $_.'Display Name' -like "*$cePolicy*"
        } | Select-Object -First 1
        
        if ($matchingPolicy) {
            # Policy found - check enforcement status
        } else {
            # Policy missing - add to gap list
        }
    }
}
```

### Compliance Score Calculation

```
Compliance Score = (Deployed Controls / Total CE+ Controls) × 100%

Color Coding:
- 🟢 Green (80-100%): Strong CE+ alignment
- 🟡 Yellow (50-79%): Moderate coverage, gaps exist
- 🔴 Red (0-49%): Significant gaps, action required
```

---

## ⚠️ Important Limitations

### What This Tool Does

✅ Maps CE+ requirements to common Azure Policy display names  
✅ Identifies which policies are deployed vs. missing  
✅ Shows enforcement status (Enabled/DoNotEnforce)  
✅ Highlights non-compliant resources  
✅ Generates actionable recommendations  
✅ Exports compliance data to CSV for reporting  

### What This Tool Does NOT Do

❌ **Provide official CE+ certification** - Only formal audits by CREST-certified bodies can certify compliance  
❌ **Cover all CE+ requirements** - Some requirements (physical security, training, procedures) are outside Azure Policy scope  
❌ **Guarantee 100% accurate mapping** - Policy names may vary, custom policies may not match  
❌ **Replace security audits** - This is a guidance tool, not a comprehensive assessment  
❌ **Detect all policy variations** - Azure Landing Zone (ALZ) and custom policies may use different naming  

### Known Issues

1. **Policy Naming Variations**: Azure policies can have custom display names. Pattern matching may:
   - Miss policies with heavily customized names
   - Match unrelated policies with similar names

2. **Built-In vs. Custom Policies**: Maps to built-in Azure Policy names only. Custom definitions may not be detected.

3. **Enforcement vs. Deployment**: A policy may be deployed but set to `DoNotEnforce` mode. The tool flags this but counts it as "deployed."

4. **Scope Coverage**: Checks if a policy exists anywhere, but doesn't verify complete coverage or exemptions.

5. **Azure Landing Zone (ALZ)**: ALZ policies often have different naming (e.g., `Deny-PublicIP` vs. `Public IPs should be denied`). Future versions may add ALZ support.

---

## 💡 Usage Examples

### Basic CE+ Assessment (Console Only)

```powershell
# Run with CE+ compliance check
.\Get-PolicyAssignments.ps1 -ShowRecommendations
```

The CE+ compliance section automatically appears when using `-ShowRecommendations`.

### Export CE+ Compliance to CSV

```powershell
# Generate CSV report
.\Get-PolicyAssignments.ps1 -ShowRecommendations -ExportCEPCompliance
```

**Output File**: `CyberEssentialsPlus_Compliance_20260205_143022.csv`

### Combined Export (Policies + CE+ Compliance)

```powershell
# Export both standard policy assessment and CE+ compliance
.\Get-PolicyAssignments.ps1 -ShowRecommendations -Export -ExportCEPCompliance
```

**Output Files**:
- `PolicyAssignments_20260205_143022.csv` (all policies)
- `CyberEssentialsPlus_Compliance_20260205_143022.csv` (CE+ mapping)

### Automated Assessment

```powershell
# For CI/CD pipelines or scheduled assessments
.\Get-PolicyAssignments.ps1 `
    -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ShowRecommendations `
    -Export `
    -ExportCEPCompliance
```

---

## 📊 Interpreting Results

### Console Output Sections

#### 1. Control-by-Control Analysis
Each CE+ category shows individual policy status:
- ✓ **Green**: Policy deployed and enforced
- ⚠️ **Yellow**: Policy deployed but `DoNotEnforce` mode
- ✗ **Red**: Policy missing

#### 2. Compliance Summary
- **Total CE+ Controls Mapped**: 24 (fixed)
- **Deployed**: Count of matched policies
- **Missing**: Gap count
- **Compliance Score**: Percentage (color-coded)

#### 3. Recommended Actions
Prioritized guidance based on gaps found.

### CSV Export Usage

**Use Cases**:
- Dashboard integration (Power BI, Tableau)
- Quarterly compliance reporting
- Audit evidence collection
- Trend analysis over time
- Executive summaries

**Sample Row**:
```csv
CE+ Category,Required Control,Status,Assignment Name,Enforcement Mode,Non-Compliant Resources,Recommendation
"Patch Management","System updates should be installed on your machines","Deployed","ASC-SystemUpdates","Default",23,"Monitor compliance"
"Patch Management","Update Manager should be enabled for all VMs","Missing","N/A","N/A","N/A","Assign this policy to meet CE+ requirements"
```

---

## 🔧 Technical Details

### Data Structure

**In-Memory Mapping**:
```powershell
$CyberEssentialsPlusMapping = @{
    'Patch Management' = @(
        'System updates should be installed on your machines',
        'Missing system updates should be remediated',
        ...
    )
    'Firewalls & Internet Boundary' = @(...)
    'Secure Configuration' = @(...)
    'Malware Protection' = @(...)
    'Access Control' = @(...)
}
```

### Processing Flow

```
1. Run standard policy assessment (ARG queries)
   ↓
2. Build $results array with all policy assignments
   ↓
3. For each CE+ category:
   a. For each required control:
      - Search $results for matching policy
      - Check enforcement status
      - Count non-compliant resources
   b. Categorize as deployed/missing
   ↓
4. Calculate compliance score
   ↓
5. Display console output (if -ShowRecommendations)
   ↓
6. Export to CSV (if -ExportCEPCompliance)
```

---

## 🛠️ Extending the Tool

### Future Enhancements (Roadmap)

- [ ] **Azure Landing Zone (ALZ) Support**: Recognize ALZ policy naming patterns
- [ ] **Custom Policy Detection**: Allow user-provided policy mappings
- [ ] **Scope Coverage Analysis**: Verify policies apply to all subscriptions/resources
- [ ] **Exemption Awareness**: Identify resources with policy exemptions
- [ ] **Historical Tracking**: Compare compliance scores over time
- [ ] **Defender for Cloud Integration**: Cross-reference with security recommendations
- [ ] **CE+ Certification Readiness**: Full checklist including procedural requirements

### Community Contributions

We welcome feedback on policy mappings! See [CYBER-ESSENTIALS-PLUS.md](CYBER-ESSENTIALS-PLUS.md) for contribution guidelines.

---

## 📚 Additional Resources

### Official Documentation
- [UK NCSC Cyber Essentials Scheme](https://www.ncsc.gov.uk/cyberessentials/overview)
- [Azure Compliance - UK Cyber Essentials Plus](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus?utm_source=copilot.com)
- [Azure Policy Documentation](https://learn.microsoft.com/en-us/azure/governance/policy/)
- [Azure Security Baseline](https://learn.microsoft.com/en-us/security/benchmark/azure/)

### Related Tools
- [Azure Landing Zone Policies](https://github.com/Azure/Enterprise-Scale/wiki/ALZ-Policies)
- [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
- [Azure Update Manager](https://learn.microsoft.com/en-us/azure/update-manager/)

---

## 🔄 Backward Compatibility

All existing features from v2.1.0 are **fully preserved**:

✅ Azure Resource Graph (ARG) performance (10-50x faster)  
✅ `-ShowRecommendations` parameter  
✅ `-Export` parameter  
✅ `-IncludeSubscriptions` parameter  
✅ `-IncludeResourceGroups` parameter  
✅ `-TenantId` parameter  
✅ Azure Landing Zone (ALZ) gap analysis  
✅ Compliance data matching Azure Portal  

**New Parameters**:
- `-ExportCEPCompliance`: Export Cyber Essentials Plus compliance to CSV

**No Breaking Changes**: Existing scripts will continue to work without modification.

---

## 📈 Version History

| Version | Date | Key Features |
|---------|------|-------------|
| **2.2.0** | 2026-02-06 | ✨ Cyber Essentials Plus mapping (experimental) |
| **2.1.0** | 2026-02-05 | 🚀 Azure Resource Graph integration (10-50x faster) |
| **2.0.1** | 2026-02-05 | 📊 Enhanced summary statistics |
| **2.0.0** | 2026-02-05 | 🎯 Multi-tenant support, subscription/RG enumeration |
| **1.0.0** | Initial | 📋 Azure Landing Zone policy assessment |

---

## 🙏 Feedback & Support

### Reporting Issues
If you encounter issues with CE+ mapping:
1. Verify policy exists in your environment
2. Check for custom display names
3. Review [CYBER-ESSENTIALS-PLUS.md](CYBER-ESSENTIALS-PLUS.md) limitations
4. Open an issue with details (policy name, expected behavior)

### Feature Requests
Have ideas for improving CE+ mapping? We'd love to hear:
- Better policy matching algorithms
- Additional compliance frameworks
- Integration with other tools

---

**Last Updated**: February 6, 2026  
**Status**: Experimental Feature - Community Feedback Welcome 🙏  
**Documentation**: See [CYBER-ESSENTIALS-PLUS.md](CYBER-ESSENTIALS-PLUS.md) for full details
