# Azure Policy Assignments Assessment Script

**Version 2.2.1** | [View Changelog](CHANGELOG.md)

> ⚠️ **DISCLAIMER**  
> This is **NOT an official Microsoft tool**. It is provided as-is with **no warranties or guarantees**. Support is provided on a **best-effort basis** by the community. Results may not be 100% accurate—always verify against Azure Portal and official Microsoft tools. Use at your own risk.

## What Does This Script Do?

This PowerShell script scans your Azure tenant and reports on **all policy assignments** across management groups, subscriptions, and resource groups. It uses **Azure Resource Graph** for fast execution and produces:

- A **console summary** of every directly-assigned policy (excluding inherited), grouped by scope
- **Security, cost, and compliance impact** ratings for each assignment
- **Azure Landing Zone gap analysis** — highlights missing policies compared to the official ALZ reference
- **UK Cyber Essentials Plus mapping** *(experimental)* — maps deployed policies to CE+ requirements
- Optional **CSV exports** for offline analysis and reporting

👉 Jump to [Prerequisites](#prerequisites) · [Usage](#usage) · [Parameters](#parameters)

---

## Prerequisites

### PowerShell Version

- **PowerShell 7.0 or later** is required. Windows PowerShell 5.1 is **not supported**.
- To check your version: `$PSVersionTable.PSVersion`
- Install PowerShell 7: [https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell)

### Required Modules

- **Az.Accounts**: For Azure authentication and context management
- **Az.Resources**: For management group and subscription queries
- **Az.ResourceGraph**: For high-performance policy and compliance queries (NEW in v2.1)

### Installation

```powershell
Install-Module -Name Az.Accounts -Force -AllowClobber
Install-Module -Name Az.Resources -Force -AllowClobber
Install-Module -Name Az.ResourceGraph -Force -AllowClobber
```

### Azure Permissions

The account running the script needs:
- **Reader** access or higher on management groups
- **Reader** access on policy assignments
- Typically requires at least **Management Group Reader** role at the tenant root level
- **Note**: Azure Resource Graph queries respect existing RBAC permissions automatically

**Permission Errors**: If you encounter permission errors, the script will provide specific guidance on required roles. Contact your Azure administrator to grant appropriate access.

---

## Usage

### Execution Modes

The script supports multiple enumeration scopes:

1. **Management Groups Only** (Default) - Assess policies at MG level
2. **Include Subscriptions** - Use `-IncludeSubscriptions` to add subscription-level policies
3. **Full Coverage** - Use `-IncludeSubscriptions -IncludeResourceGroups` for complete inventory

See [OUTPUT-OPTIONS.md](OUTPUT-OPTIONS.md) for detailed examples.

### Basic Execution

1. **Connect to Azure** (if not already connected):
   ```powershell
   Connect-AzAccount
   ```

2. **Run the script**:
   ```powershell
   # Basic execution - Management Groups only
   .\Get-PolicyAssignments.ps1
   
   # With recommendations
   .\Get-PolicyAssignments.ps1 -ShowRecommendations
   
   # Cyber Essentials Plus compliance assessment (NEW in v2.2!)
   .\Get-PolicyAssignments.ps1 -ShowRecommendations -ExportCEPCompliance
   
   # Specify tenant ID (skip tenant selection prompt)
   .\Get-PolicyAssignments.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   
   # Include subscription-level policies
   .\Get-PolicyAssignments.ps1 -IncludeSubscriptions -Export
   
   # Full coverage (MG + Subscriptions + Resource Groups)
   .\Get-PolicyAssignments.ps1 -IncludeSubscriptions -IncludeResourceGroups -Export
   
   # Complete assessment with recommendations
   .\Get-PolicyAssignments.ps1 -IncludeSubscriptions -ShowRecommendations -Export
   
   # Automated run for specific tenant
   .\Get-PolicyAssignments.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -IncludeSubscriptions -Export
   ```

3. **Select a tenant** when prompted (if you have access to multiple tenants and didn't specify -TenantId)

4. **Review the output** in the console

5. **CSV export** (optional): Use the `-Export` switch to save results to CSV files.

### Parameters

- **`-ShowRecommendations`**: Generates comprehensive recommendations for each policy assignment including:
  - **Security Impact Classification** (High/Medium/Low/None):
    - **High**: Deny/DeployIfNotExists/Modify effects, or policies protecting critical areas (network security, encryption, public access, Defender for Cloud, backup/DR)
    - **Medium**: Audit policies, governance policies, general compliance controls
    - **Low**: Informational policies, tagging policies
    - **None**: Disabled policies or those in DoNotEnforce mode
  - **Security Posture Assessment**: Shows count and detailed list of high-impact security policies currently deployed, with effect types and enforcement status
  - **Cyber Essentials Plus Compliance Mapping**: Maps CE+ requirements to deployed Azure policies (v2.2+)
  - Cost Impact Analysis
  - Compliance Impact Assessment
  - Operational Overhead Evaluation
  - Risk Level Assessment
  - Azure Landing Zone Coverage Analysis (compares against official ALZ Library)
  - Actionable recommendations with gap analysis

- **`-Export`**: When specified, exports results to a CSV file. Without this switch, no file is exported.

- **`-FileName`**: Custom filename for CSV export (e.g., "MyReport.csv"). If not provided, uses default timestamped format `PolicyAssignments_YYYYMMDD_HHMMSS.csv`. Only used when `-Export` is specified.

- **`-IncludeSubscriptions`**: When specified, includes policy assignments from all subscriptions in addition to management groups.

- **`-IncludeResourceGroups`**: When specified, includes policy assignments from all resource groups. Requires `-IncludeSubscriptions` to be effective.

- **`-TenantId`**: Optional tenant ID to use for the assessment. When specified, skips the tenant selection prompt. Useful for automation scenarios or when working with a specific tenant. Example: `-TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`

- **`-ExportCEPCompliance`**: When specified with `-ShowRecommendations`, exports Cyber Essentials Plus compliance results to a CSV file. See [Cyber Essentials Plus](#cyber-essentials-plus-compliance) section below.

### Example Output

```
Retrieving available tenants...

Available Tenants:
  [1] Example Corp (ID: 12345678-1234-1234-1234-123456789abc)
  [2] Demo Company (ID: 87654321-4321-4321-4321-cba987654321)

Select a tenant by number (1-2): 1
Selected tenant: Example Corp (ID: 12345678-1234-1234-1234-123456789abc)

Retrieving all management groups...
Found 5 management group(s):
  - Tenant Root Group (12345678-1234-1234-1234-123456789abc)
  - Platform (mg-platform)
  - Landing Zones (mg-landingzones)
  - Sandbox (mg-sandbox)
  - Decommissioned (mg-decommissioned)

Retrieving policy assignments for each management group...

  Processing MG: Tenant Root Group (12345678-1234-1234-1234-123456789abc)
    Total assignments found (including inherited): 16
      ✓ Direct: Enforce-ACSB
      ✓ Direct: Deploy-ASC-Monitoring
      - Inherited: Audit-ResourceRGLocation (from /providers/Microsoft.Management/managementGroups/mg-platform)
    Direct assignments: 2

  Processing MG: Platform (mg-platform)
    Total assignments found (including inherited): 18
      ✓ Direct: Deploy-MDFC-OssDb
      ✓ Direct: Audit-ResourceRGLocation
    Direct assignments: 2
...
```

### Output Table

```
Assignment Name          Display Name              Policy Type Scope Type       Scope Name            Management Group ID Policy Name
---------------          ------------              ----------- ----------       ----------            ------------------- -----------
Enforce-ACSB             Enforce Azure Security... Policy      Management Group Tenant Root Group     12345678-1234...    Enforce-ACSB
Deploy-ASC-Monitoring    Deploy Azure Security...  Initiative  Management Group Tenant Root Group     12345678-1234...    Deploy-ASC-Monitoring
Deploy-MDFC-OssDb        Deploy Microsoft Defen... Policy      Management Group Platform             mg-platform         Deploy-MDFC-OssDb
```

---

## Overview

This PowerShell script analyzes Azure Policy assignments across all management groups in an Azure tenant. It retrieves policy assignments directly assigned to each management group, excluding inherited policies from parent management groups, providing a clear view of the policy governance structure.

**NEW in v2.2**: Cyber Essentials Plus compliance mapping!  
**NEW in v2.0**: Enhanced with subscription and resource group enumeration, multi-tenant support, progress tracking, and accurate compliance data matching Azure Portal values!

**IMPORTANT**: This script is specifically designed for and optimized for **Azure Landing Zone (ALZ) management group structures**. All recommendations and gap analysis are based on the standard ALZ architecture. The script will work with any management group hierarchy, but the policy recommendations are most meaningful when applied to an ALZ-compliant structure.

### Azure Landing Zone Management Group Structure

This script is designed to work with the standard Azure Landing Zone management group hierarchy:

```
Tenant Root Group
│
└── <Organization> (e.g., Contoso)
    │
    ├── Platform
    │   ├── Management
    │   ├── Connectivity
    │   └── Identity
    │
    ├── Landing Zones
    │   ├── Corp (Corporate workloads)
    │   └── Online (Internet-facing workloads)
    │
    ├── Sandboxes (Innovation/testing)
    │
    └── Decommissioned (Workloads being retired)
```

**Why ALZ Structure Matters**:
- Policy recommendations are tailored to each management group type (Platform, Landing Zones, etc.)
- The script validates against ALZ best practices and standard policy assignments
- Gap analysis identifies missing policies based on ALZ reference implementation
- Without an ALZ structure, many recommendations may not be applicable to your environment

## What's New

### 🎯 v2.2: Cyber Essentials Plus Compliance Mapping

**Experimental Feature**: Map UK Cyber Essentials Plus (CE+) requirements to Azure Policy assignments!

- 🇬🇧 CE+ compliance gap analysis
- 📊 Automated mapping of 24 CE+ requirements to Azure policies
- 📄 CSV export for compliance reporting (`-ExportCEPCompliance`)
- ⚠️ **Experimental** - Policy mappings are approximate ([Read More](CYBER-ESSENTIALS-PLUS.md))

### 🚀 v2.1: Azure Resource Graph Performance Boost

**10-50x faster execution!** The script now uses Azure Resource Graph (ARG) for blazing-fast policy queries. What used to take 2-5 minutes now completes in **5-30 seconds**.

- ✅ Single query instead of hundreds of API calls
- ✅ No subscription context switching required
- ✅ Simplified code (50% reduction)
- ✅ All features preserved (compliance, recommendations, export)
- ✅ Requires `Az.ResourceGraph` module (easy one-time install)

## Features

### Performance (NEW in v2.1)
- **Azure Resource Graph Integration**: 10-50x faster than traditional enumeration
- **Single Query Architecture**: Retrieves all policy assignments in one call
- **No Context Switching**: Eliminates slow subscription context changes
- **Efficient Compliance Data**: Aggregated compliance queries using ARG
- **Scales to Thousands**: Handles large environments with ease

### Core Capabilities
- **Multi-Tenant Support**: Select from multiple Azure tenants you have access to
- **Management Group Discovery**: Automatically discovers all management groups in the selected tenant (including nested hierarchies)
- **Direct Assignment Filtering**: Shows only policies directly assigned to each management group, excluding inherited policies
- **Real-Time Progress Tracking**: Visual feedback during processing

### Policy Assessment
- **Azure Landing Zone Validation**: Dynamically compares deployed policies against the official [Azure Landing Zones Library](https://github.com/Azure/Azure-Landing-Zones-Library)
- **Impact Analysis**: Security, Cost, Compliance, and Operational impact classification
- **Gap Analysis**: Identifies missing policies based on ALZ recommendations
- **Recommendations Engine**: Actionable insights for each policy assignment
- **Compliance Data**: Non-compliant resources and policies tracking

### Flexible Output Modes
- **Policy Enumeration**: Fast discovery using Azure Resource Graph
- **Compliance Integration**: Real-time compliance status from Azure Policy Insights
- **Combined Analysis**: Full assessment with policy and compliance data

### Export & Reporting
- **CSV Export**: Comprehensive policy assignment data
- **Custom Filenames**: User-defined or timestamped naming
- **Comprehensive Details**: All metrics and recommendations included

## Script Logic

### Management Group Discovery

1. Retrieves all root management groups using `Get-AzManagementGroup`
2. Recursively expands each management group to discover all children
3. Builds a complete list of all management groups in the tenant hierarchy

### Policy Assignment Filtering

For each management group:
1. Retrieves all policy assignments using `Get-AzPolicyAssignment -Scope`
2. Filters assignments to include only those where:
   - `assignment.Scope` exactly matches the current management group scope
   - This excludes inherited policies from parent management groups
3. Extracts policy metadata and creates structured output

### Key Filtering Logic

```powershell
# Only include direct assignments (not inherited)
if ($assignment.Scope -eq "/providers/Microsoft.Management/managementGroups/$($mg.Name)") {
    # Process this assignment
}
```

## Output Details

### Console Output

- **Progress indicators**: Shows which management group is being processed
- **Assignment classification**: 
  - `✓ Direct`: Policy is directly assigned to this MG
  - `- Inherited`: Policy is inherited from a parent MG (not included in results)
- **Count summaries**: Total vs direct assignments per management group

### CSV Export

**Export Behavior**: The script does NOT export to CSV by default. Use the `-Export` switch to save results.

**Filename options**:
- **Default**: `PolicyAssignments_YYYYMMDD_HHMMSS.csv` (timestamped)
- **Custom**: Use `-FileName "YourCustomName.csv"` parameter
- **CE+ Compliance**: `CyberEssentialsPlus_Compliance_YYYYMMDD_HHMMSS.csv` (when using `-ExportCEPCompliance`)

**Location**: Current directory

**Columns included**: All policy details including Assignment Name, Display Name, Policy Type, Effect Type, Enforcement Mode, Security Impact, Cost Impact, Compliance Impact, Operational Overhead, Risk Level, Scope details, Parameters

**Examples**:
```powershell
# Export with default timestamped filename
.\Get-PolicyAssignments.ps1 -Export

# Export with custom filename
.\Get-PolicyAssignments.ps1 -Export -FileName "Q4-PolicyAudit.csv"

# Export Cyber Essentials Plus compliance report (NEW in v2.2!)
.\Get-PolicyAssignments.ps1 -ShowRecommendations -ExportCEPCompliance

# Export with date-based filename
.\Get-PolicyAssignments.ps1 -Export -FileName "Policies_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

### Cyber Essentials Plus Compliance

**NEW in v2.2!** The script can now assess your environment against UK Cyber Essentials Plus (CE+) requirements.

⚠️ **EXPERIMENTAL FEATURE - READ CAREFULLY**  
- Policy mappings are **approximate** and **NOT 100% accurate**
- This tool does **NOT provide official CE+ certification**
- Use for **guidance only** - not for compliance attestation
- Community feedback welcome to improve mappings
- See [CYBER-ESSENTIALS-PLUS.md](CYBER-ESSENTIALS-PLUS.md) for full limitations

**Usage**:
```powershell
# Console output only
.\Get-PolicyAssignments.ps1 -ShowRecommendations

# Export CE+ compliance to CSV
.\Get-PolicyAssignments.ps1 -ShowRecommendations -ExportCEPCompliance
```

**Output**:
- Console: CE+ compliance section with deployed/missing controls and compliance score
- CSV: Detailed report with recommendations for each CE+ requirement

**See also**: [Cyber Essentials Plus Documentation](CYBER-ESSENTIALS-PLUS.md)

## Troubleshooting

### Common Issues

**Issue**: "Not logged in to Azure"
- **Solution**: Run `Connect-AzAccount` before executing the script

**Issue**: "ERROR: Unable to retrieve management groups" or "Access Denied" messages
- **Solution**: 
  - Verify you have at least **Reader** permissions on management groups
  - Contact your Azure administrator to grant **Management Group Reader** role at tenant root level
  - The script will provide specific guidance when permission errors are detected

**Issue**: "No management groups found"
- **Solution**: 
  - Verify you have appropriate permissions on management groups
  - Ensure your Azure environment has management groups configured
  - This script is designed for Azure Landing Zone structures - verify ALZ implementation

**Issue**: Script shows 0 assignments
- **Solution**: Check if policies are assigned at subscription or resource group level instead of management groups

**Issue**: Missing expected management groups
- **Solution**: Ensure you selected the correct tenant and have appropriate permissions to view all management groups

**Issue**: Many policies show as "MISSING" despite being deployed
- **Solution**: 
  - This is expected if your environment doesn't follow the standard Azure Landing Zone structure
  - Policy recommendations are based on ALZ best practices
  - If you're not using ALZ, use the CSV export to analyze your actual policy coverage

**Issue**: Recommendations don't seem relevant to your environment
- **Solution**: 
  - This script is optimized for **Azure Landing Zone management group structures**
  - If you're not using ALZ, focus on the direct assignment data rather than gap analysis
  - Consider implementing ALZ structure for enterprise-grade governance

**Issue**: Parameters column shows "(no parameters)" for most policies
- **Solution**: This is a known limitation. The Azure PowerShell `Get-AzPolicyAssignment` cmdlet's `Parameter` property is often empty or incomplete due to API restrictions. The script attempts to extract parameter values but Azure's API doesn't always expose them through standard PowerShell cmdlets. To view full parameter details, check the Azure Portal or use Azure Resource Graph queries.

### Debugging

The script includes verbose output that shows:
- Which management groups were discovered
- How many assignments found per MG
- Which assignments are direct vs inherited

Review the console output to identify where policies are actually assigned.

## Use Cases

1. **Governance Audit**: Understand which policies are assigned at each management group level
2. **Policy Cleanup**: Identify duplicate or unnecessary policy assignments
3. **Compliance Reporting**: Document current policy governance structure
4. **Migration Planning**: Map policies before restructuring management groups
5. **Security Assessment**: Review security policies across organizational hierarchy with detailed security posture analysis showing:
   - Which high-impact security policies are deployed
   - Effect types (Deny, DeployIfNotExists, Modify) and enforcement status
   - Gaps in security controls compared to Azure Landing Zone best practices
   - Critical areas covered (network security, encryption, access control, backup/DR)
6. **Impact Analysis**: Evaluate cost, security, and compliance impact of current policy assignments
7. **Azure Landing Zone Validation**: Compare deployed policies against ALZ recommendations
8. **Risk Assessment**: Identify high-risk policy configurations and enforcement gaps

## Limitations

- **Scope**: By default, shows policies assigned to management groups. Use `-IncludeSubscriptions` and `-IncludeResourceGroups` assignment scopes if needed.
- **Permissions**: Requires appropriate Azure permissions (Reader) on queried scopes. ARG queries respect RBAC automatically.
- **ALZ Context**: Policy recommendations and gap analysis are based on **Azure Landing Zone structure** - results are most meaningful in ALZ-compliant environments.
- **Connectivity**: Azure Landing Zone validation requires internet connectivity to fetch latest policies from the official [Azure Landing Zones Library](https://github.com/Azure/Azure-Landing-Zones-Library) (falls back to cached list if offline).

---

## Version History

- **v2.2.0**: Cyber Essentials Plus compliance mapping, `-ExportCEPCompliance` parameter, disclaimers. See [WHATS-NEW-v2.2.md](WHATS-NEW-v2.2.md).
- **v2.1.0**: Major Resource Graph (ARG) integration for 10-50x performance boost, unified compliance queries, and ALZ library integration fix.
- **v2.0.1**: Enhanced summary statistics and detailed breakdowns.
- **v2.0.0**: Added subscription/RG enumeration, multi-tenant support, and impact analysis.
- **v1.0.0**: Initial release with multi-tenant support and inherited policy filtering.

## References

- [Azure Landing Zones Library](https://github.com/Azure/Azure-Landing-Zones-Library) - Official ALZ policy definitions
- [Azure Policy Overview](https://docs.microsoft.com/en-us/azure/governance/policy/overview)
- [Management Groups](https://docs.microsoft.com/en-us/azure/governance/management-groups/overview)

## License

This script is provided as-is for Azure governance and compliance purposes.
```
