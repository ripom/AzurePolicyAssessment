# Azure Policy Assignments Assessment Script

**Version 2.0.0** | [View Changelog](CHANGELOG.md)

## Overview

This PowerShell script analyzes Azure Policy assignments across all management groups in an Azure tenant. It retrieves policy assignments directly assigned to each management group, excluding inherited policies from parent management groups, providing a clear view of the policy governance structure.

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

## Features

### Core Capabilities
- **Multi-Tenant Support**: Select from multiple Azure tenants you have access to
- **Management Group Discovery**: Automatically discovers all management groups in the selected tenant (including nested hierarchies)
- **Direct Assignment Filtering**: Shows only policies directly assigned to each management group, excluding inherited policies
- **Detailed Progress Tracking**: Displays real-time progress as it processes each management group

### Policy Assessment
- **Azure Landing Zone Validation**: Dynamically compares deployed policies against the official [Azure Landing Zones Library](https://github.com/Azure/Azure-Landing-Zones-Library)
- **Impact Analysis**: Security, Cost, Compliance, and Operational impact classification
- **Gap Analysis**: Identifies missing policies based on ALZ recommendations
- **Recommendations Engine**: Actionable insights for each policy assignment

### Regulatory Compliance (NEW in v2.0)
- **9 Major Frameworks**: PCI DSS, ISO 27001, NIST, CIS, SOC 2, HIPAA, FedRAMP, UK OFFICIAL, Microsoft Cloud Security Benchmark
- **Compliance Scoring**: Real-time calculation of compliance percentages
- **Resource-Level Details**: Identify specific non-compliant resources
- **Framework Status**: Detection of assigned vs unassigned frameworks
- **Remediation Guidance**: Actionable steps to improve compliance

### Defender for Cloud Integration (NEW in v2.1)
- **Secure Score**: Microsoft Defender for Cloud secure score reporting
- **Control-Level Assessment**: Individual control pass/fail status (1.1, 1.2, etc.)
- **Security Assessments**: Detailed security posture data from Defender for Cloud
- **Microsoft Cloud Security Benchmark**: Azure Security Benchmark compliance
- **Enhanced Details**: Control descriptions, severity levels, and remediation steps

### Flexible Output Modes
- **Policy Only**: Focus on ALZ policy assessment without compliance
- **Compliance Only**: Quick compliance check without policy enumeration
- **Combined**: Full assessment with both policy and compliance data

### Export & Reporting
- **CSV Export**: Separate exports for policy assignments and compliance data
- **Custom Filenames**: User-defined or timestamped naming
- **Comprehensive Details**: All metrics and recommendations included

## Prerequisites

### Required Modules

- **Az.Accounts**: For Azure authentication and context management
- **Az.Resources**: For policy assignment and management group queries
- **Az.Security**: For Microsoft Defender for Cloud integration (Secure Score, assessments)

### Installation

```powershell
Install-Module -Name Az.Accounts -Force -AllowClobber
Install-Module -Name Az.Resources -Force -AllowClobber
Install-Module -Name Az.Security -Force -AllowClobber
```

### Azure Permissions

The account running the script needs:
- **Reader** access or higher on management groups
- **Security Reader** role for Microsoft Defender for Cloud features (optional but recommended)
- **Reader** access on policy assignments
- Typically requires at least **Management Group Reader** role at the tenant root level

**Permission Errors**: If you encounter permission errors, the script will provide specific guidance on required roles. Contact your Azure administrator to grant appropriate access.

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
   
   # Include subscription-level policies
   .\Get-PolicyAssignments.ps1 -IncludeSubscriptions -Export
   
   # Full coverage (MG + Subscriptions + Resource Groups)
   .\Get-PolicyAssignments.ps1 -IncludeSubscriptions -IncludeResourceGroups -Export
   
   # Complete assessment with recommendations
   .\Get-PolicyAssignments.ps1 -IncludeSubscriptions -ShowRecommendations -Export
   ```

3. **Select a tenant** when prompted (if you have access to multiple tenants)

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
  - Cost Impact Analysis
  - Compliance Impact Assessment
  - Operational Overhead Evaluation
  - Risk Level Assessment
  - Azure Landing Zone Coverage Analysis (compares against official ALZ Library)
  - Actionable recommendations with gap analysis

- **`-Export`**: When specified, exports results to a CSV file. Without this switch, no file is exported.

- **`-FileName`**: Custom filename for CSV export (e.g., "MyReport.csv"). If not provided, uses default timestamped format `PolicyAssignments_YYYYMMDD_HHMMSS.csv`. Only used when `-Export` is specified.

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

**Location**: Current directory

**Columns included**: All policy details including Assignment Name, Display Name, Policy Type, Effect Type, Enforcement Mode, Security Impact, Cost Impact, Compliance Impact, Operational Overhead, Risk Level, Scope details, Parameters

**Examples**:
```powershell
# Export with default timestamped filename
.\Get-PolicyAssignments.ps1 -Export

# Export with custom filename
.\Get-PolicyAssignments.ps1 -Export -FileName "Q4-PolicyAudit.csv"

# Export with date-based filename
.\Get-PolicyAssignments.ps1 -Export -FileName "Policies_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

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

- Only shows policies assigned to **management groups** (not subscriptions or resource groups)
- Requires appropriate Azure permissions to read management groups and policies
- Large tenants with many management groups may take time to process
- Parameter values may show "(no parameters)" for some policies due to Azure API limitations
- **Policy recommendations and gap analysis are based on Azure Landing Zone structure** - results are most meaningful in ALZ-compliant environments
- Azure Landing Zone validation requires internet connectivity to fetch latest policies from the official [Azure Landing Zones Library](https://github.com/Azure/Azure-Landing-Zones-Library) (falls back to cached list if offline)

## Version History

- **v2.1**: Updated to use official Azure Landing Zones Library as source of truth for policy recommendations
- **v2.0**: Added impact analysis, recommendations, Azure Landing Zone validation, auto-CSV export
- **v1.0**: Initial release with multi-tenant support and inherited policy filtering

## References

- [Azure Landing Zones Library](https://github.com/Azure/Azure-Landing-Zones-Library) - Official ALZ policy definitions
- [Azure Policy Overview](https://docs.microsoft.com/en-us/azure/governance/policy/overview)
- [Management Groups](https://docs.microsoft.com/en-us/azure/governance/management-groups/overview)

## License

This script is provided as-is for Azure governance and compliance purposes.
```
