# Azure Policy Assignments Assessment Script

## Overview

This PowerShell script analyzes Azure Policy assignments across all management groups in an Azure tenant. It retrieves policy assignments directly assigned to each management group, excluding inherited policies from parent management groups, providing a clear view of the policy governance structure.

## Features

- **Multi-Tenant Support**: Select from multiple Azure tenants you have access to
- **Management Group Discovery**: Automatically discovers all management groups in the selected tenant (including nested hierarchies)
- **Direct Assignment Filtering**: Shows only policies directly assigned to each management group, excluding inherited policies
- **Detailed Progress Tracking**: Displays real-time progress as it processes each management group
- **Impact Analysis & Recommendations**: Optional recommendations on cost, security, compliance, and operational impact of policies
- **Azure Landing Zone Validation**: Dynamically compares deployed policies against the official [Azure Landing Zones Library](https://github.com/Azure/Azure-Landing-Zones-Library) (version-controlled policy definitions)
- **Comprehensive Output**: Shows policy assignment details including:
  - Assignment Name
  - Display Name
  - Policy Type (Policy or Initiative)
  - Effect Type (Deny, Audit, DINE, Modify, etc.)
  - Enforcement Mode (Default or DoNotEnforce)
  - Impact Analysis (Security, Cost, Compliance, Operational Overhead, Risk Level)
  - Management Group Name and ID
  - Policy Definition Name
  - Scope
  - Parameters
- **CSV Export**: Automatically exports results to CSV for further analysis (with option to prompt instead)

## Prerequisites

### Required Modules

- **Az.Accounts**: For Azure authentication and context management
- **Az.Resources**: For policy assignment and management group queries

### Installation

```powershell
Install-Module -Name Az.Accounts -Force -AllowClobber
Install-Module -Name Az.Resources -Force -AllowClobber
```

### Azure Permissions

The account running the script needs:
- **Reader** access or higher on management groups
- **Reader** access on policy assignments
- Typically requires at least **Management Group Reader** role at the tenant root level

## Usage

### Basic Execution

1. **Connect to Azure** (if not already connected):
   ```powershell
   Connect-AzAccount
   ```

2. **Run the script**:
   ```powershell
   # Basic execution (auto-exports to CSV)
   .\Get-PolicyAssignments.ps1
   
   # With recommendations and impact analysis
   .\Get-PolicyAssignments.ps1 -ShowRecommendations
   
   # Prompt before exporting to CSV
   .\Get-PolicyAssignments.ps1 -PromptForExport
   
   # With all options
   .\Get-PolicyAssignments.ps1 -ShowRecommendations -PromptForExport
   ```

3. **Select a tenant** when prompted (if you have access to multiple tenants)

4. **Review the output** in the console

5. **CSV export**: By default, results are automatically exported to a timestamped CSV file. Use `-PromptForExport` switch to be prompted before exporting.

### Parameters

- **`-ShowRecommendations`**: Generates comprehensive recommendations for each policy assignment including:
  - Security Impact (Critical/High/Medium/Low)
  - Cost Impact
  - Compliance Impact
  - Operational Overhead
  - Risk Level Assessment
  - Azure Landing Zone Coverage Analysis
  - Actionable recommendations

- **`-PromptForExport`**: Prompts user before exporting to CSV. Without this switch, results are automatically exported.

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

**Default Behavior**: The script automatically exports results to a timestamped CSV file without prompting.

**Filename format**: `PolicyAssignments_YYYYMMDD_HHMMSS.csv`

**Location**: Current directory

**Columns included**: All policy details including Assignment Name, Display Name, Policy Type, Effect Type, Enforcement Mode, Security Impact, Cost Impact, Compliance Impact, Operational Overhead, Risk Level, Scope details, Parameters

**Prompt for Export**: Use the `-PromptForExport` switch parameter to be asked before exporting:
```powershell
.\Get-PolicyAssignments.ps1 -PromptForExport
```

## Troubleshooting

### Common Issues

**Issue**: "Not logged in to Azure"
- **Solution**: Run `Connect-AzAccount` before executing the script

**Issue**: "No management groups found"
- **Solution**: Verify you have at least Reader permissions on management groups

**Issue**: Script shows 0 assignments
- **Solution**: Check if policies are assigned at subscription or resource group level instead of management groups

**Issue**: Missing expected management groups
- **Solution**: Ensure you selected the correct tenant and have appropriate permissions

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
5. **Security Assessment**: Review security policies across organizational hierarchy
6. **Impact Analysis**: Evaluate cost, security, and compliance impact of current policy assignments
7. **Azure Landing Zone Validation**: Compare deployed policies against ALZ recommendations
8. **Risk Assessment**: Identify high-risk policy configurations and enforcement gaps

## Limitations

- Only shows policies assigned to **management groups** (not subscriptions or resource groups)
- Requires appropriate Azure permissions to read management groups and policies
- Large tenants with many management groups may take time to process
- Parameter values may show "(no parameters)" for some policies due to Azure API limitations
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
