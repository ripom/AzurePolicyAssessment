# Azure Policy Assignments Assessment Script

**Version 3.2.0** | [View Changelog](CHANGELOG.md) | [What's New](WHATS-NEW-v3.0.md) | [AI Guide](AI-INTEGRATION-GUIDE.md)

> **Author**: This project is made and maintained by **Riccardo Pomato**.
>
> ⚠️ **DISCLAIMER**  
> This is **NOT an official Microsoft tool**. It is provided as-is with **no warranties or guarantees**. Results may not be 100% accurate — always verify against Azure Portal and official Microsoft tools. Use at your own risk.

## What Does This Script Do?

This PowerShell script scans your Azure tenant and reports on **all policy assignments** across management groups, subscriptions, and resource groups. It uses **Azure Resource Graph** for fast execution and produces:

- A **console summary** of every directly-assigned policy (excluding inherited), grouped by scope
- **Security, cost, and compliance impact** ratings for each assignment
- **Azure Landing Zone gap analysis** — highlights missing policies compared to the official ALZ reference
- **UK Cyber Essentials Plus mapping** with [CE+ v3.2 test specification](https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf) (TC1–TC5)
- **Policy exemptions** — lists all exemptions with scope, category, expiry, and coverage detail
- Optional **CSV, HTML, YAML** exports for offline analysis, reporting, and delta comparison

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

The script assesses all scopes by default (Management Groups, Subscriptions, Resource Groups). Use `-ManagementGroup` or `-Subscription` to filter to a specific scope.

See [OUTPUT-OPTIONS.md](OUTPUT-OPTIONS.md) for detailed examples.

### Basic Execution

1. **Connect to Azure** (if not already connected):
   ```powershell
   Connect-AzAccount
   ```

2. **Run the script**:
   ```powershell
   # Basic execution — all scopes assessed by default
   .\Get-PolicyAssignments.ps1
   
   # Quick executive summary
   .\Get-PolicyAssignments.ps1 -QuickAssess

   # Export to CSV and HTML
   .\Get-PolicyAssignments.ps1 -Output CSV,HTML

   # Cyber Essentials Plus compliance with test cases
   .\Get-PolicyAssignments.ps1 -CEP Full

   # Full assessment — everything enabled
   .\Get-PolicyAssignments.ps1 -Full
   
   # Specify tenant ID (skip tenant selection prompt)
   .\Get-PolicyAssignments.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   
   # Filter to a specific management group
   .\Get-PolicyAssignments.ps1 -ManagementGroup "mg-platform" -Output HTML

   # Filter to a specific subscription
   .\Get-PolicyAssignments.ps1 -Subscription "Production" -Output CSV

   # Export YAML database for delta comparison
   .\Get-PolicyAssignments.ps1 -Output YAML

   # Compare against a previous YAML snapshot
   .\Get-PolicyAssignments.ps1 -DeltaYAML ".\PolicyAssessment_20260218.yaml" -Output HTML
   ```

3. **Select a tenant** when prompted (if you have access to multiple tenants and didn't specify -TenantId)

4. **Review the output** in the console

5. **CSV export** (optional): Use the `-Export` switch to save results to CSV files.

### Parameters

- **`-Output`** (`CSV`, `HTML`, `NC`, `YAML`, `All`): Controls which exports are generated. Accepts one or more comma-separated values.
  - `CSV` — Export policy assignments to timestamped CSV file
  - `HTML` — Generate comprehensive interactive HTML report
  - `NC` — Export all non-compliant resources to CSV
  - `YAML` — Export full assessment database to YAML (for delta comparisons)
  - `All` — All of the above

- **`-CEP`** (`Show`, `Test`, `Export`, `Full`): Controls Cyber Essentials compliance features.
  - `Show` — Display CE v3.1 compliance analysis in console
  - `Test` — Run CE+ v3.2 Test Specification (TC1–TC5)
  - `Export` — Export CE compliance data to CSV
  - `Full` — All of the above

- **`-ManagementGroup`**: Filter the assessment to a specific Management Group by name or ID.

- **`-Subscription`**: Filter the assessment to a specific Subscription by name or ID.

- **`-TenantId`**: Optional tenant ID to skip the tenant selection prompt. Useful for automation.

- **`-FileName`**: Custom filename for CSV export (e.g., `"MyReport.csv"`). Used with `-Output CSV`.

- **`-QuickAssess`**: Produces a concise one-page Quick Assessment: posture verdict, top 5 gaps, top 5 non-compliant assignments, and key actions.

- **`-DeltaYAML`**: Path to a previous YAML assessment database (generated with `-Output YAML`). Produces a comprehensive policy-by-policy comparison showing new, removed, and changed assignments, compliance drift, effect type shifts, exemption changes, and overall posture trend.

- **`-Full`**: Runs a comprehensive assessment with all features enabled (equivalent to `-Output All -CEP Full`).

- **`-AI`** (`Off`, `Summary`, `Full`): Controls the optional AI narrative layer powered by GitHub Copilot (GitHub Models).
  - `Off` — No AI processing (default). Fully deterministic output.
  - `Summary` — AI executive insight: posture, top drivers, prioritised actions.
  - `Full` — Summary + detailed per-policy remediation steps, compliance gaps, framework alignment.
  - Requires a GitHub token with `Models: read` permission. Usage follows GitHub Models billing and rate limits. See [AI-INTEGRATION-GUIDE.md](AI-INTEGRATION-GUIDE.md).

- **`-AIKey`**: GitHub Personal Access Token for GitHub Models API. Can also be set via `GITHUB_TOKEN` environment variable.

- **`-AIModel`**: GitHub Models catalog ID (default: `openai/gpt-4.1`). IDs use the `publisher/model` format; consult the current GitHub Models catalog.

- **`-Update`**: Self-update switch. Downloads the latest version of the script from GitHub, validates it has no parse errors, creates a backup of the current version (e.g., `Get-PolicyAssignments-v3.0.0-backup.ps1`), replaces the local script file, and exits so you can re-run with the new version. No Azure login required.

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

### Current Output vs AI-Augmented Output

The script today is **deterministic** (rule-based scoring + exact Azure data).
An optional future AI mode can add narrative interpretation while keeping your computed metrics as the source of truth.

| Aspect | Current Output (No AI) | AI-Augmented Output (Optional) |
|---|---|---|
| Data source | Azure Resource Graph + script logic | Same data + AI narrative layer |
| Assignment metrics | ✅ Exact counts and values | ✅ Same exact counts and values |
| Recommendations | Fixed rule-based text per policy/effect | Context-aware prioritized actions across multiple signals |
| Trend explanation | Manual interpretation of delta metrics | Automatic explanation of likely drivers and impact |
| Consistency | Fully deterministic run-to-run | Deterministic metrics + controlled AI text (schema + temperature 0) |
| Dependency | No external AI service | Requires AI endpoint/API key |
| Risk profile | No hallucination risk | Low but non-zero narrative risk (mitigated by validation) |

**Without AI (current):**

```text
EXECUTIVE SUMMARY
- Assignments: 412 (290 Policy | 95 Initiative | 27 Regulatory)
- Non-Compliant: 1,284 resources across 73 assignments
- Enforcement: 331 enforced | 81 audit-only
- High-Security Policies NOT Enforced: 14
- Top Non-Compliant Assignments: <top 10 list>
```

**With AI (optional future mode):**

```text
AI EXECUTIVE INSIGHTS
- Posture: Needs Improvement (confidence: high)
- Main drivers:
  1) 14 high-security policies in DoNotEnforce
  2) +182 non-compliant resources vs previous snapshot
  3) Regression concentrated in 2 subscriptions
- Prioritized actions (7-day plan):
  P1) Enforce top 5 high-security audit-only assignments
  P1) Remediate top 3 Deny failures
  P2) Review exemptions expiring in <30 days
```

> Recommended model for production use: keep scoring/compliance calculations deterministic, and use AI only for summarization, prioritization, and remediation narrative.

👉 **Full guide with examples, prerequisites, and architecture**: see [AI-INTEGRATION-GUIDE.md](AI-INTEGRATION-GUIDE.md)

---

## Overview

This PowerShell script analyzes Azure Policy assignments across all management groups in an Azure tenant. It retrieves policy assignments directly assigned to each management group, excluding inherited policies from parent management groups, providing a clear view of the policy governance structure.

**NEW in v3.2**: AI Executive Insights via GitHub Copilot — framework-aware analysis, compliance gaps, prioritised actions! Enhanced recommendation engine with 11 trigger categories!
**NEW in v3.1**: Multi-assignment Cyber Essentials Plus support — automatic deduplication when the same initiative is assigned at multiple scopes!  
**NEW in v3.0**: Simplified CLI (`-Output`, `-CEP`), real policy metadata, CE+ v3.2 test specification (TC1–TC5), Quick Assess mode, delta/trending!  
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

### 🤖 v3.2: AI Executive Insights & Recommendation Engine Overhaul

- 🤖 **AI Executive Insights**: Optional `-AI Summary|Full` powered by GitHub Copilot (GitHub Models) — free with Copilot subscription
- 📊 **Framework-Aware Analysis**: AI evaluates against Azure Landing Zone (80% coverage benchmark), CIS/NIST security baselines, and Well-Architected Framework
- 🚨 **Compliance Gap Analysis**: AI identifies specific findings with risk ratings and framework references
- 📐 **Framework Alignment Cards**: Visual assessment of ALZ, Security Baseline, and Well-Architected alignment in HTML report
- 🎯 **Enhanced Recommendations**: 11 trigger categories (up from 5) — broken DINE remediation, ALZ gaps, cost review, medium-security enforcement gaps
- 📋 **Lowered NC Threshold**: Any non-compliant resources now generate recommendations (previously required >10)
- 🔧 **3-Tier JSON Fallback**: Resilient AI response parsing handles malformed LLM output gracefully
- 💰 **Cost-Specific Analysis**: AI names each high-cost policy with enforcement mode, estimated cost impact, and budget recommendations
- 📝 **Compliance-Specific Analysis**: AI names each NC assignment with compliance rates, broken remediation detection, and category breakdown

See [AI-INTEGRATION-GUIDE.md](AI-INTEGRATION-GUIDE.md) for setup and examples.

### 🚀 v3.0: Major Release — Complete Interface Overhaul

- 🔧 **Scoring Accuracy**: Parameterised initiatives (Defender, ASC Default, Sentinel) now correctly scored using category + name keyword inference
- 🔄 **Automatic Update Check**: Script checks GitHub for newer versions at startup and shows new capabilities
- ⬇️ **Self-Update**: `-Update` switch downloads the latest version from GitHub, validates it, backs up the current script, and replaces it in place — no Azure login required
- �📊 **Enhanced Legends**: Cost & Security legends with real-world cost examples, scoring methodology panels, updated glossary formulas
- 📋 **Policy Exemptions**: Queries all exemptions from ARG, shows scope/category/expiry, integrated into Engineering Report
- 🗃️ **YAML Database Export**: `-Output YAML` exports full assessment snapshot for offline analysis
- 📈 **YAML Delta Comparison**: `-DeltaYAML <path>` compares against a previous snapshot — shows changes, drift, and posture trend
- 🎯 **Simplified CLI**: `-Output CSV,HTML` and `-CEP Full` replace 6+ legacy switches
- 📊 **Real policy metadata**: Batch ARG query resolves actual policy definitions — no more regex guessing
- 🔍 **All scopes by default**: MG + Subscriptions + RGs assessed automatically
- ⚡ **Quick Assess**: One-page executive summary with `-QuickAssess`
- 🇬🇧 **CE+ v3.2 Tests**: 5 test cases (TC1–TC5) aligned to [NCSC specification](https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf)
- ⚖️ **Control Type Balance**: Suggested ranges with honest attribution
- ⚠️ **Enhanced Anti-Patterns**: Expandable cards with granular detail and Microsoft docs references
- 👤 **Attribution**: Project credited to Riccardo Pomato

See [WHATS-NEW-v3.0.md](WHATS-NEW-v3.0.md) for full details.
## Features

### Performance (NEW in v2.1)
- **Azure Resource Graph Integration**: 10-50x faster than traditional enumeration
- **Single Query Architecture**: Retrieves all policy assignments in one call
- **No Context Switching**: Eliminates slow subscription context changes
- **Efficient Compliance Data**: Aggregated compliance queries using ARG
- **Scales to Thousands**: Handles large environments with ease

### Core Capabilities
- **Automatic Update Check**: Checks GitHub for newer versions at startup; displays new capabilities when an update is available
- **Self-Update (`-Update`)**: Downloads the latest script from GitHub, validates it has no parse errors, creates a versioned backup (e.g., `Get-PolicyAssignments-v3.0.0-backup.ps1`), replaces the local script, and exits so you can re-run with the new version. No Azure login required
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
- **HTML Report**: Interactive report with navigation, Azure Landing Zone coverage analysis, expandable anti-patterns with Microsoft docs references, control type balance with suggested ranges, policy exemptions, and optional delta assessment
- **YAML Database**: Complete assessment snapshot for offline analysis and delta comparisons
- **Non-Compliant Export**: Dedicated NC resource export
- **Custom Filenames**: User-defined or timestamped naming
- **Quick Assess**: One-page executive summary
- **Delta/Trending**: YAML snapshot comparison with `-DeltaYAML` for tracking changes across runs

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
- **CE+ Compliance**: `CyberEssentialsPlus_Compliance_YYYYMMDD_HHMMSS.csv` (when using `-CEP Export`)

**Location**: Current directory

**Columns included**: All policy details including Assignment Name, Display Name, Policy Type, Effect Type, Enforcement Mode, Security Impact, Cost Impact, Compliance Impact, Operational Overhead, Risk Level, Scope details, Parameters

**Examples**:
```powershell
# Export with default timestamped filename
.\Get-PolicyAssignments.ps1 -Output CSV

# Export with custom filename
.\Get-PolicyAssignments.ps1 -Output CSV -FileName "Q4-PolicyAudit.csv"

# Export Cyber Essentials Plus compliance report
.\Get-PolicyAssignments.ps1 -CEP Export

# Export with date-based filename
.\Get-PolicyAssignments.ps1 -Output CSV -FileName "Policies_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

### Cyber Essentials Plus Compliance

The script assesses your environment against UK Cyber Essentials Plus (CE+) requirements using the built-in **UK NCSC Cyber Essentials v3.1** Azure Policy Initiative. See the [Azure CE+ Compliance Offering](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus) for details.

⚠️ **EXPERIMENTAL FEATURE**  
- This tool does **NOT provide official CE+ certification**
- Use for **guidance only** — not for compliance attestation
- See [CYBER-ESSENTIALS-PLUS.md](CYBER-ESSENTIALS-PLUS.md) for full limitations

**Usage**:
```powershell
# Console output only
.\Get-PolicyAssignments.ps1 -CEP Show

# Run CE+ v3.2 test cases (TC1–TC5)
.\Get-PolicyAssignments.ps1 -CEP Test

# Export CE+ compliance to CSV
.\Get-PolicyAssignments.ps1 -CEP Export

# Full CE+ assessment
.\Get-PolicyAssignments.ps1 -CEP Full
```

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

## Regression Tests

The tracked Pester 5 regression suite runs offline and does not require an Azure login, GitHub token, or network access. It validates script syntax, release consistency, GitHub Models configuration, versioned ALZ source contracts, framework evidence semantics, CE+/DINE wording, and assignment metadata.

```powershell
# One-time prerequisite
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser

# Run the regression suite
Invoke-Pester -Path .\tests\Get-PolicyAssignments.Regression.Tests.ps1 -Output Detailed
```

## Limitations

- **Scope**: All scopes (Management Groups, Subscriptions, Resource Groups) are assessed by default. Use `-ManagementGroup` or `-Subscription` to filter.
- **Permissions**: Requires appropriate Azure permissions (Reader) on queried scopes. ARG queries respect RBAC automatically.
- **ALZ Context**: Policy recommendations and gap analysis are based on **Azure Landing Zone structure** - results are most meaningful in ALZ-compliant environments.
- **Connectivity**: Azure Landing Zone validation requires internet connectivity to fetch latest policies from the official [Azure Landing Zones Library](https://github.com/Azure/Azure-Landing-Zones-Library) (falls back to cached list if offline).

---

## Version History

- **v3.2.0**: AI Executive Insights plus official-source refresh for versioned ALZ assets, current GitHub Models API, Azure-discovered framework initiatives, and evidence-based CE+/DINE semantics.
- **v3.1.1**: Bug fix — YAML/HTML/console numeric fields now handle "N/A" values gracefully instead of failing with Int32 conversion errors.
- **v3.1.0**: Multi-assignment Cyber Essentials Plus — automatic detection of initiative assignments at multiple scopes, strictest-state-wins deduplication preventing double-counting, HTML report multi-assignment banner with per-assignment enforcement detail.
- **v3.0.0**: Major release — simplified CLI, real policy metadata, CE+ v3.2 tests, Quick Assess, YAML delta/trending, exemptions, Landing Zone Analysis in HTML report, enhanced anti-patterns, control type balance, scoring accuracy fixes, updated attribution. See [WHATS-NEW-v3.0.md](WHATS-NEW-v3.0.md).
- **v2.2.0**: Cyber Essentials Plus compliance mapping, `-ExportCEPCompliance` parameter, disclaimers. See [WHATS-NEW-v2.2.md](WHATS-NEW-v2.2.md).
- **v2.1.0**: Major Resource Graph (ARG) integration for 10-50x performance boost.
- **v2.0.1**: Enhanced summary statistics and detailed breakdowns.
- **v2.0.0**: Added subscription/RG enumeration, multi-tenant support, and impact analysis.
- **v1.0.0**: Initial release with multi-tenant support and inherited policy filtering.

## References

- [Azure Landing Zones Library](https://github.com/Azure/Azure-Landing-Zones-Library) - Official ALZ policy definitions
- [Azure Policy Overview](https://learn.microsoft.com/en-us/azure/governance/policy/overview)
- [Management Groups](https://learn.microsoft.com/en-us/azure/governance/management-groups/overview)

## License

This script is provided as-is for Azure governance and compliance purposes.
```
