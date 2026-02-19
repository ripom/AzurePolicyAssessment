# Changelog

All notable changes to the Azure Policy & Compliance Assessment Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.1] - 2026-02-19

### ⚡ Performance Optimisation

- **Array append optimisation**: Replaced all `@() += $item` patterns with `[System.Collections.Generic.List[object]]` and `.Add()` / `.AddRange()` calls. This eliminates O(n²) array copy overhead in hot loops (policy assignment processing, ARG pagination, NC resource export, CEP compliance data). Tenants with 1000+ assignments will see meaningful speedup.
- **Removed unused variables**: Removed `$regEffect` and `$regNamesJoined` (assigned but never referenced).

## [3.0.0] - 2026-02-18

### � Major Release — Complete Interface Overhaul & Accuracy Upgrade

This release consolidates all changes from v2.3 through v2.6 into a single major version, introducing a simplified command interface, real policy-definition-based classification, CE+ v3.2 test specification support, delta/trending capabilities, and updated project attribution.

### 🔧 Cost & Security Scoring Accuracy Fix for Parameterised Initiatives

#### Fixed — Scoring Engine
- **Display name resolution**: `Get-PolicyRecommendation` now receives the human-readable display name (e.g. "Defender for SQL Servers on Machines provisioning") instead of the definition GUID. All keyword detectors (`defender`, `sentinel`, `backup`, `asc default`, etc.) now fire correctly.
- **Parameterised cost scoring**: Added `Parameterised|Multiple` handling to the cost switch — infers cost from category (Security Center/Monitoring/Backup → +30, Network/Compute → +15, other → +5) instead of scoring 0.
- **Parameterised security scoring**: Same fix for security — Security Center/Defender for Cloud → +15, Network/Identity → +10, other → +5.
- **Parameterised operational overhead**: New branch infers overhead from category (Security Center/Monitoring/Backup → High, Network/Compute/SQL → Medium, Regulatory Compliance → Medium, other → Low).
- **Risk level enforcement bonus**: Active enforcement bonus (-10 risk points) now applies to initiative effects containing Deny/DINE/Modify keywords, not just exact string matches.
- **Keyword regex update**: Added `security.?center` and `asc.?default` to both `$isSecurityName` and `$isCostName` patterns.
- **Context-aware recommendations**: New recommendation text for parameterised initiatives (Defender → licensing cost advice, Monitoring → ingestion cost advice, Regulatory → control group mapping advice).

#### Fixed — Impact Examples
| Policy | Before | After |
|--------|--------|-------|
| Defender for SQL Servers on Machines provisioning | Low / Low / Low | **High / High / High** |
| ASC Default | Low / Low / Low | **High / High / High** |
| ASC OpenSourceRelationalDatabasesProtection | Low / Low / Low | **Medium / High / High** |
| Sentinel - Configure VMs to run Azure Monitor Agent | Low / Low / Low | **Medium / High / High** |

#### Enhanced — Report Legends & Documentation
- **Cost & Overhead Legend**: Added real-world cost examples (Defender ~$15/server/month, Log Analytics ~$2.76/GB), explained parameterised initiative scoring
- **Security Legend**: Added parameterised initiative scoring explanation with category-based inference
- **Calculation details**: Updated "How are Cost/Security calculated?" panels with new Parameterised × Category signal row
- **Glossary**: Cost Impact and Operational Overhead entries now include full scoring formulas and parameterised initiative handling

### 📋 Policy Exemptions, YAML Database & Enhanced Architecture Insights

#### Added — Policy Exemptions
- **Exemption discovery**: Queries all `microsoft.authorization/policyexemptions` from Azure Resource Graph
- **Scope derivation from resource ID**: Correctly extracts scope from the exemption `id` (ARG exemptions don't have `properties.scope`)
- **Exemption detail**: Shows display name, category (Waiver/Mitigated), scope type, scope name, coverage (full/partial), expiry, and description
- **Exemptions by Assignment**: Grouped view showing which assignments have exemptions and how many
- **Integrated into Engineering Report**: Exemptions displayed as a subsection inside Engineering Report (not a standalone tab) for better context
- **Exemptions in console output**: Summary counts (active, expired, waiver, mitigated) shown during execution
- **Exemption lookup**: Each policy assignment result includes an `Exemptions` count

#### Added — YAML Database Export & Delta Comparison
- **`-Output YAML`**: Exports complete assessment snapshot (assignments, compliance, exemptions, CE+ results) to a YAML database file
- **`-DeltaYAML <path>`**: Compares current run against a previous YAML snapshot. Reports:
  - New and removed assignments
  - Changed assignments (property-level diffs with previous → current values)
  - Effect type shifts
  - Exemption changes (new/removed)
  - CE+ previous results
  - Overall posture trend (IMPROVING / STABLE / DEGRADING)
- **Delta in HTML**: When `-DeltaYAML` is used with `-Output HTML`, the delta assessment appears as a dedicated section
- **Delta in console**: `Show-YAMLDelta` displays colour-coded delta summary in the terminal
- **Composite matching key**: Uses `assignmentName|||scope` to prevent false delta matches across scopes

#### Added — Enhanced Architecture Insights
- **Control Type Balance**: Three individual progress bars (one per control type) with:
  - Suggested percentage ranges (honestly labelled as opinionated tool guidance, not WAF targets)
  - Dashed green bands showing suggested ranges for each
  - Health colour coding: green (in range), amber (close), red (out of range)
  - Overall balance badge: Well Balanced / Moderate / Imbalanced
  - Combined distribution bar
  - Collapsible explanation panel with disclaimer and reference to actual [WAF Security pillar](https://learn.microsoft.com/en-us/azure/well-architected/security/)
- **Expandable Anti-Patterns**: Each anti-pattern is now a collapsible card with:
  - What this means / Why it matters
  - Granular list of affected scopes or policies (names, types, NC counts)
  - Recommended actions
  - Links to official Microsoft documentation (Policy effects, enforcement mode, safe deployment practices, CAF governance, remediation, limits)
- **Duplicate detection**: New anti-pattern detects the same policy definition assigned multiple times at the same scope
- **AP severity colours**: Red border for critical (enforcement gaps), amber for others

#### Added — Documentation & Glossary Updates
- **Glossary expanded**: 19 → 23 terms. New: Parameterised, Disabled, Control Type Balance, Anti-Pattern, Delta Assessment
- **Glossary docs links**: Assignment, Deny, DINE, DoNotEnforce, Disabled, Exemption entries now link to official Microsoft docs
- **Risk Level & Security Impact**: Glossary entries now include the actual scoring formula
- **"How to Read" guide**: Updated section descriptions, expanded Key Terms from 7 to 11
- **Non-Compliant Policies**: Renamed table from "Non-Compliant Resources — Policy Perspective" to "Non-Compliant Policies"

#### Changed
- **Version**: Updated to 3.0.0
- **Section count**: 8 base sections (+ optional Delta Assessment with `-DeltaYAML`); exemptions folded into Engineering Report
- **Navigation**: Removed standalone Exemptions tab from nav bar
- **Exemption scope filter**: Uses `id`-based filtering instead of non-existent `properties.scope` for exemptions
- **`createdOn` field**: Uses `coalesce()` to try `properties.metadata.createdOn` first for exemptions

## [3.0.0] - 2026-02-10

### 🚀 Major Release — Complete Interface Overhaul & Accuracy Upgrade

This release consolidates all changes from v2.3 through v2.6 into a single major version, introducing a simplified command interface, real policy-definition-based classification, CE+ v3.2 test specification support, delta/trending capabilities, and updated project attribution.

### 🔄 Automatic Update Check

- **VERSION.json**: New machine-readable version manifest in the repository root containing version, release date, highlights, and download URL
- **Startup check**: Script fetches VERSION.json from GitHub at launch (5-second timeout, silent on failure)
- **Update banner**: When a newer version is detected, displays a prominent banner with version comparison, key highlights (up to 5), release notes URL, and download link
- **Non-blocking**: Network errors, offline mode, or rate limiting are silently ignored — the script continues normally
- **`-Update` self-update**: New `-Update` switch downloads the latest script from GitHub, validates it has no parse errors, creates a versioned backup (e.g., `Get-PolicyAssignments-v3.0.0-backup.ps1`), replaces the local file, and exits so the user can re-run with the new version. No Azure login required

#### Attribution
- **Project Ownership**: Updated all disclaimers to reflect that this project is made and maintained by **Riccardo Pomato**
- Removed references to "community-maintained" across console output, HTML header banner, and HTML footer disclaimer

#### Added — Simplified Command Interface (formerly v2.5)
- **`-Output` parameter** (`CSV`, `HTML`, `NC`, `All`): Replaces `-Export`, `-ExportHTML`, `-ExportNonCompliant` switches
- **`-CEP` parameter** (`Show`, `Test`, `Export`, `Full`): Replaces `-ShowCEPCompliance`, `-RunCEPTests`, `-ExportCEPCompliance` switches
- **`-Full` switch**: Runs a comprehensive assessment with all features enabled (equivalent to `-Output All -CEP Full`)
- **Initiative effect resolution**: Shows actual member-policy effects instead of generic "(Initiative)" label
- Legacy switches remain functional (backward compatible) but are hidden from tab-completion

#### Added — Scope Handling & Filtering (formerly v2.6)
- **`-ManagementGroup` parameter**: Filter assessment to a specific management group by name or ID
- **`-Subscription` parameter**: Filter assessment to a specific subscription by name or ID
- **All scopes included by default**: Management Groups, Subscriptions, and Resource Groups are assessed automatically
- Removed `-Scope`, `-IncludeSubscriptions`, and `-IncludeResourceGroups` parameters

#### Added — Accuracy & Performance Overhaul (formerly v2.4)
- **Real policy definition metadata**: Replaced heuristic name-regex classifications with actual policy definition metadata (category, effect) via batch ARG query — eliminates misclassifications
- **Batch policy definition resolution**: Single ARG query replaces N individual `Get-AzPolicyDefinition` calls — 10–100x faster for large tenants
- **`-QuickAssess` parameter**: Concise one-page summary with top KPIs, top 5 enforcement gaps, top 5 non-compliant assignments, and key recommendations
- **`-BaselinePath` parameter removed**: Delta/trending now uses `-DeltaYAML` exclusively for YAML-based snapshot comparison
- **Azure Landing Zone Analysis in HTML report**: New dedicated section (section 6) showing ALZ coverage metrics, category breakdown, missing policies, and audit-only policies
- **Simplified HTML report**: Removed redundant data, tightened sections for clarity
- Effect type detection now uses actual policy definition effect field

#### Added — CE+ v3.2 Test Specification (formerly v2.3)
- **CE+ v3.2 Test Cases (TC1–TC5)** via `-CEP Test`:
  - **TC1**: Remote Vulnerability Assessment (public IPs, NSG rules, Defender findings, storage)
  - **TC2**: Patching / Authenticated Scan (missing patches, CVSS 7+, EOL software)
  - **TC3**: Malware Protection (endpoint protection, Defender plans, signatures)
  - **TC4**: MFA Configuration (MFA assessments, conditional access policies)
  - **TC5**: Account Separation (RBAC privileged roles, admin controls)
- **MANUAL status type**: Subtests requiring physical/assessor verification are flagged MANUAL with checklists
- **Initiative-based CE compliance**: Replaced static CE policy mapping with built-in 'UK NCSC Cyber Essentials v3.1' Azure Policy Initiative for accurate compliance assessment
- Queries actual initiative definition, checks assignments, and reports per-policy compliance grouped by CE control areas

#### Changed
- **Version**: Updated from 2.2.x to 3.0.0
- **Disclaimer**: All disclaimers now credit Riccardo Pomato as author/maintainer
- **Parameter interface**: Unified `-Output` and `-CEP` parameters as the primary interface
- **Scope handling**: All scopes assessed by default (no opt-in switches needed)
- **Classification engine**: Real policy metadata replaces heuristic regex matching

#### Removed
- `-Scope` parameter
- `-IncludeSubscriptions` switch
- `-IncludeResourceGroups` switch
- Community attribution in disclaimers

#### Migration from v2.2
| Old (v2.2) | New (v3.0) |
|------------|------------|
| `-Export` | `-Output CSV` |
| `-ExportHTML` | `-Output HTML` |
| `-ExportNonCompliant` | `-Output NC` |
| `-Export -ExportHTML -ExportNonCompliant` | `-Output All` |
| `-ShowCEPCompliance` | `-CEP Show` |
| `-RunCEPTests` | `-CEP Test` |
| `-ExportCEPCompliance` | `-CEP Export` |
| All three CE switches | `-CEP Full` |
| `-IncludeSubscriptions -IncludeResourceGroups` | *(automatic — all scopes included by default)* |
| `-ShowRecommendations` | *(recommendations now always shown)* |

> **Note**: Old switches still work for backward compatibility but are hidden from tab-completion.

## [2.2.0] - 2026-02-06

### 🇬🇧 Cyber Essentials Plus Compliance Mapping (Experimental)

#### Added
- **Cyber Essentials Plus Assessment**: Maps UK NCSC Cyber Essentials Plus requirements to Azure Policy assignments
- **5 CE+ Categories**: Patch Management, Firewalls & Internet Boundary, Secure Configuration, Malware Protection, Access Control
- **24 Policy Mappings**: Comprehensive mapping of CE+ requirements to Azure built-in policies
- **Compliance Score**: Automatic calculation of CE+ compliance percentage
- **CSV Export**: New `-ExportCEPCompliance` parameter to export compliance report
- **Gap Analysis**: Identifies deployed vs. missing controls with recommendations
- **Documentation**: New `CYBER-ESSENTIALS-PLUS.md` with detailed mapping, limitations, and FAQ

#### Changed
- **Version**: Updated from 2.1.0 to 2.2.0
- **Script Help**: Added `-ExportCEPCompliance` parameter documentation and examples
- **README**: Updated with CE+ feature highlights and usage examples

#### Experimental Notice
⚠️ **This feature is experimental**:
- Policy mappings are approximate and may not be 100% accurate
- Display names may vary across Azure environments
- Custom policies may not be detected
- Does not provide official CE+ certification
- Community feedback welcome - see [CYBER-ESSENTIALS-PLUS.md](CYBER-ESSENTIALS-PLUS.md) for details

#### CSV Export Format
The `-ExportCEPCompliance` generates a CSV with:
- CE+ Category
- Required Control (Azure Policy name)
- Status (Deployed/Missing)
- Assignment Name
- Enforcement Mode
- Non-Compliant Resources
- Recommendation

## [2.1.0] - 2026-02-05

### 🚀 Major Performance Enhancement

**Azure Resource Graph Integration** - Complete rewrite for massive performance gains:

#### Added
- **Azure Resource Graph (ARG) Support**: Replaces traditional API enumeration with optimized queries
- **10-50x Performance Improvement**: Execution time reduced from minutes to seconds
- **Pagination Support**: Automatically handles large result sets (>1000 assignments per query)
- **Unified Compliance Queries**: Single ARG query for all compliance data
- **Simplified Architecture**: Reduced code complexity by ~50%
- **Tenant-Wide Scope**: Uses `-UseTenantScope` parameter to query management groups, subscriptions, and resource groups in single call
- **Progress Bars**: Added visual feedback for ARG queries (IDs 10, 11, 12) and dynamic progress updates during processing

#### Changed
- **Policy Enumeration**: Now uses single ARG query instead of iterating through MG/Sub/RG
- **Compliance Data**: ARG-based aggregation replaces multiple `Get-AzPolicyStateSummary` calls
- **Context Switching**: Eliminated subscription context changes (no more `Set-AzContext`)
- **Module Requirements**: Added `Az.ResourceGraph` module dependency
- **Error Handling**: Improved error messages with ARG-specific troubleshooting

#### Technical Details
- Query Optimization: Uses KQL (Kusto Query Language) for efficient filtering
- Single Tenant Query: All data retrieved in 2-3 queries total
- Memory Efficient: Streams results instead of loading all data upfront
- Native Scoping: ARG respects RBAC permissions automatically

#### Fixed
- **ALZ Policy Fetching**: Fixed syntax errors in function calls and ensured compatibility with supported ALZ Library versions to resolve 404 errors
- **Output Completeness**: Added missing Azure Landing Zone Recommendations breakdown, Recommended Actions (5 items), and Best Practices (6 items) sections at end of report

#### Performance Comparison
| Environment Size | v2.0.1 (API-based) | v2.1.0 (ARG-based) | Improvement |
|------------------|--------------------|--------------------|-------------|
| Small (< 50 policies) | 30-60 seconds | 5-10 seconds | 6x faster |
| Medium (50-200 policies) | 2-3 minutes | 10-20 seconds | 9x faster |
| Large (200-1000 policies) | 5-10 minutes | 20-40 seconds | 15x faster |
| Very Large (1000+ policies) | 10-30 minutes | 30-90 seconds | 20-40x faster |

### Features Preserved
- ✅ All existing parameters (`-ShowRecommendations`, `-Export`, `-IncludeSubscriptions`, etc.)
- ✅ ALZ gap analysis and recommendations
- ✅ Security posture assessment
- ✅ Compliance data (non-compliant resources/policies)
- ✅ CSV export functionality
- ✅ Multi-tenant support with `-TenantId` parameter
- ✅ Summary statistics and impact analysis

### Migration Notes
- **New Requirement**: Install `Az.ResourceGraph` module before running
  ```powershell
  Install-Module -Name Az.ResourceGraph -Force -AllowClobber
  ```
- **Backward Compatible**: All command-line parameters and output formats unchanged
- **No Breaking Changes**: Existing automation scripts will work without modification

## [2.0.1] - 2026-02-05

### Added
- **TenantId Parameter**: Optional `-TenantId` parameter to skip tenant selection prompt
  - Enables automation scenarios
  - Validates tenant ID and provides helpful error messages
  - Useful for CI/CD pipelines and scheduled assessments

### Enhanced
- **Summary Statistics**: Comprehensive breakdown of policy assignments
  - Policy type distribution (Initiatives vs Single Policies)
  - Assignments by scope (Management Groups, Subscriptions, Resource Groups)
  - Effect types distribution (Deny, Audit, DeployIfNotExists, Modify, etc.)
  - Enforcement mode statistics (Default vs DoNotEnforce)
  - Reorganized impact analysis for better readability

### Changed
- Enhanced recommendations output with detailed statistics
- Improved summary statistics formatting and organization
- Added conditional display for subscription and RG counts (only shown when enumerated)
- Improved tenant selection experience with clearer error messages

## [2.0.0] - 2026-02-05

### Added
- **Subscription and Resource Group Enumeration**: New parameters `-IncludeSubscriptions` and `-IncludeResourceGroups` to enumerate policies at subscription and RG levels
- **Multi-Tenant Support**: Explicit tenant boundary enforcement to prevent cross-tenant data leakage
- **Progress Bars**: Real-time progress tracking during policy enumeration and CSV export
- **Enhanced Security Posture Assessment**: Integrated Azure Landing Zone gap analysis with security recommendations
- **Compliance Data Export**: Separate columns for non-compliant resources and policies in CSV export

### Fixed
- **Compliance Data Accuracy**: Changed from `PolicySetDefinitionId`/`PolicyDefinitionId` filters to `PolicyAssignmentName` filter for reliable compliance queries
- **Non-Compliant Policies Count**: Now correctly counts unique non-compliant policy definitions within Initiatives using `Get-AzPolicyState`
- **Non-Compliant Resources**: Fixed resource counting to match Azure Portal values exactly
- **Tenant Context**: Added tenant ID verification and filtering to ensure only subscriptions from current tenant are processed

### Changed
- Removed 'Compliant Resources' column from export (not needed, reduces clutter)
- Enhanced ALZ recommendations to show missing policy counts and categorize by security impact
- Progress bars now show during Management Group, Subscription, and Resource Group processing
- Compliance queries now use assignment-specific filters for better accuracy

### Technical
- Updated compliance fetching logic across all scopes (MG, Subscription, RG)
- Added `$currentTenantId` tracking for tenant boundary enforcement
- Improved error handling for compliance data retrieval
- Added progress tracking with unique IDs for parallel operations

## [1.0.0] - Initial Release

### Added
- **Azure Landing Zone Policy Assessment**
  - Multi-tenant support with tenant selection
  - Management group discovery and traversal
  - Direct policy assignment filtering (excludes inherited)
  - Real-time progress tracking during execution

- **Policy Analysis**:
  - Policy type classification (Initiative vs Policy)
  - Effect type detection (Deny, Audit, DINE, Modify, etc.)
  - Enforcement mode identification
  - Impact analysis (Security, Cost, Compliance, Operational)
  - Risk level classification

- **Azure Landing Zone Integration**:
  - Dynamic policy recommendations from Azure Landing Zones Library
  - Category-based policy organization
  - Gap analysis against ALZ best practices
  - Fallback to static policy list

- **Recommendations Engine**:
  - Security impact classification
  - Cost impact assessment
  - Compliance impact evaluation
  - Operational overhead analysis
  - Actionable recommendations per policy

- **Export Functionality**:
  - CSV export with customizable filenames
  - Timestamped default naming
  - Comprehensive policy details in export

- **Output Features**:
  - Color-coded console output
  - Detailed progress indicators
  - Summary statistics
  - Policy coverage by management group
  - Security posture assessment

### Documentation
- README.md - Comprehensive usage guide
- ALZ architecture context
- Permission requirements
- Parameter documentation

---

## Version Numbering

- **Major version (X.0.0)**: Breaking changes or significant new features
- **Minor version (0.X.0)**: New features, backward compatible
- **Patch version (0.0.X)**: Bug fixes and minor improvements

## Support

For issues, questions, or feature requests, please review the documentation:
- [README.md](README.md) - Main documentation
- [CYBER-ESSENTIALS-PLUS.md](CYBER-ESSENTIALS-PLUS.md) - CE+ compliance mapping
- [OUTPUT-OPTIONS.md](OUTPUT-OPTIONS.md) - Execution modes
