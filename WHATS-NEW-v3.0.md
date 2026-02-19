# What's New in Version 3.x

> **Author**: This project is made and maintained by **Riccardo Pomato**.
>
> **Disclaimer**: This tool is **NOT an official Microsoft product**. It is provided as-is with no warranties. Results may not be 100% accurate — always verify with official tools. Use at your own risk.

---

## v3.0.0 — Complete Interface Overhaul, Scoring Accuracy & Enhanced Reporting

### 🔧 Cost & Security Scoring Accuracy for Parameterised Initiatives

Fixes a systemic scoring blind spot where **parameterised initiatives** (Defender, ASC Default, Sentinel, etc.) were incorrectly classified as Low cost / Low security / Low overhead.

**Root Cause**: Three bugs combined:
1. The scoring function received the definition GUID instead of the display name, so keyword detectors ("defender", "sentinel", "backup") never matched
2. The cost/security/overhead scoring branches only handled exact effect strings (`^DeployIfNotExists$`), missing `"Parameterised"` initiative effects entirely
3. The risk level enforcement bonus only applied to exact effect matches, not initiative effect summaries

**Impact**: All Defender, ASC Default, Sentinel agent, and similar parameterised initiatives now score correctly:

| Policy | Before (Cost/Security/Overhead) | After |
|--------|------|-------|
| Defender for SQL provisioning | Low / Low / Low | **High / High / High** |
| ASC Default | Low / Low / Low | **High / High / High** |
| Sentinel - Configure VMs to run AMA | Low / Low / Low | **Medium / High / High** |
| ASC OpenSourceRelationalDatabasesProtection | Low / Low / Low | **Medium / High / High** |

### 📊 Enhanced Report Legends

- **Cost & Overhead Legend**: Real-world cost examples (Defender ~$15/server/month, Log Analytics ~$2.76/GB), parameterised initiative explanation
- **Security Legend**: Explains how parameterised initiatives are scored by category + name keywords
- **Calculation panels**: New "Parameterised × Category" signal row in the scoring methodology tables
- **Glossary**: Cost Impact and Operational Overhead entries now include full scoring formulas

### 📋 Policy Exemptions

The tool now queries all policy exemptions from Azure Resource Graph and integrates them throughout:

- **ARG discovery**: Queries `microsoft.authorization/policyexemptions` with correct scope derivation from resource `id`
- **Detail view**: Display name, category (Waiver/Mitigated), scope type, scope name, coverage (full/partial), expiry date, description
- **Exemptions by Assignment**: Grouped view showing which assignments have exemptions and how many
- **Engineering Report**: Exemptions are shown as a subsection inside the Engineering Report (not a standalone tab) for better context alongside assignments
- **Console summary**: Active/expired/waiver/mitigated counts shown during execution
- **YAML export**: Full exemption data included in YAML database for delta comparison
- **Delta tracking**: New and removed exemptions shown in delta comparison

### 🗃️ YAML Database Export & Delta Comparison

New export format and comparison capabilities:

```powershell
# Export YAML database
.\Get-PolicyAssignments.ps1 -Output YAML

# Compare against previous snapshot
.\Get-PolicyAssignments.ps1 -DeltaYAML ".\PolicyAssessment_20260218.yaml" -Output HTML
```

The delta report includes:
- **New/removed assignments** with full detail
- **Changed assignments** with property-level diffs (previous → current)
- **Effect type shifts** (e.g., 3 more Deny, 2 fewer Audit)
- **Exemption changes** (new/removed)
- **CE+ previous results** (if available)
- **Overall trend**: IMPROVING / STABLE / DEGRADING
- **Composite matching key**: Uses `assignmentName|||scope` to prevent false matches across scopes

### ⚖️ Enhanced Control Type Balance

The Architecture Insights section now features:

- **Three individual bars** (Preventive, Detective, Remediation) each with:
  - Suggested percentage ranges shown as dashed green bands
  - Health colour coding: green (in range), amber (close), red (out of range)
- **Overall balance badge**: Well Balanced / Moderate / Imbalanced
- **Combined distribution bar** for quick visual summary
- **Collapsible explanation**: Guidance on what each control type means and how to improve
- **Honest attribution**: Suggested ranges clearly labelled as opinionated tool guidance, not official Azure or WAF targets. Links to the actual [WAF Security pillar](https://learn.microsoft.com/en-us/azure/well-architected/security/)

### ⚠️ Enhanced Anti-Patterns

Each anti-pattern is now an **expandable card** (click to expand):

| Pattern | Detail |
|---------|--------|
| **Disabled policies** | Lists affected policy names, explains quota impact |
| **High-security in audit-only** | Lists affected policies with scope, links to [enforcement mode docs](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/assignment-structure#enforcement-mode) |
| **Scopes lacking Deny** | Lists affected scopes with type, assignment count, NC count, links to [Deny effect docs](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects#deny) |
| **Scopes lacking auto-remediation** | Lists affected scopes, links to [DINE docs](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects#deployifnotexists) |
| **Duplicate assignments** *(new)* | Detects same policy assigned multiple times at same scope, links to [Policy limits docs](https://learn.microsoft.com/en-us/azure/governance/policy/overview#maximum-count-of-azure-policy-objects) |

Each card includes: **What this means**, **Why it matters**, **Affected items** (granular list), **Recommended action**, and **Reference links** to official Microsoft documentation.

### 📖 Documentation & Glossary

- **Glossary**: Expanded from 19 to 23 terms. New: Parameterised, Disabled, Control Type Balance, Anti-Pattern, Delta Assessment
- **Docs links in glossary**: Assignment, Deny, DINE, DoNotEnforce, Disabled, Exemption entries link to Microsoft docs
- **Risk Level & Security Impact**: Glossary now includes actual scoring formulas
- **"How to Read" guide**: Updated section descriptions, Key Terms expanded from 7 to 11
- **Table rename**: "Non-Compliant Resources — Policy Perspective" → "Non-Compliant Policies"

---

## v3.0.0 — Complete Interface Overhaul

### Overview

Version 3.0.0 is a major release that consolidates all improvements since v2.2 into a single, cohesive update. It introduces a **simplified command interface**, **real policy-definition-based classification** (eliminating heuristic guesswork), **CE+ v3.2 test specification support**, **delta/trending capabilities**, and **streamlined scope handling**.

---

## 🎯 Highlights at a Glance

| Feature | Description |
|---------|-------------|
| **Simplified CLI** | `-Output` and `-CEP` parameters replace 6+ legacy switches |
| **All scopes by default** | MG + Subscriptions + RGs assessed automatically |
| **Real metadata** | Policy definitions resolved via batch ARG query — no more regex guessing |
| **CE+ v3.2 Tests** | 5 test cases (TC1–TC5) aligned to NCSC specification |
| **Quick Assess** | One-page executive summary with `-QuickAssess` |
| **Delta/Trending** | Track changes across runs with `-DeltaYAML` |
| **Update Check** | Automatic check for newer versions at startup via `VERSION.json` |
| **Self-Update (`-Update`)** | Downloads latest script from GitHub, validates, backs up current version, and replaces in place — no Azure login required |
| **Attribution** | Project credited to Riccardo Pomato |

---

## 1️⃣ Simplified Command Interface

The new `-Output` and `-CEP` parameters provide a cleaner, more intuitive interface. Old switches still work for backward compatibility.

### `-Output` Parameter

Controls which exports are generated. Accepts one or more comma-separated values:

| Value | Description | Replaces |
|-------|-------------|----------|
| `CSV` | Export policy assignments to CSV | `-Export` |
| `HTML` | Generate interactive HTML report | `-ExportHTML` |
| `NC` | Export non-compliant resources to CSV | `-ExportNonCompliant` |
| `YAML` | Export full assessment database to YAML *(new in v3.2)* | — |
| `All` | All of the above | All switches |

```powershell
# Old way (still works)
.\Get-PolicyAssignments.ps1 -Export -ExportHTML

# New way
.\Get-PolicyAssignments.ps1 -Output CSV,HTML
```

### `-CEP` Parameter

Controls Cyber Essentials compliance features:

| Value | Description | Replaces |
|-------|-------------|----------|
| `Show` | Display CE v3.1 compliance analysis | `-ShowCEPCompliance` |
| `Test` | Run CE+ v3.2 test cases (TC1–TC5) | `-RunCEPTests` |
| `Export` | Export CE compliance data to CSV | `-ExportCEPCompliance` |
| `Full` | All of the above | All three switches |

```powershell
# Old way (still works)
.\Get-PolicyAssignments.ps1 -ShowCEPCompliance -RunCEPTests -ExportCEPCompliance

# New way
.\Get-PolicyAssignments.ps1 -CEP Full
```

### `-Full` Switch

Runs everything at once — equivalent to `-Output All -CEP Full`:

```powershell
.\Get-PolicyAssignments.ps1 -Full
```

---

## 2️⃣ Scope Handling Changes

**All scopes are now included by default.** You no longer need `-IncludeSubscriptions` or `-IncludeResourceGroups` — Management Groups, Subscriptions, and Resource Groups are all assessed automatically.

### New Filtering Parameters

| Parameter | Description |
|-----------|-------------|
| `-ManagementGroup` | Filter to a specific MG by name or ID |
| `-Subscription` | Filter to a specific subscription by name or ID |

```powershell
# Assess only the Platform management group hierarchy
.\Get-PolicyAssignments.ps1 -ManagementGroup "mg-platform"

# Assess only the Production subscription
.\Get-PolicyAssignments.ps1 -Subscription "Production"

# Tenant-wide (default — no filter needed)
.\Get-PolicyAssignments.ps1
```

### Removed Parameters

- `-Scope`
- `-IncludeSubscriptions`
- `-IncludeResourceGroups`

---

## 3️⃣ Accuracy & Performance Overhaul

### Real Policy Definition Metadata

Previous versions used **regex-based heuristics** on policy names to guess categories and effects. This led to misclassifications. Version 3.0.0 resolves actual policy definitions via a **single batch ARG query**, retrieving:

- **True policy category** (e.g., "Monitoring", "Security Center", "Network")
- **True effect** (Deny, Audit, DeployIfNotExists, Modify, etc.)
- **Initiative member effects** — shows the actual effects of member policies instead of "(Initiative)"

### Performance Gains

| Operation | v2.2 | v3.0 | Improvement |
|-----------|------|------|-------------|
| Policy definition resolution | N individual API calls | 1 batch ARG query | 10–100x faster |
| Effect classification | Regex on name strings | Policy definition metadata | 100% accurate |
| Initiative effects | Generic "(Initiative)" | Actual member effects | Full visibility |

---

## 4️⃣ Quick Assess Mode

New `-QuickAssess` parameter produces a concise one-page summary:

```powershell
.\Get-PolicyAssignments.ps1 -QuickAssess
```

Output includes:
- **Posture verdict** (Good / Needs Attention / Critical)
- **Top KPIs**: total assignments, enforcement rate, compliance rate
- **Top 5 enforcement gaps**
- **Top 5 non-compliant assignments**
- **Category breakdown**
- **Key recommended actions**

Ideal for executives, architects, and engineers who need a fast overview.

---

## 5️⃣ Delta / Trending with YAML Snapshots

The `-DeltaYAML` parameter enables change tracking across runs:

```powershell
# First run — export YAML database
.\Get-PolicyAssignments.ps1 -Output YAML

# Subsequent runs — compare against previous snapshot
.\Get-PolicyAssignments.ps1 -DeltaYAML ".\PolicyAssessment_20260218.yaml" -Output HTML
```

The delta report shows:
- **New assignments** added since last run
- **Removed assignments** no longer present
- **Changed assignments** with property-level diffs (previous → current)
- **Effect type shifts** (e.g., 3 more Deny, 2 fewer Audit)
- **Exemption changes** (new/removed)
- **Overall posture trend** — IMPROVING / STABLE / DEGRADING

---

## 6️⃣ CE+ v3.2 Test Specification (TC1–TC5)

The CE+ assessment has been significantly upgraded:

### Initiative-Based Compliance

Replaced the static 24-policy mapping with the **built-in 'UK NCSC Cyber Essentials v3.1' Azure Policy Initiative**. The tool now queries the actual initiative definition, checks assignments, and reports per-policy compliance grouped by CE control areas — dramatically improving accuracy.

### CE+ v3.2 Test Cases

When using `-CEP Test` or `-CEP Full`, the tool runs test cases aligned to the [NCSC CE+ v3.2 Test Specification](https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf):

| Test Case | Area | What It Checks |
|-----------|------|----------------|
| **TC1** | Remote Vulnerability Assessment | Public IPs, NSG rules, Defender findings, storage exposure |
| **TC2** | Patching / Authenticated Scan | Missing patches, CVSS 7+ vulnerabilities, EOL software |
| **TC3** | Malware Protection | Endpoint protection, Defender plans, signature freshness |
| **TC4** | MFA Configuration | MFA assessments, conditional access policies |
| **TC5** | Account Separation | RBAC privileged roles, admin controls |

Subtests that require physical verification are flagged as **MANUAL** with checklists for the assessor.

---

## 7️⃣ HTML Report Improvements

- **Azure Landing Zone Analysis section**: New dedicated section showing ALZ coverage metrics (total recommended, matched, missing, audit-only), category breakdown table, missing policies detail, and audit-only policies detail
- **8 base sections**: Executive Summary, Engineering Report, Architecture Insights, Governance Overview, Security Posture, Landing Zone Analysis, Cost Insights, Recommendations (+ optional Delta Assessment with `-DeltaYAML`)
- **Simplified layout**: Removed redundant data, tightened sections
- **Updated disclaimer**: Credits Riccardo Pomato as author/maintainer
- **Initiative effects**: Shows actual member-policy effects in the report
- **Delta section**: When using `-DeltaYAML`, the HTML report includes a visual delta summary

---

## Migration Guide

### From v2.2.x

| Old (v2.2) | New (v3.0) |
|------------|------------|
| `-Export` | `-Output CSV` |
| `-ExportHTML` | `-Output HTML` |
| `-ExportNonCompliant` | `-Output NC` |
| `-ShowCEPCompliance` | `-CEP Show` |
| `-RunCEPTests` | `-CEP Test` |
| `-ExportCEPCompliance` | `-CEP Export` |
| `-IncludeSubscriptions` | *(automatic)* |
| `-IncludeResourceGroups` | *(automatic)* |

> All old switches still work (backward compatible) but are hidden from tab-completion.

### Quick Examples

```powershell
# v2.2 style (still works)
.\Get-PolicyAssignments.ps1 -ShowRecommendations -Export -ExportHTML -IncludeSubscriptions

# v3.0 style (recommended)
.\Get-PolicyAssignments.ps1 -Output CSV,HTML

# Full assessment — everything enabled
.\Get-PolicyAssignments.ps1 -Full

# Quick executive summary
.\Get-PolicyAssignments.ps1 -QuickAssess

# Filtered + delta
.\Get-PolicyAssignments.ps1 -ManagementGroup "mg-platform" -DeltaYAML ".\PolicyAssessment_20260218.yaml" -Output HTML
```

---

## References

- [CHANGELOG.md](CHANGELOG.md) — Full changelog
- [README.md](README.md) — Main documentation
- [CYBER-ESSENTIALS-PLUS.md](CYBER-ESSENTIALS-PLUS.md) — CE+ compliance mapping
- [OUTPUT-OPTIONS.md](OUTPUT-OPTIONS.md) — Export and output modes
- [NCSC CE+ v3.2 Test Specification](https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf)
- [Azure CE+ Compliance Offering](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus)
