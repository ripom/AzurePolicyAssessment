# Output Options - Quick Reference

**Version 4.0.0** | [View Changelog](CHANGELOG.md) | [What's New](WHATS-NEW-v4.0.md)

## Current Output Model

- `-Output YAML` exports a complete assessment database (assignments, compliance, exemptions, CE+ results)
- `-DeltaYAML <path>` compares against a previous YAML snapshot for change tracking
- `-Output HTML` creates the five-page audience report: Summary, CSA / Architect, Engineer, Evidence, and Methodology
- Policy exemptions and actionable records are displayed in Engineer; collection provenance and snapshot changes are displayed in Evidence
- Findings and recommendations are deterministic and require no model credentials

## Cyber Essentials Plus Assessment

Experimental feature mapping CE+ requirements to Azure policies:
- `-CEP Show` displays initiative-based CE evidence
- `-CEP Test` runs the mapped automated and manual CE+ test workflow
- `-CEP Export` exports CE evidence to CSV
- `-CEP Full` enables display, tests, and export
- See [CYBER-ESSENTIALS-PLUS.md](CYBER-ESSENTIALS-PLUS.md) for details

## 🚀 v2.1: Lightning-Fast Performance

The script uses Azure Resource Graph for 10-50x faster execution!
- Queries complete in seconds instead of minutes
- No subscription context switching required
- All features preserved

## Scope Options

All scopes (Management Groups, Subscriptions, Resource Groups) are assessed by default since v3.0. Use `-ManagementGroup` or `-Subscription` to filter.

### 🎯 Default: All Scopes
**Use Case**: Standard Azure policy assessment

```powershell
# Basic assessment — all scopes
.\Get-PolicyAssignments.ps1

# Quick executive summary
.\Get-PolicyAssignments.ps1 -QuickAssess

# Export to CSV and HTML
.\Get-PolicyAssignments.ps1 -Output CSV,HTML

# Full assessment — everything enabled
.\Get-PolicyAssignments.ps1 -Full
```

---

### 🎯 Filtered: Specific Management Group
**Use Case**: Assess a single MG hierarchy

```powershell
.\Get-PolicyAssignments.ps1 -ManagementGroup "mg-platform" -Output HTML
```

---

### 🎯 Filtered: Specific Subscription
**Use Case**: Assess a single subscription

```powershell
.\Get-PolicyAssignments.ps1 -Subscription "Production" -Output CSV
```

---

### 🎯 YAML Database & Delta
**Use Case**: Track changes across runs

```powershell
# First run — export YAML database
.\Get-PolicyAssignments.ps1 -Output YAML,HTML

# Subsequent runs — compare against previous snapshot
.\Get-PolicyAssignments.ps1 -DeltaYAML ".\PolicyAssessment_20260218.yaml" -Output HTML
```

The delta report shows:
- New and removed assignments (with detail)
- Changed assignments (property-level diffs)
- Effect type shifts
- Exemption changes (new/removed)
- Overall posture trend (IMPROVING / STABLE / DEGRADING)

---

## Decision Tree

```
Start
  │
  ├─ Need exports?
  │   │
  │   ├─ CSV only   → -Output CSV
  │   ├─ HTML report → -Output HTML
  │   ├─ YAML db     → -Output YAML
  │   ├─ Everything  → -Output All  (or -Full)
  │   └─ NC export   → -Output NC
  │
  ├─ Need delta comparison?
  │   │
  │   ├─ First run   → -Output YAML (creates snapshot)
  │   └─ Next run    → -DeltaYAML <prev.yaml> -Output HTML
  │
  ├─ Need CE+ compliance?
  │   │
  │   ├─ Console     → -CEP Show
  │   ├─ Test cases  → -CEP Test
  │   └─ Everything  → -CEP Full
  │
  └─ Need to filter scope?
      │
      ├─ Specific MG  → -ManagementGroup "mg-name"
      └─ Specific sub → -Subscription "sub-name"
```

## Quick Examples

### Daily Operations
```powershell
# Quick policy check
.\Get-PolicyAssignments.ps1 -QuickAssess
```

### Weekly Review
```powershell
# Weekly assessment with HTML report
.\Get-PolicyAssignments.ps1 -Output HTML
```

### Monthly Reporting
```powershell
# Comprehensive monthly report with delta
.\Get-PolicyAssignments.ps1 -Output All -CEP Full
```

### Change Tracking
```powershell
# Export YAML snapshot
.\Get-PolicyAssignments.ps1 -Output YAML

# Next month — compare against previous
.\Get-PolicyAssignments.ps1 -DeltaYAML ".\PolicyAssessment_20260218.yaml" -Output HTML
```

### Audit Preparation
```powershell
# Full policy inventory for audit
.\Get-PolicyAssignments.ps1 -Full
```

## Performance Tips

| Scope | Execution Time* | Resource Count | Best For |
|-------|----------------|----------------|----------|
| MG Only | 5-10 seconds | ~40-60 policies | Regular reviews |
| + Subscriptions | 10-20 seconds | +10-20 per sub | Subscription audits |
| + Resource Groups | 20-40 seconds | +varies by RGs | Complete inventory |

*Times vary based on environment size. Azure Resource Graph (ARG) provides 10-50x faster execution than traditional API enumeration.

## CSV Export Structure

### Single Export File
- **PolicyAssignments_TIMESTAMP.csv** - All policy details including:
  - Assignment Name
  - Display Name
  - Policy Type (Initiative/Policy)
  - Effect Type
  - Enforcement Mode
  - Non-Compliant Resources
  - Non-Compliant Policies
  - Security Impact
  - Cost Exposure
  - Compliance Impact
  - Operational Overhead
  - Risk Level
  - Scope Type (MG/Subscription/Resource Group)
  - Scope Name
  - Policy Name
  - Parameters
  - Recommendations

### Custom Filename
```powershell
.\Get-PolicyAssignments.ps1 -Output CSV -FileName "MyPolicyReport.csv"
```

## Progress Tracking

The script includes real-time progress bars:

```
Processing Policy Assignments
  Management Group: Platform (3 of 8)                [===>     ] 37%

Processing Subscription Assignments
  Subscription: prod-subscription (2 of 5)           [====>    ] 40%

Exporting Policy Assignments
  Processing item 85 of 120                          [========>] 71%
```

## Multi-Tenant Support

The script enforces tenant boundaries:

```
Current Tenant ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Subscription in context: MySubscription (sub-id)
Found 5 subscription(s) in current tenant
```

Only subscriptions from the current authenticated tenant are processed, preventing cross-tenant data leakage.

## Compliance Data

Compliance results are point-in-time evidence collected through Azure Resource Graph and Azure Policy state queries. The report distinguishes evaluated, not evaluated, and unavailable states; failed or missing queries cannot produce a positive posture conclusion. Azure Policy evaluation can be delayed, so validate material findings against the Azure Policy portal and rerun after remediation.

## Tips

1. **Start with default** — All scopes are assessed by default for comprehensive coverage
2. **Filter when needed** — Use `-ManagementGroup` or `-Subscription` to narrow the assessment
3. **Quick check** — Use `-QuickAssess` for a fast executive summary
4. **Export regularly** — Keep historical records for trend analysis using `-Output YAML`
5. **Use custom filenames** — Organize exports by date or purpose
6. **Check progress bars** — Monitor execution for large environments
7. **Verify tenant context** — Ensure you're in the correct tenant before running
8. **Track changes** — Use `-DeltaYAML` to compare against previous YAML snapshots

## Troubleshooting

### Slow Performance
- Use `-ManagementGroup` or `-Subscription` to narrow the scope
- Run during off-peak hours
- Check network connectivity

### Missing Compliance Data
- Ensure policies have been evaluated (wait 24 hours after assignment)
- Verify you have read permissions on subscriptions
- Check if policies are in DoNotEnforce mode

### Cross-Tenant Issues
- Run `Get-AzContext` to verify current tenant
- Use `Connect-AzAccount -Tenant <tenant-id>` to switch tenants
- Script will filter subscriptions to current tenant only

