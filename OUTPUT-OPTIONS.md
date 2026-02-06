# Output Options - Quick Reference

**Version 2.2.0** | [View Changelog](CHANGELOG.md)

## 🎯 NEW in v2.2: Cyber Essentials Plus Compliance

Experimental feature mapping CE+ requirements to Azure policies!
- `-ExportCEPCompliance` parameter for CSV export
- Gap analysis and compliance scoring
- See [CYBER-ESSENTIALS-PLUS.md](CYBER-ESSENTIALS-PLUS.md) for details

## 🚀 v2.1: Lightning-Fast Performance

The script uses Azure Resource Graph for 10-50x faster execution!
- Queries complete in seconds instead of minutes
- No subscription context switching required
- All features preserved

## Scope Options

Your script now supports multiple enumeration scopes for comprehensive policy assessment:

### 🎯 Scope 1: Management Groups Only (Default)
**Use Case**: Standard Azure Landing Zone policy assessment

```powershell
# Basic assessment
.\Get-PolicyAssignments.ps1

# With recommendations
.\Get-PolicyAssignments.ps1 -ShowRecommendations

# Export to CSV
.\Get-PolicyAssignments.ps1 -ShowRecommendations -Export
```

**What you get:**
- ✅ All policy assignments at Management Group level
- ✅ Direct assignments only (excludes inherited)
- ✅ ALZ policy coverage analysis
- ✅ Impact and gap analysis
- ✅ Security posture assessment

---

### 🎯 Scope 2: Include Subscriptions
**Use Case**: View subscription-level policy assignments in addition to MG policies

```powershell
# Include subscription policies
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -Export

# With recommendations
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -ShowRecommendations -Export
```

**What you get:**
- ✅ All Management Group policies (direct assignments)
- ✅ All Subscription-level policies (direct assignments)
- ✅ Accurate compliance data per assignment
- ✅ Progress tracking during enumeration

---

### 🎯 Scope 3: Full Coverage (MG + Subscriptions + Resource Groups)
**Use Case**: Complete policy inventory across all scopes

```powershell
# Full scope assessment
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -IncludeResourceGroups -Export

# With recommendations
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -IncludeResourceGroups -ShowRecommendations -Export
```

**What you get:**
- ✅ Management Group policies
- ✅ Subscription-level policies
- ✅ Resource Group-level policies
- ✅ Complete policy hierarchy view
- ✅ Compliance data for all assignments

---

## Decision Tree

```
Start
  │
  ├─ Need subscription policies?
  │   │
  │   ├─ YES
  │   │   │
  │   │   ├─ Need resource group policies too?
  │   │   │   │
  │   │   │   ├─ YES → Use -IncludeSubscriptions -IncludeResourceGroups
  │   │   │   │
  │   │   │   └─ NO → Use -IncludeSubscriptions
  │   │   
  │   └─ NO → Run without flags (MG policies only)
```

## Quick Examples

### Daily Operations
```powershell
# Quick policy check at MG level
.\Get-PolicyAssignments.ps1 -ShowRecommendations
```

### Weekly Review
```powershell
# Weekly assessment including subscriptions
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -ShowRecommendations -Export
```

### Monthly Reporting
```powershell
# Comprehensive monthly report
$month = Get-Date -Format "yyyy-MM"
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -IncludeResourceGroups -ShowRecommendations -Export -FileName "PolicyReport-$month.csv"
```

### Change Management
```powershell
# Review policy changes after ALZ deployment
.\Get-PolicyAssignments.ps1 -ShowRecommendations -Export
```

### Audit Preparation
```powershell
# Full policy inventory for audit
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -IncludeResourceGroups -ShowRecommendations -Export
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
  - Cost Impact
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
.\Get-PolicyAssignments.ps1 -Export -FileName "MyPolicyReport.csv"
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

All scopes include accurate compliance data:
- **Non-Compliant Resources**: Matches Azure Portal exactly
- **Non-Compliant Policies**: Accurate count for Initiatives

Compliance data is fetched using `PolicyAssignmentName` filter for reliability.

## Tips

1. **Start with MG only** - Use default scope for regular monitoring
2. **Add subscriptions for audits** - Include subscription scope for comprehensive reviews
3. **Use RG scope sparingly** - Resource Group enumeration is slower, use only when needed
4. **Export regularly** - Keep historical records for trend analysis
5. **Use custom filenames** - Organize exports by date or purpose
6. **Check progress bars** - Monitor execution for large environments
7. **Verify tenant context** - Ensure you're in the correct tenant before running

## Troubleshooting

### Slow Performance
- Reduce scope (remove `-IncludeResourceGroups`)
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

