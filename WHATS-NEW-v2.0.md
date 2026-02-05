# Version 2.0.0 - Enhanced Policy Assessment

## 🎉 Major Enhancements

Version 2.0.0 brings significant improvements to policy enumeration, compliance data accuracy, and multi-scope support!

## ✨ What's New

### 1. **Subscription and Resource Group Enumeration**
Expand your policy assessment beyond Management Groups:
```powershell
# Include subscription-level policies
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -Export

# Include all levels: MG + Subscriptions + Resource Groups
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -IncludeResourceGroups -Export
```

### 2. **Accurate Compliance Data**
Compliance numbers now match Azure Portal exactly:
- ✅ Fixed non-compliant resources count
- ✅ Fixed non-compliant policies count for Initiatives
- ✅ Uses `PolicyAssignmentName` filter for reliable queries
- ✅ Correctly counts unique policy definitions within Initiatives

**Before**: Inconsistent counts that didn't match portal
**After**: Exact match with Azure Portal compliance view

### 3. **Multi-Tenant Support**
Explicit tenant boundary enforcement:
```
Current Tenant ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Subscription in context: MySubscription (sub-id)
```
- Prevents cross-tenant data leakage
- Filters subscriptions by current tenant
- Clear tenant identification

### 4. **Progress Tracking**
Real-time progress bars during execution:
```
Processing Policy Assignments
  Management Group: Platform (2 of 8)            [===>     ] 25%
```
- Management Group processing
- Subscription enumeration
- Resource Group scanning
- CSV export progress

### 5. **Enhanced Security Posture Assessment**
Integrated ALZ gap analysis with security recommendations:
```
🔒 SECURITY POSTURE:
   ⚠️  Weak - Security posture requires immediate attention.
      • Only 3 high-impact security policies deployed
      • 45 Azure Landing Zone recommended policies missing
      • This represents critical security and governance gaps

   🛡️  AZURE LANDING ZONE RECOMMENDATIONS:
   Missing 45 ALZ recommended policies that provide:
      • Security Controls (12 missing): Network isolation, access control, encryption
      • Auto-Remediation (8 missing): Automated configuration and compliance
      • Monitoring & Audit (25 missing): Visibility and compliance tracking
```

### 6. **Improved Export Format**
Streamlined CSV export:
- ✅ Removed redundant 'Compliant Resources' column
- ✅ Added 'Non-Compliant Resources' column
- ✅ Added 'Non-Compliant Policies' column
- ✅ Shows accurate compliance data per assignment

## 📊 Output Comparison

### Before:
```
Assignment Name: PCI DSS v4
Non-Compliant Resources: 0 (incorrect)
Non-Compliant Policies: 0 (missing)
```

### After (v2.0):
```
Assignment Name: PCI DSS v4
Non-Compliant Resources: 114 (matches portal)
Non-Compliant Policies: 10 (accurate count)
```

## 🚀 Usage Examples

### Basic Usage (Management Groups only)
```powershell
.\Get-PolicyAssignments.ps1 -ShowRecommendations -Export
```

### Include Subscriptions
```powershell
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -Export
```

### Full Scope Assessment
```powershell
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -IncludeResourceGroups -ShowRecommendations -Export
```

### Export with Custom Filename
```powershell
.\Get-PolicyAssignments.ps1 -Export -FileName "MyPolicyReport.csv"
```

## 🔧 Technical Improvements

### Compliance Data Accuracy
**Changed**: From using `PolicySetDefinitionId`/`PolicyDefinitionId` filters
**To**: Using `PolicyAssignmentName` filter

This provides:
- More reliable query results
- Consistent data across Azure APIs
- Better matching with Azure Portal

### Non-Compliant Policies Counting
For Initiatives, the script now:
1. Queries `Get-AzPolicyState` with assignment filter
2. Filters for non-compliant states
3. Counts unique `PolicyDefinitionId` values
4. Returns accurate count of failed policies within the Initiative

### Tenant Boundary Enforcement
```powershell
$currentTenantId = (Get-AzContext).Tenant.Id
$allSubs = Get-AzSubscription | Where-Object { $_.TenantId -eq $currentTenantId }
```

Ensures only subscriptions from the current tenant are processed.

## 📦 Module Requirements

```powershell
Install-Module -Name Az.Accounts -Force
Install-Module -Name Az.Resources -Force
Install-Module -Name Az.PolicyInsights -Force
```

## 🎯 Breaking Changes

None! All existing parameters and functionality remain compatible.

## 📝 Migration Guide

If you're upgrading from v1.0:
1. No changes needed to existing scripts
2. Optionally add `-IncludeSubscriptions` for broader scope
3. Optionally add `-IncludeResourceGroups` for complete coverage
4. Compliance data is now more accurate automatically

## 🐛 Bug Fixes

- Fixed: Non-compliant resources showing 0 when portal shows actual numbers
- Fixed: Non-compliant policies count incorrect for Initiatives
- Fixed: Cross-tenant subscriptions appearing in reports
- Fixed: Progress tracking not showing during long operations
- Fixed: Export missing compliance data columns

## 📚 Documentation Updates

- Updated README.md with new features
- Updated CHANGELOG.md with detailed changes
- Updated OUTPUT-OPTIONS.md with examples
- Added comprehensive inline documentation

---

**Full Changelog**: [CHANGELOG.md](CHANGELOG.md)
**Documentation**: [README.md](README.md)
