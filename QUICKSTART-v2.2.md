# Quick Start Guide - v2.2.0

> ⚠️ **DISCLAIMER**: This is NOT an official Microsoft tool. Provided as-is with no warranties.  
> Results may not be 100% accurate. Support is best-effort only. Use at your own risk.

## 🎯 What's New?
**10-50x faster execution** using Azure Resource Graph!
**NEW**: Cyber Essentials Plus compliance mapping!

## ⚡ One-Time Setup

```powershell
# Install the new required module (30 seconds)
Install-Module -Name Az.ResourceGraph -Force -AllowClobber
```

## 📋 Usage (Same as Before!)

```powershell
# Basic assessment
.\Get-PolicyAssignments.ps1

# With recommendations
.\Get-PolicyAssignments.ps1 -ShowRecommendations

# With CE+ compliance (NEW in v2.2!)
.\Get-PolicyAssignments.ps1 -ShowRecommendations -ExportCEPCompliance

# Export to CSV
.\Get-PolicyAssignments.ps1 -Export

# Include subscriptions
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions

# Full coverage
.\Get-PolicyAssignments.ps1 -IncludeSubscriptions -IncludeResourceGroups

# Specify tenant (skip prompt)
.\Get-PolicyAssignments.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Complete assessment
.\Get-PolicyAssignments.ps1 -ShowRecommendations -IncludeSubscriptions -Export
```

## 📊 Performance

| Environment | Old Time | New Time | Speedup |
|-------------|----------|----------|---------|
| Small       | 30-60s   | 5-10s    | 6x      |
| Medium      | 2-3min   | 10-20s   | 9x      |
| Large       | 5-10min  | 20-40s   | 15x     |
| Very Large  | 10-30min | 30-90s   | 40x     |

## ✅ All Features Preserved

- ✅ ALZ gap analysis
- ✅ Compliance data
- ✅ Recommendations
- ✅ CSV export
- ✅ Multi-tenant
- ✅ Summary statistics

## 🔧 Rollback (if needed)

```powershell
Copy-Item "Get-PolicyAssignments-v2.0.1-backup.ps1" "Get-PolicyAssignments.ps1" -Force
```

## 📚 Documentation

- [WHATS-NEW-v2.1.md](WHATS-NEW-v2.1.md) - Full feature overview
- [MIGRATION-GUIDE-v2.1.md](MIGRATION-GUIDE-v2.1.md) - Detailed migration guide
- [README.md](README.md) - Complete usage guide
- [CHANGELOG.md](CHANGELOG.md) - Version history

## 🎯 Bottom Line

**Same script, same output, 10-50x faster!** Just install `Az.ResourceGraph` and go! 🚀
