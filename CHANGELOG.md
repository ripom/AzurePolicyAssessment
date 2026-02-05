# Changelog

All notable changes to the Azure Policy & Compliance Assessment Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- [COMPLIANCE-USAGE-GUIDE.md](COMPLIANCE-USAGE-GUIDE.md) - Compliance features
- [OUTPUT-OPTIONS.md](OUTPUT-OPTIONS.md) - Execution modes
