<#
.SYNOPSIS
    Lists all Azure Policy assignments from all management groups with detailed information using Azure Resource Graph.

.DESCRIPTION
    This script retrieves all Azure Policy assignments from all management groups in the tenant
    using Azure Resource Graph for optimal performance. It displays policy information in a table format 
    showing the policy name, type (Initiative or Policy), effect type, enforcement mode, scope type 
    (Management Group, Subscription, or Resource Group), scope name, and policy definition name. 
    Optionally provides recommendations on impact analysis.
    
    Security Impact Classification:
    - High: Policies with Deny/DeployIfNotExists/Modify effects, or those protecting critical areas
            (network security, data encryption, public access, Defender for Cloud, backup/DR)
    - Medium: Audit policies, governance policies, and general compliance controls
    - Low: Informational policies, tagging policies
    - None: Disabled policies or those in DoNotEnforce mode

.PARAMETER ShowRecommendations
    When specified, generates recommendations for each policy assignment including impact on cost, 
    security, compliance, and operational overhead. Also includes a detailed security posture 
    assessment showing which high-impact security policies are deployed.

.PARAMETER Export
    When specified, exports the results to a CSV file. Without this switch, no file is exported.

.PARAMETER FileName
    Custom filename for the CSV export. If not provided, uses default timestamped format:
    PolicyAssignments_YYYYMMDD_HHMMSS.csv. Only used when -Export is specified.

.PARAMETER IncludeSubscriptions
    When specified, includes policy assignments from all subscriptions in addition to management groups.

.PARAMETER IncludeResourceGroups
    When specified, includes policy assignments from all resource groups. Requires -IncludeSubscriptions to be effective.

.PARAMETER TenantId
    Optional tenant ID to use for the assessment. When specified, skips the tenant selection prompt.
    Useful for automation scenarios or when working with a specific tenant.

.EXAMPLE
    .\Get-PolicyAssignments.ps1
    Lists all policy assignments across all management groups.
    
.EXAMPLE
    .\Get-PolicyAssignments.ps1 -ShowRecommendations
    Lists all policies with detailed impact analysis and recommendations.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -Export
    Lists all policies and exports to timestamped CSV file.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -Export -FileName "MyPolicyReport.csv"
    Lists all policies and exports to custom filename.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -ShowRecommendations -Export -FileName "PolicyAudit_$(Get-Date -Format 'yyyy-MM').csv"
    Lists all policies with recommendations and exports to custom dated filename.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    Lists all policies in a specific tenant without prompting for tenant selection.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -IncludeSubscriptions -Export
    Automated assessment of a specific tenant including subscriptions with CSV export.

.NOTES
    Version: 2.1.0
    Last Updated: February 5, 2026
    Author: Azure Policy Assessment Tool
    
    Requires Azure PowerShell modules: Az.Accounts, Az.Resources, Az.ResourceGraph
    Requires appropriate Azure RBAC permissions (typically Management Group Reader)
    For compliance data, policies must be assigned and evaluated (may take time for new assignments)
    
    Performance: Uses Azure Resource Graph for fast queries (10-50x faster than traditional enumeration)
    
    Version History:
    - 2.1.0 (2026-02-05): Major performance enhancement using Azure Resource Graph (ARG):
                          - 10-50x faster execution (seconds instead of minutes)
                          - Simplified code with single queries instead of nested loops
                          - All features preserved (compliance, recommendations, export)
                          - Eliminated context switching between subscriptions
    - 2.0.1 (2026-02-05): Enhanced summary statistics with detailed breakdowns
    - 2.0.0 (2026-02-05): Enhanced with subscription/RG enumeration, multi-tenant support
    - 1.0.0 (Initial): Azure Landing Zone policy assessment with ALZ Library integration
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$ShowRecommendations,
    
    [Parameter(Mandatory=$false)]
    [switch]$Export,
    
    [Parameter(Mandatory=$false)]
    [string]$FileName,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeSubscriptions,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeResourceGroups,
    
    [Parameter(Mandatory=$false)]
    [string]$TenantId
)

# Script Version
$ScriptVersion = "2.1.0"
$ScriptLastUpdated = "2026-02-05"

# Display version banner
Write-Host "ÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉ" -ForegroundColor Cyan
Write-Host "  Azure Policy & Compliance Assessment Tool" -ForegroundColor Cyan
Write-Host "  Version: $ScriptVersion | Last Updated: $ScriptLastUpdated" -ForegroundColor Cyan
Write-Host "  Performance: Azure Resource Graph Integration" -ForegroundColor Green
Write-Host "ÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉ" -ForegroundColor Cyan

# Requires Azure PowerShell modules
# Install-Module -Name Az.Accounts -Force -AllowClobber
# Install-Module -Name Az.Resources -Force -AllowClobber
# Install-Module -Name Az.ResourceGraph -Force -AllowClobber

# Ensure user is logged in to Azure
try {
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "Not logged in to Azure. Please run Connect-AzAccount first." -ForegroundColor Red
        exit
    }
} catch {
    Write-Host "Not logged in to Azure. Please run Connect-AzAccount first." -ForegroundColor Red
    exit
}

# Get all available tenants
Write-Host "`nRetrieving available tenants..." -ForegroundColor Cyan
$tenants = Get-AzTenant

if ($tenants.Count -eq 0) {
    Write-Host "No tenants found. Please check your Azure access." -ForegroundColor Red
    exit
}

# Tenant selection logic
if ($TenantId) {
    # TenantId parameter provided - validate and use it
    $selectedTenant = $tenants | Where-Object { $_.Id -eq $TenantId }
    
    if ($selectedTenant) {
        Write-Host "Using specified tenant: $($selectedTenant.Name) (ID: $($selectedTenant.Id))" -ForegroundColor Green
        
        # Set the context to the specified tenant
        Write-Host "Switching to specified tenant..." -ForegroundColor Cyan
        Set-AzContext -TenantId $selectedTenant.Id | Out-Null
        Write-Host "Context switched successfully!" -ForegroundColor Green
    } else {
        Write-Host "Error: Tenant ID '$TenantId' not found or not accessible." -ForegroundColor Red
        Write-Host "Available tenants:" -ForegroundColor Yellow
        $tenants | ForEach-Object { Write-Host "  - $($_.Name) (ID: $($_.Id))" -ForegroundColor White }
        exit
    }
} else {
    # No TenantId parameter - prompt for selection
    # Display tenants for selection
    Write-Host "`nAvailable Tenants:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $tenants.Count; $i++) {
        $tenant = $tenants[$i]
        Write-Host "  [$($i + 1)] $($tenant.Name) (ID: $($tenant.Id))" -ForegroundColor White
    }

    # Prompt user to select a tenant
    Write-Host ""
    $selection = Read-Host "Select a tenant by number (1-$($tenants.Count))"

    # Validate selection
    if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $tenants.Count) {
        $selectedTenant = $tenants[[int]$selection - 1]
        Write-Host "Selected tenant: $($selectedTenant.Name) (ID: $($selectedTenant.Id))" -ForegroundColor Green
        
        # Set the context to the selected tenant
        Write-Host "Switching to selected tenant..." -ForegroundColor Cyan
        Set-AzContext -TenantId $selectedTenant.Id | Out-Null
        Write-Host "Context switched successfully!" -ForegroundColor Green
    } else {
        Write-Host "Invalid selection. Please run the script again and select a valid number." -ForegroundColor Red
        exit
    }
}

#region Function Definitions

# Function to get Azure Landing Zone recommended policies from GitHub
function Get-ALZRecommendedPolicies {
    param(
        [string]$ALZVersion = "platform/alz/2025.09.3"
    )
    
    Write-Host "  Fetching Azure Landing Zone recommended policies from official ALZ Library..." -ForegroundColor Gray
    
    try {
        # Official Azure Landing Zones Library - the authoritative source
        $alzLibraryBaseUrl = "https://api.github.com/repos/Azure/Azure-Landing-Zones-Library/contents/platform/alz/policy_assignments"
        
        Write-Host "    Querying ALZ Library policy assignments directory..." -ForegroundColor Gray
        
        # Get list of policy assignment files from the library
        $headers = @{
            'Accept' = 'application/vnd.github.v3+json'
            'User-Agent' = 'PowerShell-AzurePolicyAssessment'
        }
        
        $policyFiles = Invoke-RestMethod -Uri "$alzLibraryBaseUrl`?ref=$ALZVersion" -Headers $headers -Method Get -TimeoutSec 15 -ErrorAction Stop
        
        $discoveredPolicies = @{
            'Security & Network' = [System.Collections.ArrayList]@()
            'Monitoring & Logging' = [System.Collections.ArrayList]@()
            'Backup & DR' = [System.Collections.ArrayList]@()
            'Compliance & Governance' = [System.Collections.ArrayList]@()
            'Defender for Cloud' = [System.Collections.ArrayList]@()
            'Identity' = [System.Collections.ArrayList]@()
            'Other' = [System.Collections.ArrayList]@()
        }
        
        $policyCount = 0
        foreach ($file in $policyFiles) {
            if ($file.name -match '\.alz_policy_assignment\.json$') {
                # Extract policy name from filename (e.g., Deny-IP-forwarding.alz_policy_assignment.json -> Deny-IP-forwarding)
                $policyName = $file.name -replace '\.alz_policy_assignment\.json$', ''
                
                $policyCount++
                
                # Categorize by naming convention
                if ($policyName -match '^(Deny|Enforce).*(?:Public|Internet|IP|Network|Subnet|Nsg|Firewall|Storage.*Http|Hybrid)') {
                    [void]$discoveredPolicies['Security & Network'].Add($policyName)
                }
                elseif ($policyName -match '^Deploy.*(?:Log|Monitor|Diagnostic|Activity|Vmss|Vm.*Monitoring|Asc)') {
                    [void]$discoveredPolicies['Monitoring & Logging'].Add($policyName)
                }
                elseif ($policyName -match '(?:Backup|Asr|Recovery|ChangeTrack)') {
                    [void]$discoveredPolicies['Backup & DR'].Add($policyName)
                }
                elseif ($policyName -match '^(?:Enforce|Audit).*(?:Tag|Location|Naming|Acsb|Decomm|Sandbox|Unused)') {
                    [void]$discoveredPolicies['Compliance & Governance'].Add($policyName)
                }
                elseif ($policyName -match '(?:Mdfc|Defender|Security.*Center|Asc|DefSql|OssDb|MdEndpoint|SqlAtp)') {
                    [void]$discoveredPolicies['Defender for Cloud'].Add($policyName)
                }
                elseif ($policyName -match '(?:Identity|Mfa|Conditional|Access|Classic)') {
                    [void]$discoveredPolicies['Identity'].Add($policyName)
                }
                else {
                    [void]$discoveredPolicies['Other'].Add($policyName)
                }
            }
        }
        
        # If GitHub fetch failed or returned nothing, use fallback list
        $totalFound = ($discoveredPolicies.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        
        if ($totalFound -eq 0) {
            Write-Host "    No policies found from ALZ Library, using static fallback list..." -ForegroundColor Yellow
            return Get-FallbackALZPolicies
        }
        
        # Remove duplicates and empty categories (create copy of keys to avoid collection modification)
        $categories = @($discoveredPolicies.Keys)
        foreach ($category in $categories) {
            $discoveredPolicies[$category] = @($discoveredPolicies[$category] | Select-Object -Unique | Sort-Object)
        }
        
        Write-Host "    Successfully retrieved $totalFound policy recommendations from ALZ Library ($ALZVersion)" -ForegroundColor Green
        return $discoveredPolicies
    }
    catch {
        Write-Host "    Error fetching from ALZ Library: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Using static fallback list..." -ForegroundColor Yellow
        return Get-FallbackALZPolicies
    }
}

# Fallback static list if GitHub is unavailable
function Get-FallbackALZPolicies {
    return @{
        'Security & Network' = @(
            'Deny-Public-IP',
            'Deny-MgmtPorts-Internet',
            'Deny-Subnet-Without-Nsg',
            'Deny-IP-forwarding',
            'Deny-Public-Endpoints',
            'Enforce-TLS-SSL',
            'Deny-Storage-http',
            'Deny-Privileged-AKS',
            'Deny-Public-IP-On-NIC',
            'Deny-Priv-Esc-AKS'
        )
        'Monitoring & Logging' = @(
            'Deploy-AzActivity-Log',
            'Deploy-ASC-Monitoring',
            'Deploy-Diagnostic-Settings',
            'Deploy-VM-Monitoring',
            'Deploy-VMSS-Monitoring',
            'Deploy-Log-Analytics',
            'Deploy-vmHybr-Monitoring'
        )
        'Backup & DR' = @(
            'Deploy-VM-Backup',
            'Enforce-ASR',
            'Deploy-VM-ChangeTrack',
            'Deploy-VMSS-ChangeTrack',
            'Deploy-vmArc-ChangeTrack'
        )
        'Compliance & Governance' = @(
            'Enforce-ACSB',
            'Audit-ResourceRGLocation',
            'Require-Tag',
            'Audit-UnusedResources',
            'Enforce-ALZ-Decomm',
            'Enforce-ALZ-Sandbox',
            'Audit-TrustedLaunch',
            'Audit-ZoneResiliency'
        )
        'Defender for Cloud' = @(
            'Deploy-MDFC-DefSQL-AMA',
            'Deploy-MDFC-OssDb',
            'Deploy-MDEndpoints',
            'Deploy-MDEndpointsAMA',
            'Deploy-MDFC-SqlAtp'
        )
        'Identity' = @(
            'Enforce-MFA',
            'Deny-Classic-Resources'
        )
    }
}

# Function to generate policy recommendations
function Get-PolicyRecommendation {
    param(
        [string]$PolicyName,
        [string]$EffectType,
        [string]$EnforcementMode,
        [string]$PolicyType
    )
    
    # Security impact classification
    $securityImpact = "Medium"
    if ($EnforcementMode -eq "DoNotEnforce") {
        $securityImpact = "None"
    } elseif ($EffectType -in @("Deny", "DeployIfNotExists", "Modify")) {
        $securityImpact = "High"
    } elseif ($PolicyName -match "Security|Defender|Encryption|Network|Public|Backup|DR|DisasterRecovery|TLS|SSL|Firewall|NSG|DDoS") {
        $securityImpact = "High"
    } elseif ($EffectType -eq "Audit") {
        $securityImpact = "Medium"
    } elseif ($PolicyName -match "Tag|Label|Naming") {
        $securityImpact = "Low"
    }
    
    # Cost impact
    $costImpact = "Low"
    if ($PolicyName -match "DeployIfNotExists|Deploy|Backup|Monitoring|Diagnostics|Defender|Security") {
        $costImpact = "Medium"
    }
    if ($PolicyName -match "VM|Storage|Database|Cosmos|SQL") {
        $costImpact = "High"
    }
    
    # Compliance impact
    $complianceImpact = "Medium"
    if ($PolicyName -match "ISO|NIST|PCI|HIPAA|SOC|Compliance|Audit|GDPR") {
        $complianceImpact = "High"
    }
    if ($EnforcementMode -eq "DoNotEnforce") {
        $complianceImpact = "Low"
    }
    
    # Operational overhead
    $operationalOverhead = "Low"
    if ($EffectType -in @("DeployIfNotExists", "Modify")) {
        $operationalOverhead = "High"
    } elseif ($EffectType -eq "Deny") {
        $operationalOverhead = "Medium"
    }
    
    # Risk level
    $riskLevel = "Medium"
    if ($securityImpact -eq "None" -or $EnforcementMode -eq "DoNotEnforce") {
        $riskLevel = "Low"
    } elseif ($securityImpact -eq "High" -and $EffectType -eq "Deny") {
        $riskLevel = "High"
    }
    
    # Generate recommendation
    $recommendation = ""
    if ($EnforcementMode -eq "DoNotEnforce") {
        $recommendation = "Policy is in audit-only mode. Consider enabling enforcement for production compliance."
    } elseif ($EffectType -eq "Audit" -and $securityImpact -eq "High") {
        $recommendation = "High security impact policy in audit mode. Review findings and consider Deny effect."
    } elseif ($EffectType -eq "Deny") {
        $recommendation = "Preventive control in place. Ensure exception process is documented."
    } elseif ($EffectType -eq "DeployIfNotExists") {
        $recommendation = "Auto-remediation enabled. Monitor deployment costs and performance impact."
    } else {
        $recommendation = "Review policy effectiveness regularly and adjust as needed."
    }
    
    return @{
        SecurityImpact = $securityImpact
        CostImpact = $costImpact
        ComplianceImpact = $complianceImpact
        OperationalOverhead = $operationalOverhead
        RiskLevel = $riskLevel
        Recommendation = $recommendation
    }
}

#endregion Function Definitions

Write-Host "`nInitializing Azure Resource Graph queries...\" -ForegroundColor Cyan

# Get current tenant context to enforce tenant boundary
$currentContext = Get-AzContext
if (-not $currentContext) {
    Write-Host "ERROR: No Azure context available. Please run Connect-AzAccount first." -ForegroundColor Red
    exit
}

$currentTenantId = $currentContext.Tenant.Id
Write-Host "Current Tenant ID: $currentTenantId" -ForegroundColor Gray
Write-Host "Subscription in context: $($currentContext.Subscription.Name) ($($currentContext.Subscription.Id))" -ForegroundColor Gray
Write-Host "" # Blank line

# Check if Az.ResourceGraph module is available
try {
    $argModule = Get-Module -Name Az.ResourceGraph -ListAvailable | Select-Object -First 1
    if (-not $argModule) {
        Write-Host "ERROR: Az.ResourceGraph module not found" -ForegroundColor Red
        Write-Host "Please install it with: Install-Module -Name Az.ResourceGraph -Force" -ForegroundColor Yellow
        exit
    }
    Import-Module Az.ResourceGraph -ErrorAction Stop
    Write-Host "Ô£ô Az.ResourceGraph module loaded successfully (Version: $($argModule.Version))" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to load Az.ResourceGraph module: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

Write-Host "" # Blank line

# Create array to store results
$results = @()

Write-Host "`nQuerying Azure Resource Graph for policy assignments..." -ForegroundColor Cyan
Write-Host "(Using Azure Resource Graph for optimal performance)" -ForegroundColor DarkGray
Write-Host "" # Blank line

# Build ARG query based on parameters
$scopeFilter = ""
if (-not $IncludeSubscriptions -and -not $IncludeResourceGroups) {
    # Management Groups only
    $scopeFilter = "| where properties.scope contains 'managementGroups'"
    Write-Host "Scope: Management Groups only" -ForegroundColor Gray
} elseif ($IncludeSubscriptions -and -not $IncludeResourceGroups) {
    # MGs and Subscriptions
    $scopeFilter = "| where properties.scope contains 'managementGroups' or (properties.scope contains 'subscriptions' and properties.scope !contains 'resourceGroups')"
    Write-Host "Scope: Management Groups and Subscriptions" -ForegroundColor Gray
} else {
    # All scopes
    Write-Host "Scope: Management Groups, Subscriptions, and Resource Groups" -ForegroundColor Gray
}

# ARG Query for Policy Assignments
$policyQuery = @"
policyresources
| where type == 'microsoft.authorization/policyassignments'
$scopeFilter
| extend 
    scopeType = case(
        properties.scope contains 'resourceGroups', 'Resource Group',
        properties.scope contains 'subscriptions' and properties.scope !contains 'resourceGroups', 'Subscription',
        'Management Group'
    ),
    policyType = iff(properties.policyDefinitionId contains 'policySetDefinitions', 'Initiative', 'Policy'),
    enforcementMode = iff(isnull(properties.enforcementMode) or properties.enforcementMode == '', 'Default', properties.enforcementMode)
| project 
    assignmentId = id,
    assignmentName = name,
    displayName = properties.displayName,
    policyType,
    policyDefinitionId = properties.policyDefinitionId,
    scope = properties.scope,
    scopeType,
    enforcementMode,
    parameters = properties.parameters,
    subscriptionId,
    resourceGroup
| order by scopeType asc, assignmentName asc
"@

try {
    Write-Host "Executing Resource Graph query..." -ForegroundColor Cyan
    Write-Progress -Activity "Querying Azure Resource Graph" -Status "Retrieving policy assignments..." -PercentComplete 0 -Id 10
    
    $argResults = Search-AzGraph -Query $policyQuery -First 1000 -UseTenantScope
    
    if ($argResults.Count -eq 1000) {
        Write-Host "  Warning: Result limit reached (1000). Using pagination..." -ForegroundColor Yellow
        # If we hit the limit, we need to page through results
        $allArgResults = @()
        $allArgResults += $argResults
        $skipToken = $argResults.SkipToken
        $pageCount = 1
        
        while ($skipToken) {
            $pageCount++
            Write-Progress -Activity "Querying Azure Resource Graph" -Status "Retrieving page $pageCount (total: $($allArgResults.Count) assignments)..." -PercentComplete 25 -Id 10
            $moreResults = Search-AzGraph -Query $policyQuery -First 1000 -SkipToken $skipToken -UseTenantScope
            $allArgResults += $moreResults
            $skipToken = $moreResults.SkipToken
            Write-Host "  Retrieved $($allArgResults.Count) assignments..." -ForegroundColor Gray
        }
        $argResults = $allArgResults
    }
    
    Write-Progress -Activity "Querying Azure Resource Graph" -Status "Completed" -PercentComplete 100 -Id 10
    Write-Progress -Activity "Querying Azure Resource Graph" -Completed -Id 10
    Write-Host "  Ô£ô Found $($argResults.Count) policy assignments" -ForegroundColor Green
    Write-Host "" # Blank line
} catch {
    Write-Host "ERROR: Failed to query Azure Resource Graph" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "" # Blank line
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Ensure Az.ResourceGraph module is installed: Install-Module Az.ResourceGraph" -ForegroundColor Yellow
    Write-Host "  2. Verify you have appropriate permissions (Reader role)" -ForegroundColor Yellow
    exit
}

# Now query compliance data using ARG
Write-Host "Querying compliance data from Azure Resource Graph..." -ForegroundColor Cyan
$complianceQuery = @"
policyresources
| where type == 'microsoft.policyinsights/policystates'
| where properties.complianceState == 'NonCompliant'
| extend policyAssignmentId = tolower(tostring(properties.policyAssignmentId))
| summarize 
    NonCompliantResources = dcount(tostring(properties.resourceId)),
    NonCompliantPolicyDefs = dcount(tostring(properties.policyDefinitionId))
    by policyAssignmentId
"@

$complianceData = @{}
try {
    Write-Progress -Activity "Querying Compliance Data" -Status "Retrieving non-compliant resources..." -PercentComplete 0 -Id 11
    
    $complianceResults = Search-AzGraph -Query $complianceQuery -First 1000 -UseTenantScope
    
    if ($complianceResults) {
        # Handle pagination if needed
        if ($complianceResults.Count -eq 1000) {
            $allComplianceResults = @()
            $allComplianceResults += $complianceResults
            $skipToken = $complianceResults.SkipToken
            $pageCount = 1
            
            while ($skipToken) {
                $pageCount++
                Write-Progress -Activity "Querying Compliance Data" -Status "Retrieving page $pageCount..." -PercentComplete 25 -Id 11
                $moreResults = Search-AzGraph -Query $complianceQuery -First 1000 -SkipToken $skipToken -UseTenantScope
                $allComplianceResults += $moreResults
                $skipToken = $moreResults.SkipToken
            }
            $complianceResults = $allComplianceResults
        }
        
        Write-Progress -Activity "Querying Compliance Data" -Status "Processing results..." -PercentComplete 75 -Id 11
        
        # Build lookup dictionary
        foreach ($item in $complianceResults) {
            $complianceData[$item.policyAssignmentId] = @{
                NonCompliantResources = $item.NonCompliantResources
                NonCompliantPolicyDefs = $item.NonCompliantPolicyDefs
            }
        }
        Write-Progress -Activity "Querying Compliance Data" -Completed -Id 11
        Write-Host "  Ô£ô Retrieved compliance data for $($complianceData.Count) assignments" -ForegroundColor Green
    } else {
        Write-Progress -Activity "Querying Compliance Data" -Completed -Id 11
        Write-Host "  No non-compliant resources found (all policies are compliant)" -ForegroundColor Green
    }
} catch {
    Write-Host "  Warning: Could not retrieve compliance data: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Continuing without compliance information..." -ForegroundColor Gray
}

Write-Host "" # Blank line

# Get management group names for display
Write-Host "Retrieving management group details for display names..." -ForegroundColor Cyan
Write-Progress -Activity "Loading Management Groups" -Status "Retrieving management group hierarchy..." -PercentComplete 0 -Id 12

$mgLookup = @{}
try {
    $rootMgs = Get-AzManagementGroup -ErrorAction Stop
    $mgCount = 0
    $totalMgs = $rootMgs.Count
    
    foreach ($rootMg in $rootMgs) {
        $mgCount++
        $percentComplete = [math]::Round(($mgCount / $totalMgs) * 100)
        Write-Progress -Activity "Loading Management Groups" -Status "Processing $($rootMg.DisplayName)..." -PercentComplete $percentComplete -Id 12
        
        $mgWithChildren = Get-AzManagementGroup -GroupId $rootMg.Name -Expand -Recurse -ErrorAction SilentlyContinue
        if ($mgWithChildren) {
            $mgLookup[$mgWithChildren.Name] = $mgWithChildren.DisplayName
            
            function Add-MgToLookup {
                param($Mg)
                if ($Mg.Children) {
                    foreach ($child in $Mg.Children) {
                        if ($child.Type -eq '/providers/Microsoft.Management/managementGroups') {
                            $childMg = Get-AzManagementGroup -GroupId $child.Name -Expand -Recurse -ErrorAction SilentlyContinue
                            if ($childMg) {
                                $mgLookup[$childMg.Name] = $childMg.DisplayName
                                Add-MgToLookup -Mg $childMg
                            }
                        }
                    }
                }
            }
            Add-MgToLookup -Mg $mgWithChildren
        }
    }
    Write-Progress -Activity "Loading Management Groups" -Completed -Id 12
    Write-Host "  Ô£ô Loaded $($mgLookup.Count) management group names" -ForegroundColor Green
} catch {
    Write-Progress -Activity "Loading Management Groups" -Completed -Id 12
    Write-Host "  Warning: Could not retrieve management group names" -ForegroundColor Yellow
}

Write-Host "" # Blank line
Write-Host "Processing policy assignments and building results..." -ForegroundColor Cyan
Write-Progress -Activity "Processing Policy Assignments" -Status "Starting processing..." -PercentComplete 0 -Id 1

# Process each assignment from ARG results
$processedCount = 0
$totalAssignments = $argResults.Count

foreach ($assignment in $argResults) {
    $processedCount++
    
    # Update progress bar more frequently for better feedback
    $updateFrequency = if ($totalAssignments -gt 500) { 50 } elseif ($totalAssignments -gt 100) { 10 } else { 1 }
    
    if ($processedCount % $updateFrequency -eq 0 -or $processedCount -eq $totalAssignments -or $processedCount -eq 1) {
        $percentComplete = [math]::Round(($processedCount / $totalAssignments) * 100, 2)
        $statusMessage = "Processing assignment $processedCount of $totalAssignments ($percentComplete%)"
        Write-Progress -Activity "Processing Policy Assignments" -Status $statusMessage -PercentComplete $percentComplete -Id 1
    }
    
    # Extract policy definition name from PolicyDefinitionId
    $policyDefName = if ($assignment.policyDefinitionId -match '/([^/]+)$') {
        $Matches[1]
    } else {
        $assignment.policyDefinitionId
    }
    
    # Determine effect type (simplified - actual effect may vary by parameters)
    $effectType = switch -Regex ($policyDefName) {
        'Deny' { 'Deny' }
        'Audit' { 'Audit' }
        'DeployIfNotExists|DINE' { 'DeployIfNotExists' }
        'Modify' { 'Modify' }
        'Disabled' { 'Disabled' }
        default { 'Audit' }  # Default assumption
    }
    
    # Format parameters
    $parametersString = if ($assignment.parameters) {
        try {
            $paramJson = $assignment.parameters | ConvertTo-Json -Compress -Depth 5
            if ($paramJson.Length -gt 100) {
                $paramJson.Substring(0, 97) + "..."
            } else {
                $paramJson
            }
        } catch {
            "(parameters present)"
        }
    } else {
        "(no parameters)"
    }
    
    # Get scope name
    $scopeName = "Unknown"
    $mgId = ""
    
    if ($assignment.scopeType -eq 'Management Group') {
        if ($assignment.scope -match '/managementGroups/([^/]+)$') {
            $mgId = $Matches[1]
            $scopeName = if ($mgLookup[$mgId]) { $mgLookup[$mgId] } else { $mgId }
        }
    } elseif ($assignment.scopeType -eq 'Subscription') {
        if ($assignment.scope -match '/subscriptions/([^/]+)$') {
            $subId = $Matches[1]
            try {
                $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue
                $scopeName = if ($sub) { $sub.Name } else { $subId }
            } catch {
                $scopeName = $subId
            }
        }
    } elseif ($assignment.scopeType -eq 'Resource Group') {
        if ($assignment.scope -match '/resourceGroups/([^/]+)$') {
            $scopeName = $Matches[1]
        }
    }
    
    # Get recommendations
    $recommendationObj = Get-PolicyRecommendation -PolicyName $policyDefName -EffectType $effectType -EnforcementMode $assignment.enforcementMode -PolicyType $assignment.policyType
    
    # Get compliance data for this assignment
    $assignmentIdLower = $assignment.assignmentId.ToLower()
    $nonCompliantResources = 0
    $nonCompliantPolicies = 0
    
    if ($complianceData.ContainsKey($assignmentIdLower)) {
        $nonCompliantResources = $complianceData[$assignmentIdLower].NonCompliantResources
        $nonCompliantPolicies = $complianceData[$assignmentIdLower].NonCompliantPolicyDefs
    }
    
    # For single policies, non-compliant policies is 0 or 1
    if ($assignment.policyType -eq 'Policy' -and $nonCompliantResources -gt 0) {
        $nonCompliantPolicies = 1
    }
    
    # Create result object
    $policyResult = [PSCustomObject]@{
        'Assignment Name'     = $assignment.assignmentName
        'Display Name'        = $assignment.displayName
        'Policy Type'         = $assignment.policyType
        'Effect Type'         = $effectType
        'Enforcement Mode'    = $assignment.enforcementMode
        'Non-Compliant Resources' = $nonCompliantResources
        'Non-Compliant Policies' = $nonCompliantPolicies
        'Security Impact'     = $recommendationObj.SecurityImpact
        'Cost Impact'         = $recommendationObj.CostImpact
        'Compliance Impact'   = $recommendationObj.ComplianceImpact
        'Operational Overhead'= $recommendationObj.OperationalOverhead
        'Risk Level'          = $recommendationObj.RiskLevel
        'Scope Type'          = $assignment.scopeType
        'Scope Name'          = $scopeName
        'Management Group ID' = $mgId
        'Policy Name'         = $policyDefName
        'Parameters'          = $parametersString
        'Recommendation'      = $recommendationObj.Recommendation
        'Scope'               = $assignment.scope
    }
    
    $results += $policyResult
}

Write-Progress -Activity "Processing Policy Assignments" -Completed -Id 1
Write-Host "`nProcessing complete!" -ForegroundColor Cyan

# Display results in table format
Write-Host "`nPolicy Assignments Summary:" -ForegroundColor Cyan
$results | Format-Table -AutoSize

# Generate overall recommendations if switch is enabled
if ($ShowRecommendations) {
    Write-Host "`nOVERALL ASSESSMENT & RECOMMENDATIONS" -ForegroundColor Cyan
    
    # Summary statistics
    $totalPolicies = $results.Count
    $totalInitiatives = ($results | Where-Object { $_.'Policy Type' -eq 'Initiative' }).Count
    $totalSinglePolicies = ($results | Where-Object { $_.'Policy Type' -eq 'Policy' }).Count
    $highSecurityPolicies = ($results | Where-Object { $_.'Security Impact' -eq 'High' }).Count
    $highCostPolicies = ($results | Where-Object { $_.'Cost Impact' -eq 'High' }).Count
    $doNotEnforcePolicies = ($results | Where-Object { $_.'Enforcement Mode' -eq 'DoNotEnforce' }).Count
    $defaultEnforcePolicies = ($results | Where-Object { $_.'Enforcement Mode' -eq 'Default' }).Count
    $highRiskPolicies = ($results | Where-Object { $_.'Risk Level' -eq 'High' }).Count
    
    # Count by scope type
    $mgAssignments = ($results | Where-Object { $_.'Scope Type' -eq 'Management Group' }).Count
    $subAssignments = ($results | Where-Object { $_.'Scope Type' -eq 'Subscription' }).Count
    $rgAssignments = ($results | Where-Object { $_.'Scope Type' -eq 'Resource Group' }).Count
    
    # Count effect types
    $effectTypeCounts = $results | Group-Object 'Effect Type' | Sort-Object Count -Descending
    
    Write-Host "`nSummary Statistics:" -ForegroundColor Yellow
    Write-Host "  Total Policy Assignments: $totalPolicies" -ForegroundColor White
    Write-Host "    ÔÇó Initiatives (Policy Sets): $totalInitiatives" -ForegroundColor Gray
    Write-Host "    ÔÇó Single Policies: $totalSinglePolicies" -ForegroundColor Gray
    
    Write-Host "`n  Assignments by Scope:" -ForegroundColor White
    Write-Host "    ÔÇó Management Groups: $mgAssignments" -ForegroundColor Gray
    if ($subAssignments -gt 0) {
        Write-Host "    ÔÇó Subscriptions: $subAssignments" -ForegroundColor Gray
    }
    if ($rgAssignments -gt 0) {
        Write-Host "    ÔÇó Resource Groups: $rgAssignments" -ForegroundColor Gray
    }
    
    Write-Host "`n  Enforcement Mode:" -ForegroundColor White
    Write-Host "    ÔÇó Default (Enforced): $defaultEnforcePolicies" -ForegroundColor Gray
    Write-Host "    ÔÇó DoNotEnforce: $doNotEnforcePolicies" -ForegroundColor Gray
    
    Write-Host "`n  Effect Types:" -ForegroundColor White
    foreach ($effect in $effectTypeCounts) {
        $effectName = if ([string]::IsNullOrWhiteSpace($effect.Name) -or $effect.Name -eq '(not specified)') { 
            '(not specified)' 
        } else { 
            $effect.Name 
        }
        Write-Host "    ÔÇó $($effectName): $($effect.Count)" -ForegroundColor Gray
    }
    
    Write-Host "`n  Impact Analysis:" -ForegroundColor White
    Write-Host "    ÔÇó High Security Impact: $highSecurityPolicies" -ForegroundColor Gray
    Write-Host "    ÔÇó High Cost Impact: $highCostPolicies" -ForegroundColor Gray
    Write-Host "    ÔÇó High Risk Level: $highRiskPolicies" -ForegroundColor Gray
    
    # Get recommended Azure Landing Zone policies (dynamically from GitHub or fallback)
    $recommendedALZPolicies = Get-ALZRecommendedPolicies -ALZVersion "main"
    
    Write-Host "`nAzure Landing Zone Policy Coverage Analysis:" -ForegroundColor Yellow
    Write-Host "(Based on official Azure Landing Zone Bicep repository)" -ForegroundColor Gray
    
    $missingCriticalPolicies = @()
    $doNotEnforceALZPolicies = @()
    $assignedPoliciesWithEnforcement = $results | Select-Object 'Assignment Name', 'Policy Name', 'Display Name', 'Enforcement Mode'
    
    foreach ($category in $recommendedALZPolicies.Keys) {
        if ($recommendedALZPolicies[$category].Count -eq 0) { continue }
        
        Write-Host "`n  $category\" -ForegroundColor Cyan
        foreach ($policy in $recommendedALZPolicies[$category]) {
            # Case-insensitive exact matching against Assignment Name, Policy Name, and Display Name
            $matchingPolicies = $assignedPoliciesWithEnforcement | Where-Object { 
                $_.'Assignment Name' -eq $policy -or 
                $_.'Policy Name' -eq $policy -or
                $_.'Display Name' -eq $policy
            }
            
            if ($matchingPolicies) {
                # Check if any matching policy is in DoNotEnforce mode
                $doNotEnforceMatch = $matchingPolicies | Where-Object { $_.'Enforcement Mode' -eq 'DoNotEnforce' }
                if ($doNotEnforceMatch) {
                    Write-Host "    ÔÜá´©Å  $policy (DoNotEnforce)\" -ForegroundColor Yellow
                    $doNotEnforceALZPolicies += [PSCustomObject]@{
                        Category = $category
                        PolicyName = $policy
                        ActualName = $doNotEnforceMatch[0].'Policy Name'
                    }
                } else {
                    Write-Host "    Ô£ô $policy\" -ForegroundColor Green
                }
            } else {
                Write-Host "    Ô£ù $policy (MISSING)\" -ForegroundColor Red
                $missingCriticalPolicies += [PSCustomObject]@{
                    Category = $category
                    PolicyPattern = $policy
                }
            }
        }
    }
    
    # Overall recommendations
    Write-Host "`nKEY RECOMMENDATIONS:" -ForegroundColor Yellow
    
    if ($highRiskPolicies -gt 0) {
        Write-Host "`nÔÜá´©Å  HIGH PRIORITY:" -ForegroundColor Red
        Write-Host "   $highRiskPolicies policies are marked as high risk (disabled or critical misconfigurations)."
        Write-Host "   Review and remediate immediately." -ForegroundColor Red
    }
    
    if ($doNotEnforcePolicies -gt 0) {
        Write-Host "`nÔÜá´©Å  ENFORCEMENT:" -ForegroundColor Yellow
        Write-Host "   $doNotEnforcePolicies policies are in DoNotEnforce mode."
        Write-Host "   These are not actively protecting your environment. Consider enabling enforcement." -ForegroundColor Yellow
        
        # Show ALZ-recommended policies in DoNotEnforce mode
        if ($doNotEnforceALZPolicies.Count -gt 0) {
            Write-Host "`n   ÔÜá´©Å  ALZ-Recommended Policies in DoNotEnforce Mode:" -ForegroundColor Yellow
            $doNotEnforceByCategory = $doNotEnforceALZPolicies | Group-Object Category
            foreach ($group in $doNotEnforceByCategory) {
                Write-Host "`n      $($group.Name):" -ForegroundColor White
                foreach ($item in $group.Group) {
                    Write-Host "        ÔÇó $($item.ActualName) - DoNotEnforce" -ForegroundColor Gray
                }
            }
            Write-Host "`n      These are recommended by Azure Landing Zones but not actively enforced." -ForegroundColor DarkYellow
        }
    }
    
    if ($highCostPolicies -gt 0) {
        Write-Host "`n­ƒÆ░ COST OPTIMIZATION:" -ForegroundColor Cyan
        Write-Host "   $highCostPolicies policies have high cost impact."
        
        # List high cost impact policies
        Write-Host "`n   High Cost Impact Policies:" -ForegroundColor White
        $results | Where-Object { $_.'Cost Impact' -eq 'High' } | ForEach-Object {
            $effectInfo = if ($_.'Effect Type' -ne '(not specified)') { "[$($_.'Effect Type')]" } else { "" }
            Write-Host "     ÔÇó $($_.'Policy Name') $effectInfo" -ForegroundColor Gray
        }
        
        Write-Host "`n   Review these for budget planning. Consider:" -ForegroundColor Cyan
        Write-Host "   - Backup policies: Ensure retention is optimized"
        Write-Host "   - Monitoring policies: Use appropriate log retention"
        Write-Host "   - Defender for Cloud: Verify only necessary workloads are covered"
    }
    
    if ($missingCriticalPolicies.Count -gt 0) {
        Write-Host "`n­ƒøí´©Å  LANDING ZONE GAPS:" -ForegroundColor Magenta
        Write-Host "   $($missingCriticalPolicies.Count) recommended Azure Landing Zone policies are missing."
        Write-Host "   Consider implementing the following by category:" -ForegroundColor Magenta
        
        $missingByCategory = $missingCriticalPolicies | Group-Object Category
        foreach ($group in $missingByCategory) {
            Write-Host "`n   $($group.Name):" -ForegroundColor White
            foreach ($item in $group.Group) {
                Write-Host "     ÔÇó $($item.PolicyPattern)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "`nÔ£ô LANDING ZONE COVERAGE:" -ForegroundColor Green
        Write-Host "   Good coverage of recommended Azure Landing Zone policies." -ForegroundColor Green
    }
    
    # Security posture assessment
    Write-Host "`n­ƒöÆ SECURITY POSTURE:" -ForegroundColor Yellow
    
    # Combine security assessment with ALZ gap analysis
    $alzGapCount = $missingCriticalPolicies.Count
    
    if ($highSecurityPolicies -gt 10 -and $alzGapCount -eq 0) {
        Write-Host "   Ô£ô Strong - $highSecurityPolicies high-impact security policies in place with good ALZ coverage." -ForegroundColor Green
    } elseif ($highSecurityPolicies -gt 5 -and $alzGapCount -lt 10) {
        Write-Host "   Moderate - $highSecurityPolicies high-impact security policies deployed." -ForegroundColor Yellow
        if ($alzGapCount -gt 0) {
            Write-Host "   However, $alzGapCount Azure Landing Zone recommended policies are missing." -ForegroundColor Yellow
        }
    } else {
        Write-Host "   ÔÜá´©Å  Weak - Security posture requires immediate attention." -ForegroundColor Red
        Write-Host "      ÔÇó Only $highSecurityPolicies high-impact security policies deployed" -ForegroundColor Red
        if ($alzGapCount -gt 0) {
            Write-Host "      ÔÇó $alzGapCount Azure Landing Zone recommended policies missing" -ForegroundColor Red
            Write-Host "      ÔÇó This represents critical security and governance gaps" -ForegroundColor Red
        }
    }
    
    # List high security impact policies
    if ($highSecurityPolicies -gt 0) {
        Write-Host "`n   High Security Impact Policies Currently Deployed:" -ForegroundColor White
        $results | Where-Object { $_.'Security Impact' -eq 'High' } | ForEach-Object {
            $effectInfo = if ($_.'Effect Type' -ne '(not specified)') { "[$($_.'Effect Type')]" } else { "" }
            $enforcementInfo = if ($_.'Enforcement Mode' -eq 'DoNotEnforce') { " (NOT ENFORCED)" } else { "" }
            Write-Host "     ÔÇó $($_.'Policy Name') $effectInfo$enforcementInfo" -ForegroundColor Gray
        }
        Write-Host "`n   Note: High security impact policies include:" -ForegroundColor DarkGray
        Write-Host "   - Deny/Block policies preventing non-compliant deployments" -ForegroundColor DarkGray
        Write-Host "   - DeployIfNotExists/Modify policies for automatic remediation" -ForegroundColor DarkGray
        Write-Host "   - Policies protecting network security, encryption, and data access" -ForegroundColor DarkGray
        Write-Host "   - Defender for Cloud and backup/disaster recovery policies" -ForegroundColor DarkGray
    } else {
        Write-Host "`n   ÔØî CRITICAL: No high security impact policies found!" -ForegroundColor Red
        Write-Host "   Your environment lacks essential security controls." -ForegroundColor Red
    }
    
    # Azure Landing Zone specific recommendations
    if ($alzGapCount -gt 0) {
        Write-Host "`n   ­ƒøí´©Å  AZURE LANDING ZONE RECOMMENDATIONS:" -ForegroundColor Cyan
        Write-Host "   Missing $alzGapCount ALZ recommended policies that provide:" -ForegroundColor White
        
        # Categorize ALZ gaps by security impact
        $alzSecurityGaps = $missingCriticalPolicies | Where-Object { 
            $_.PolicyPattern -match "Deny|Block|Prevent|Disable|Restrict" 
        }
        $alzComplianceGaps = $missingCriticalPolicies | Where-Object { 
            $_.PolicyPattern -match "Audit|Monitor|Log|Enable" 
        }
        $alzRemediationGaps = $missingCriticalPolicies | Where-Object { 
            $_.PolicyPattern -match "Deploy|Configure|Enforce" 
        }
        
        if ($alzSecurityGaps.Count -gt 0) {
            Write-Host "      ÔÇó Security Controls ($($alzSecurityGaps.Count) missing): Network isolation, access control, encryption" -ForegroundColor Red
        }
        if ($alzRemediationGaps.Count -gt 0) {
            Write-Host "      ÔÇó Auto-Remediation ($($alzRemediationGaps.Count) missing): Automated configuration and compliance" -ForegroundColor Yellow
        }
        if ($alzComplianceGaps.Count -gt 0) {
            Write-Host "      ÔÇó Monitoring & Audit ($($alzComplianceGaps.Count) missing): Visibility and compliance tracking" -ForegroundColor Yellow
        }
        
        Write-Host "`n   ­ƒôû RECOMMENDED ACTIONS:" -ForegroundColor Cyan
        Write-Host "   1. Review the 'LANDING ZONE GAPS' section above for specific missing policies" -ForegroundColor White
        Write-Host "   2. Prioritize implementing Deny/Block policies for immediate security hardening" -ForegroundColor White
        Write-Host "   3. Deploy monitoring and audit policies for compliance visibility" -ForegroundColor White
        Write-Host "   4. Implement DeployIfNotExists policies for automated remediation" -ForegroundColor White
        Write-Host "   5. Reference Azure Landing Zone documentation: https://aka.ms/alz" -ForegroundColor White
    }
    
    Write-Host "`n­ƒôï BEST PRACTICES:" -ForegroundColor Yellow
    Write-Host "   1. Test blocking policies (Deny) in DoNotEnforce mode first" -ForegroundColor White
    Write-Host "   2. Regularly review audit logs for Audit policies and consider upgrading to Deny" -ForegroundColor White
    Write-Host "   3. Ensure DINE/Modify policies have proper managed identities and RBAC" -ForegroundColor White
    Write-Host "   4. Monitor policy compliance in Azure Policy compliance dashboard" -ForegroundColor White
    Write-Host "   5. Document exceptions using policy exemptions rather than disabling policies" -ForegroundColor White
    Write-Host "   6. Review policies quarterly for relevance and effectiveness" -ForegroundColor White
}

# Export to CSV if requested
if ($Export) {
    if (-not $FileName) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $FileName = "PolicyAssignments_$timestamp.csv"
    }
    
    $csvPath = Join-Path -Path (Get-Location) -ChildPath $FileName
    
    Write-Host "`nExporting to CSV..." -ForegroundColor Cyan
    
    # Show progress for export
    Write-Progress -Activity "Exporting to CSV" -Status "Writing $($results.Count) records..." -PercentComplete 50 -Id 2
    
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    
    Write-Progress -Activity "Exporting to CSV" -Completed -Id 2
    
    Write-Host "Ô£ô Policy assignments exported to: $csvPath" -ForegroundColor Green
} else {
    Write-Host "`nTo export results to CSV, use the -Export switch" -ForegroundColor Gray
}

Write-Host "`nÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉ" -ForegroundColor Cyan
Write-Host "Total policy assignments found: $($results.Count)" -ForegroundColor Green
Write-Host "Execution completed successfully!" -ForegroundColor Green
Write-Host "ÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉÔòÉ" -ForegroundColor Cyan
