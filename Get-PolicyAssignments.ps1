<#
.SYNOPSIS
    Lists all Azure Policy assignments from all management groups with detailed information and regulatory compliance assessment.

.DESCRIPTION
    This script retrieves all Azure Policy assignments from all management groups in the tenant
    and displays them in a table format showing the policy name, type (Initiative or Policy), 
    effect type, enforcement mode, scope type (Management Group, Subscription, or Resource Group), 
    scope name, and policy definition name. Optionally provides recommendations on impact analysis.
    
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
    Version: 2.0.1
    Last Updated: February 5, 2026
    Author: Azure Policy Assessment Tool
    
    Requires Azure PowerShell modules: Az.Accounts, Az.Resources, Az.PolicyInsights
    Requires appropriate Azure RBAC permissions (typically Management Group Reader)
    For compliance data, policies must be assigned and evaluated (may take time for new assignments)
    
    Version History:
    - 2.0.1 (2026-02-05): Enhanced summary statistics with detailed breakdowns:
                          - Policy type counts (Initiatives vs Single Policies)
                          - Assignments by scope (MG, Subscriptions, RG)
                          - Effect types distribution
                          - Enforcement mode statistics
    - 2.0.0 (2026-02-05): Enhanced with subscription/RG enumeration, multi-tenant support,
                          accurate compliance data using PolicyAssignmentName filter,
                          progress bars, and improved ALZ recommendations
    - 1.0.0 (Initial): Azure Landing Zone policy assessment with ALZ Library integration
                       Impact analysis and gap detection
                       CSV export functionality
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
$ScriptVersion = "2.0.1"
$ScriptLastUpdated = "2026-02-05"

# Display version banner
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Azure Policy & Compliance Assessment Tool" -ForegroundColor Cyan
Write-Host "  Version: $ScriptVersion | Last Updated: $ScriptLastUpdated" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

# Requires Azure PowerShell module
# Install-Module -Name Az.Resources -Force -AllowClobber

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
    
    $recommendation = [PSCustomObject]@{
        SecurityImpact = "Medium"
        CostImpact = "Low"
        ComplianceImpact = "Medium"
        OperationalOverhead = "Low"
        Recommendation = ""
        RiskLevel = "Low"
    }
    
    # Analyze by effect type
    switch -Regex ($EffectType) {
        "Deny" {
            $recommendation.SecurityImpact = "High"
            $recommendation.ComplianceImpact = "High"
            $recommendation.RiskLevel = "Medium"
            $recommendation.Recommendation = "Blocking policy - prevents non-compliant resources. May block legitimate deployments. Test thoroughly in DoNotEnforce mode first."
        }
        "Audit|AuditIfNotExists" {
            $recommendation.SecurityImpact = "Low"
            $recommendation.CostImpact = "Low"
            $recommendation.ComplianceImpact = "Medium"
            $recommendation.Recommendation = "Non-blocking policy - good for visibility and compliance reporting. Consider upgrading to Deny/Deploy for enforcement."
        }
        "DeployIfNotExists|Modify" {
            $recommendation.SecurityImpact = "High"
            $recommendation.CostImpact = "Medium"
            $recommendation.OperationalOverhead = "Medium"
            $recommendation.ComplianceImpact = "High"
            $recommendation.Recommendation = "Remediates non-compliant resources automatically. May incur additional costs. Requires managed identity and proper permissions."
        }
        "Disabled" {
            $recommendation.SecurityImpact = "None"
            $recommendation.CostImpact = "None"
            $recommendation.ComplianceImpact = "None"
            $recommendation.RiskLevel = "High"
            $recommendation.Recommendation = "Policy is disabled. Consider removing if not needed or re-enabling if required for compliance."
        }
    }
    
    # Adjust for enforcement mode
    if ($EnforcementMode -eq "DoNotEnforce") {
        $recommendation.SecurityImpact = "None"
        $recommendation.ComplianceImpact = "Low"
        $recommendation.Recommendation += " Currently in DoNotEnforce mode - policy not actively enforced."
    }
    
    # Analyze by policy name patterns
    switch -Regex ($PolicyName) {
        "Deny.*Public|Block.*Internet|Deny.*External" {
            $recommendation.SecurityImpact = "High"
            $recommendation.Recommendation += " Network security policy - critical for preventing unauthorized access."
        }
        "Deploy.*Monitoring|Deploy.*Log|Deploy.*Diagnostic" {
            $recommendation.CostImpact = "Medium"
            $recommendation.OperationalOverhead = "Medium"
            $recommendation.Recommendation += " Monitoring policy - will create additional resources (Log Analytics, storage). Budget accordingly."
        }
        "Backup|ASR|Disaster" {
            $recommendation.CostImpact = "High"
            $recommendation.SecurityImpact = "High"
            $recommendation.Recommendation += " Business continuity policy - significant cost impact but critical for data protection."
        }
        "Encryption|TLS|SSL" {
            $recommendation.SecurityImpact = "High"
            $recommendation.ComplianceImpact = "High"
            $recommendation.Recommendation += " Data protection policy - essential for compliance (PCI-DSS, HIPAA, etc.)."
        }
        "Tag|Naming" {
            $recommendation.CostImpact = "Low"
            $recommendation.OperationalOverhead = "Low"
            $recommendation.Recommendation += " Governance policy - helps with cost allocation and resource organization."
        }
        "MDFC|Security.*Center|Defender" {
            $recommendation.CostImpact = "High"
            $recommendation.SecurityImpact = "High"
            $recommendation.Recommendation += " Microsoft Defender for Cloud policy - requires paid tier. Review pricing."
        }
    }
    
    return $recommendation
}

#endregion Function Definitions


Write-Host "`nRetrieving all management groups..." -ForegroundColor Cyan

# Get current tenant context to enforce tenant boundary
$currentContext = Get-AzContext
if (-not $currentContext) {
    Write-Host "`n❌ ERROR: Not connected to Azure. Run 'Connect-AzAccount' first." -ForegroundColor Red
    return
}

$currentTenantId = $currentContext.Tenant.Id
Write-Host "Current Tenant ID: $currentTenantId" -ForegroundColor Gray
Write-Host "Subscription in context: $($currentContext.Subscription.Name) ($($currentContext.Subscription.Id))" -ForegroundColor Gray
Write-Host "" # Blank line

# Get all management groups recursively (including children)
$allManagementGroups = @()
try {
    $rootMgs = Get-AzManagementGroup -ErrorAction Stop
}
catch {
    Write-Host "`n❌ ERROR: Unable to retrieve management groups." -ForegroundColor Red
    Write-Host "   Reason: $($_.Exception.Message)" -ForegroundColor Yellow
    
    if ($_.Exception.Message -like "*Authorization*" -or $_.Exception.Message -like "*permission*" -or $_.Exception.Message -like "*forbidden*" -or $_.Exception.Message -like "*denied*") {
        Write-Host "`n   PERMISSION ISSUE DETECTED:" -ForegroundColor Cyan
        Write-Host "   - You need 'Reader' access or higher on management groups" -ForegroundColor Gray
        Write-Host "   - Typically requires 'Management Group Reader' role at tenant root level" -ForegroundColor Gray
        Write-Host "   - Contact your Azure administrator to grant appropriate access" -ForegroundColor Gray
    }
    
    Write-Host "`n   Run 'Connect-AzAccount' if you're not authenticated." -ForegroundColor Gray
    return
}

if (-not $rootMgs) {
    Write-Host "`n❌ No management groups found." -ForegroundColor Red
    Write-Host "   - Ensure you have appropriate permissions" -ForegroundColor Yellow
    Write-Host "   - This script is designed for Azure Landing Zone management group structures" -ForegroundColor Yellow
    return
}

foreach ($rootMg in $rootMgs) {
    # Get the management group with expanded children
    try {
        $mgWithChildren = Get-AzManagementGroup -GroupId $rootMg.Name -Expand -Recurse -ErrorAction Stop
    }
    catch {
        Write-Host "⚠️  Warning: Cannot expand management group '$($rootMg.DisplayName)' - $($_.Exception.Message)" -ForegroundColor Yellow
        continue
    }
    
    # Add root MG
    $allManagementGroups += $mgWithChildren
    
    # Recursively add all child management groups
    function Get-ChildManagementGroups($mg) {
        if ($mg.Children) {
            foreach ($child in $mg.Children) {
                if ($child.Type -eq '/providers/Microsoft.Management/managementGroups') {
                    $childMg = Get-AzManagementGroup -GroupId $child.Name -Expand -Recurse
                    $script:allManagementGroups += $childMg
                    Get-ChildManagementGroups $childMg
                }
            }
        }
    }
    Get-ChildManagementGroups $mgWithChildren
}

Write-Host "Found $($allManagementGroups.Count) management group(s):" -ForegroundColor Cyan
Write-Host "(This script is optimized for Azure Landing Zone structures)" -ForegroundColor DarkGray
foreach ($mg in $allManagementGroups) {
    Write-Host "  - $($mg.DisplayName) ($($mg.Name))" -ForegroundColor Gray
}

# Create array to store results
$results = @()

Write-Host "`nRetrieving policy assignments for each management group..." -ForegroundColor Cyan

# Process each management group
$mgCount = 0
$totalMgs = $allManagementGroups.Count

foreach ($mg in $allManagementGroups) {
    $mgCount++
    $percentComplete = [math]::Round(($mgCount / $totalMgs) * 100, 2)
    Write-Progress -Activity "Processing Policy Assignments" -Status "Management Group: $($mg.DisplayName) ($mgCount of $totalMgs)" -PercentComplete $percentComplete -Id 1
    
    Write-Host "`n  Processing MG: $($mg.DisplayName) ($($mg.Name))" -ForegroundColor Yellow
    
    # Get policy assignments directly assigned to this management group (not inherited)
    try {
        $mgAssignments = Get-AzPolicyAssignment -Scope "/providers/Microsoft.Management/managementGroups/$($mg.Name)" -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -like "*Authorization*" -or $_.Exception.Message -like "*permission*" -or $_.Exception.Message -like "*forbidden*") {
            Write-Host "    ⚠️  Access Denied: Insufficient permissions to read policies on this management group" -ForegroundColor Yellow
        }
        else {
            Write-Host "    ⚠️  Error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        continue
    }
    
    if ($mgAssignments) {
        Write-Host "    Total assignments found (including inherited): $($mgAssignments.Count)" -ForegroundColor DarkGray
        
        $directAssignments = 0
        foreach ($assignment in $mgAssignments) {
            # Only include assignments where the Scope matches this exact management group (not inherited from parent)
            if ($assignment.Scope -eq "/providers/Microsoft.Management/managementGroups/$($mg.Name)") {
                $directAssignments++
                Write-Host "      ✓ Direct: $($assignment.Name)" -ForegroundColor Green
                
                # Determine policy type based on PolicyDefinitionId
                $policyType = if ($assignment.PolicyDefinitionId -match '/policySetDefinitions/') {
                    "Initiative"
                } else {
                    "Policy"
                }
                
                # Extract policy definition name from PolicyDefinitionId
                $policyDefId = $assignment.PolicyDefinitionId
                $policyDefName = if ($policyDefId -match '/([^/]+)$') {
                    $Matches[1]
                } else {
                    $policyDefId
                }
                
                # Get enforcement mode
                $enforcementMode = "Default"
                if ($assignment.PSObject.Properties['EnforcementMode']) {
                    $enforcementMode = $assignment.EnforcementMode
                } elseif ($assignment.PSObject.Properties['Properties'] -and $assignment.Properties.PSObject.Properties['EnforcementMode']) {
                    $enforcementMode = $assignment.Properties.EnforcementMode
                }
                
                # Get effect from parameters (common parameter name)
                $effectType = "(not specified)"
                if ($assignment.PSObject.Properties['Parameter'] -and $assignment.Parameter) {
                    if ($assignment.Parameter.PSObject.Properties['effect']) {
                        $effectType = $assignment.Parameter.effect.value
                    }
                }
                
                # If effect not in parameters and it's a single policy, try to get it from the policy definition
                if ($effectType -eq "(not specified)" -and $policyType -eq "Policy") {
                    try {
                        $policyDef = Get-AzPolicyDefinition -Id $assignment.PolicyDefinitionId -ErrorAction SilentlyContinue
                        if ($policyDef -and $policyDef.PSObject.Properties['Properties'] -and $policyDef.Properties.PSObject.Properties['policyRule']) {
                            if ($policyDef.Properties.policyRule.PSObject.Properties['then'] -and $policyDef.Properties.policyRule.then.PSObject.Properties['effect']) {
                                $effectType = $policyDef.Properties.policyRule.then.effect
                            }
                        }
                    } catch {
                        # Ignore errors when unable to retrieve policy definition
                    }
                }
                
                # Extract parameters
                $parametersString = ""
                if ($assignment.PSObject.Properties['Parameter'] -and $assignment.Parameter) {
                    $paramList = @()
                    $assignment.Parameter.PSObject.Properties | ForEach-Object {
                        $paramName = $_.Name
                        $paramValue = $_.Value.value
                        
                        # Format the value based on type
                        if ($paramValue -is [array]) {
                            $paramValue = '["' + ($paramValue -join '","') + '"]'
                        } elseif ($paramValue -is [hashtable] -or $paramValue -is [PSCustomObject]) {
                            $paramValue = ($paramValue | ConvertTo-Json -Compress -Depth 10)
                        } elseif ($null -eq $paramValue) {
                            $paramValue = "(null)"
                        } else {
                            $paramValue = $paramValue.ToString()
                        }
                        
                        $paramList += "$paramName=$paramValue"
                    }
                    if ($paramList.Count -gt 0) {
                        $parametersString = $paramList -join '; '
                    }
                }
                
                if ([string]::IsNullOrEmpty($parametersString)) {
                    $parametersString = "(no parameters)"
                }
                
                # Get recommendations
                $recommendationObj = Get-PolicyRecommendation -PolicyName $policyDefName -EffectType $effectType -EnforcementMode $enforcementMode -PolicyType $policyType
                
                # Create custom object first (to ensure all policies are captured)
                $policyResult = [PSCustomObject]@{
                    'Assignment Name'     = $assignment.Name
                    'Display Name'        = $assignment.DisplayName
                    'Policy Type'         = $policyType
                    'Effect Type'         = $effectType
                    'Enforcement Mode'    = $enforcementMode
                    'Non-Compliant Resources' = 0
                    'Non-Compliant Policies' = 0
                    'Security Impact'     = $recommendationObj.SecurityImpact
                    'Cost Impact'         = $recommendationObj.CostImpact
                    'Compliance Impact'   = $recommendationObj.ComplianceImpact
                    'Operational Overhead'= $recommendationObj.OperationalOverhead
                    'Risk Level'          = $recommendationObj.RiskLevel
                    'Scope Type'          = "Management Group"
                    'Scope Name'          = $mg.DisplayName
                    'Management Group ID' = $mg.Name
                    'Policy Name'         = $policyDefName
                    'Parameters'          = $parametersString
                    'Recommendation'      = $recommendationObj.Recommendation
                    'Scope'               = $assignment.Scope
                }
                
                # Add to results immediately
                $results += $policyResult
                
                # Now try to fetch compliance data using the assignment name directly
                try {
                    $isMgScope = $assignment.Scope -like "*/managementGroups/*"
                    $mgNameForQuery = if ($isMgScope) { $assignment.Scope -replace '.*/managementGroups/', '' } else { $null }
                    $defId = $assignment.PolicyDefinitionId
                    $assignmentName = $assignment.Name
                    
                    # Use PolicyAssignmentName filter which is more reliable than PolicyDefinitionId
                    $filterQuery = "PolicyAssignmentName eq '$assignmentName'"
                    
                    $summary = $null
                    if ($filterQuery) {
                        if ($isMgScope) {
                            $summary = Get-AzPolicyStateSummary -ManagementGroupName $mgNameForQuery -Filter $filterQuery -ErrorAction SilentlyContinue
                        } else {
                            $subIdForQuery = if ($assignment.Scope -match '/subscriptions/([^/]+)') { $matches[1] } else { (Get-AzContext).Subscription.Id }
                            $summary = Get-AzPolicyStateSummary -SubscriptionId $subIdForQuery -Filter $filterQuery -ErrorAction SilentlyContinue
                        }
                    }

                    if ($summary -and $summary.Results) {
                        # Get non-compliant resources count
                        $policyResult.'Non-Compliant Resources' = if ($summary.Results.PSObject.Properties['NonCompliantResources']) {
                            $summary.Results.NonCompliantResources
                        } else { 0 }
                        
                        # Get non-compliant policies count (for Initiatives only)
                        if ($defId -like "*policySetDefinitions*") {
                            # For Initiatives, get the count of individual policies that are non-compliant
                            try {
                                $policyStates = if ($isMgScope) {
                                    Get-AzPolicyState -ManagementGroupName $mgNameForQuery -Filter $filterQuery -ErrorAction SilentlyContinue
                                } else {
                                    $subIdForQuery = if ($assignment.Scope -match '/subscriptions/([^/]+)') { $matches[1] } else { (Get-AzContext).Subscription.Id }
                                    Get-AzPolicyState -SubscriptionId $subIdForQuery -Filter $filterQuery -ErrorAction SilentlyContinue
                                }
                                
                                if ($policyStates) {
                                    # Count unique non-compliant policy definition IDs
                                    $nonCompliantPolicies = $policyStates | 
                                        Where-Object { $_.ComplianceState -eq 'NonCompliant' } | 
                                        Select-Object -ExpandProperty PolicyDefinitionId -Unique
                                    $policyResult.'Non-Compliant Policies' = ($nonCompliantPolicies | Measure-Object).Count
                                } else {
                                    $policyResult.'Non-Compliant Policies' = 0
                                }
                            } catch {
                                # Fallback to summary if available
                                $policyResult.'Non-Compliant Policies' = if ($summary.Results.PSObject.Properties['NonCompliantPolicies']) {
                                    $summary.Results.NonCompliantPolicies
                                } else { 0 }
                            }
                        } else {
                            # For single policies, non-compliant policies is always 0 or 1
                            $policyResult.'Non-Compliant Policies' = if ($policyResult.'Non-Compliant Resources' -gt 0) { 1 } else { 0 }
                        }
                    }
                } catch {
                    # Silently continue - compliance data is optional
                }
            } else {
                Write-Host "      - Inherited: $($assignment.Name) (from $($assignment.Scope))" -ForegroundColor DarkGray
            }
        }
        Write-Host "    Direct assignments: $directAssignments" -ForegroundColor Cyan
    } else {
        Write-Host "    No assignments found" -ForegroundColor DarkGray
    }
}

Write-Progress -Activity "Processing Policy Assignments" -Completed -Id 1
Write-Host "`nProcessing Management Groups complete!" -ForegroundColor Cyan

# Enumerate Subscription-level assignments if requested
if ($IncludeSubscriptions) {
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  SUBSCRIPTION-LEVEL POLICY ASSIGNMENTS" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    # Get subscriptions only from the current tenant
    $allSubs = Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $_.TenantId -eq $currentTenantId }
    
    if (-not $allSubs) {
        Write-Host "No subscriptions found in the current tenant ($currentTenantId)" -ForegroundColor Yellow
    } else {
        Write-Host "Found $($allSubs.Count) subscription(s) in current tenant" -ForegroundColor Gray
    }
    
    $subCount = 0
    $totalSubs = ($allSubs | Measure-Object).Count
    
    foreach ($sub in $allSubs) {
        $subCount++
        $percentComplete = [math]::Round(($subCount / $totalSubs) * 100, 2)
        Write-Progress -Activity "Processing Subscription Assignments" -Status "Subscription: $($sub.Name) ($subCount of $totalSubs)" -PercentComplete $percentComplete -Id 2
        
        Write-Host "Processing Subscription: $($sub.Name) ($($sub.Id))" -ForegroundColor Yellow
        
        try {
            Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
            
            $subScope = "/subscriptions/$($sub.Id)"
            $subAssignments = Get-AzPolicyAssignment -Scope $subScope -ErrorAction SilentlyContinue
            
            $directSubAssignments = 0
            
            if ($subAssignments) {
                foreach ($assignment in $subAssignments) {
                    # Only include direct assignments to this subscription
                    if ($assignment.Scope -eq $subScope) {
                        $directSubAssignments++
                        Write-Host "  ✓ Direct: $($assignment.Name)" -ForegroundColor Green
                        
                        # Determine policy type
                        $policyType = if ($assignment.PolicyDefinitionId -match '/policySetDefinitions/') {
                            "Initiative"
                        } else {
                            "Policy"
                        }
                        
                        # Extract policy definition name
                        $policyDefId = $assignment.PolicyDefinitionId
                        $policyDefName = if ($policyDefId -match '/([^/]+)$') {
                            $Matches[1]
                        } else {
                            $policyDefId
                        }
                        
                        # Get enforcement mode
                        $enforcementMode = "Default"
                        if ($assignment.PSObject.Properties['EnforcementMode']) {
                            $enforcementMode = $assignment.EnforcementMode
                        } elseif ($assignment.PSObject.Properties['Properties'] -and $assignment.Properties.PSObject.Properties['EnforcementMode']) {
                            $enforcementMode = $assignment.Properties.EnforcementMode
                        }
                        
                        # Get effect type
                        $effectType = "(not specified)"
                        if ($assignment.PSObject.Properties['Parameter'] -and $assignment.Parameter) {
                            if ($assignment.Parameter.PSObject.Properties['effect']) {
                                $effectType = $assignment.Parameter.effect.value
                            }
                        }
                        
                        # Extract parameters
                        $parametersString = "(no parameters)"
                        if ($assignment.PSObject.Properties['Parameter'] -and $assignment.Parameter) {
                            $paramList = @()
                            $assignment.Parameter.PSObject.Properties | ForEach-Object {
                                $paramName = $_.Name
                                $paramValue = $_.Value.value
                                if ($paramValue -is [array]) {
                                    $paramValue = '["' + ($paramValue -join '","') + '"]'
                                } elseif ($null -eq $paramValue) {
                                    $paramValue = "(null)"
                                } else {
                                    $paramValue = $paramValue.ToString()
                                }
                                $paramList += "$paramName=$paramValue"
                            }
                            if ($paramList.Count -gt 0) {
                                $parametersString = $paramList -join '; '
                            }
                        }
                        
                        # Get recommendations
                        $recommendationObj = Get-PolicyRecommendation -PolicyName $policyDefName -EffectType $effectType -EnforcementMode $enforcementMode -PolicyType $policyType
                        
                        # Create policy result object
                        $policyResult = [PSCustomObject]@{
                            'Assignment Name'          = $assignment.Name
                            'Display Name'             = $assignment.DisplayName
                            'Policy Type'              = $policyType
                            'Effect Type'              = $effectType
                            'Enforcement Mode'         = $enforcementMode
                            'Non-Compliant Resources'  = 0
                            'Non-Compliant Policies'   = 0
                            'Security Impact'          = $recommendationObj.SecurityImpact
                            'Cost Impact'              = $recommendationObj.CostImpact
                            'Compliance Impact'        = $recommendationObj.ComplianceImpact
                            'Operational Overhead'     = $recommendationObj.OperationalOverhead
                            'Risk Level'               = $recommendationObj.RiskLevel
                            'Scope Type'               = "Subscription"
                            'Scope Name'               = $sub.Name
                            'Management Group ID'      = $sub.Id
                            'Policy Name'              = $policyDefName
                            'Parameters'               = $parametersString
                            'Recommendation'           = $recommendationObj.Recommendation
                            'Scope'                    = $assignment.Scope
                        }
                        
                        $results += $policyResult
                        
                        # Fetch compliance data for subscription assignment
                        try {
                            $defId = $assignment.PolicyDefinitionId
                            $assignmentName = $assignment.Name
                            
                            # Use PolicyAssignmentName filter which is more reliable
                            $filterQuery = "PolicyAssignmentName eq '$assignmentName'"
                            
                            if ($filterQuery) {
                                $summary = Get-AzPolicyStateSummary -SubscriptionId $sub.Id -Filter $filterQuery -ErrorAction SilentlyContinue
                                
                                if ($summary -and $summary.Results) {
                                    # Get non-compliant resources count
                                    $policyResult.'Non-Compliant Resources' = if ($summary.Results.PSObject.Properties['NonCompliantResources']) {
                                        $summary.Results.NonCompliantResources
                                    } else { 0 }
                                    
                                    # Get non-compliant policies count (for Initiatives only)
                                    if ($defId -like "*policySetDefinitions*") {
                                        # For Initiatives, get the count of individual policies that are non-compliant
                                        try {
                                            $policyStates = Get-AzPolicyState -SubscriptionId $sub.Id -Filter $filterQuery -ErrorAction SilentlyContinue
                                            
                                            if ($policyStates) {
                                                # Count unique non-compliant policy definition IDs
                                                $nonCompliantPolicies = $policyStates | 
                                                    Where-Object { $_.ComplianceState -eq 'NonCompliant' } | 
                                                    Select-Object -ExpandProperty PolicyDefinitionId -Unique
                                                $policyResult.'Non-Compliant Policies' = ($nonCompliantPolicies | Measure-Object).Count
                                            } else {
                                                $policyResult.'Non-Compliant Policies' = 0
                                            }
                                        } catch {
                                            # Fallback to summary if available
                                            $policyResult.'Non-Compliant Policies' = if ($summary.Results.PSObject.Properties['NonCompliantPolicies']) {
                                                $summary.Results.NonCompliantPolicies
                                            } else { 0 }
                                        }
                                    } else {
                                        # For single policies, non-compliant policies is always 0 or 1
                                        $policyResult.'Non-Compliant Policies' = if ($policyResult.'Non-Compliant Resources' -gt 0) { 1 } else { 0 }
                                    }
                                }
                            }
                        } catch {
                            # Silently continue - compliance data is optional
                        }
                    }
                }
            }
            
            Write-Host "  Direct assignments: $directSubAssignments" -ForegroundColor Cyan
        }
        catch {
            Write-Host "  ⚠️ Error accessing subscription: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    Write-Progress -Activity "Processing Subscription Assignments" -Completed -Id 2
}

# Enumerate Resource Group-level assignments if requested
if ($IncludeResourceGroups -and $IncludeSubscriptions) {
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  RESOURCE GROUP-LEVEL POLICY ASSIGNMENTS" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    # Get subscriptions only from the current tenant
    $allSubs = Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $_.TenantId -eq $currentTenantId }
    
    if (-not $allSubs) {
        Write-Host "No subscriptions found in the current tenant ($currentTenantId)" -ForegroundColor Yellow
    } else {
        Write-Host "Found $($allSubs.Count) subscription(s) in current tenant" -ForegroundColor Gray
    }
    
    $rgSubCount = 0
    $totalRgSubs = ($allSubs | Measure-Object).Count
    
    foreach ($sub in $allSubs) {
        $rgSubCount++
        Write-Progress -Activity "Processing Resource Group Assignments" -Status "Subscription: $($sub.Name) ($rgSubCount of $totalRgSubs)" -PercentComplete ([math]::Round(($rgSubCount / $totalRgSubs) * 100, 2)) -Id 3
        
        try {
            Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
            
            $resourceGroups = Get-AzResourceGroup -ErrorAction SilentlyContinue
            
            if ($resourceGroups) {
                foreach ($rg in $resourceGroups) {
                    $rgScope = "/subscriptions/$($sub.Id)/resourceGroups/$($rg.ResourceGroupName)"
                    $rgAssignments = Get-AzPolicyAssignment -Scope $rgScope -ErrorAction SilentlyContinue
                    
                    $directRgAssignments = 0
                    
                    if ($rgAssignments) {
                        foreach ($assignment in $rgAssignments) {
                            # Only include direct assignments to this RG
                            if ($assignment.Scope -eq $rgScope) {
                                if ($directRgAssignments -eq 0) {
                                    Write-Host "Subscription: $($sub.Name) / RG: $($rg.ResourceGroupName)" -ForegroundColor Yellow
                                }
                                
                                $directRgAssignments++
                                Write-Host "  ✓ Direct: $($assignment.Name)" -ForegroundColor Green
                                
                                # Determine policy type
                                $policyType = if ($assignment.PolicyDefinitionId -match '/policySetDefinitions/') {
                                    "Initiative"
                                } else {
                                    "Policy"
                                }
                                
                                # Extract policy definition name
                                $policyDefId = $assignment.PolicyDefinitionId
                                $policyDefName = if ($policyDefId -match '/([^/]+)$') {
                                    $Matches[1]
                                } else {
                                    $policyDefId
                                }
                                
                                # Get enforcement mode
                                $enforcementMode = "Default"
                                if ($assignment.PSObject.Properties['EnforcementMode']) {
                                    $enforcementMode = $assignment.EnforcementMode
                                } elseif ($assignment.PSObject.Properties['Properties'] -and $assignment.Properties.PSObject.Properties['EnforcementMode']) {
                                    $enforcementMode = $assignment.Properties.EnforcementMode
                                }
                                
                                # Get effect type
                                $effectType = "(not specified)"
                                if ($assignment.PSObject.Properties['Parameter'] -and $assignment.Parameter) {
                                    if ($assignment.Parameter.PSObject.Properties['effect']) {
                                        $effectType = $assignment.Parameter.effect.value
                                    }
                                }
                                
                                # Extract parameters
                                $parametersString = "(no parameters)"
                                if ($assignment.PSObject.Properties['Parameter'] -and $assignment.Parameter) {
                                    $paramList = @()
                                    $assignment.Parameter.PSObject.Properties | ForEach-Object {
                                        $paramName = $_.Name
                                        $paramValue = $_.Value.value
                                        if ($paramValue -is [array]) {
                                            $paramValue = '["' + ($paramValue -join '","') + '"]'
                                        } elseif ($null -eq $paramValue) {
                                            $paramValue = "(null)"
                                        } else {
                                            $paramValue = $paramValue.ToString()
                                        }
                                        $paramList += "$paramName=$paramValue"
                                    }
                                    if ($paramList.Count -gt 0) {
                                        $parametersString = $paramList -join '; '
                                    }
                                }
                                
                                # Get recommendations
                                $recommendationObj = Get-PolicyRecommendation -PolicyName $policyDefName -EffectType $effectType -EnforcementMode $enforcementMode -PolicyType $policyType
                                
                                # Create policy result object
                                $policyResult = [PSCustomObject]@{
                                    'Assignment Name'          = $assignment.Name
                                    'Display Name'             = $assignment.DisplayName
                                    'Policy Type'              = $policyType
                                    'Effect Type'              = $effectType
                                    'Enforcement Mode'         = $enforcementMode
                                    'Non-Compliant Resources'  = 0
                                    'Non-Compliant Policies'   = 0
                                    'Security Impact'          = $recommendationObj.SecurityImpact
                                    'Cost Impact'              = $recommendationObj.CostImpact
                                    'Compliance Impact'        = $recommendationObj.ComplianceImpact
                                    'Operational Overhead'     = $recommendationObj.OperationalOverhead
                                    'Risk Level'               = $recommendationObj.RiskLevel
                                    'Scope Type'               = "Resource Group"
                                    'Scope Name'               = $rg.ResourceGroupName
                                    'Management Group ID'      = $sub.Name
                                    'Policy Name'              = $policyDefName
                                    'Parameters'               = $parametersString
                                    'Recommendation'           = $recommendationObj.Recommendation
                                    'Scope'                    = $assignment.Scope
                                }
                                
                                $results += $policyResult
                                
                                # Fetch compliance data for RG assignment
                                try {
                                    $defId = $assignment.PolicyDefinitionId
                                    $assignmentName = $assignment.Name
                                    
                                    # Use PolicyAssignmentName filter which is more reliable
                                    $filterQuery = "PolicyAssignmentName eq '$assignmentName'"
                                    
                                    if ($filterQuery) {
                                        $summary = Get-AzPolicyStateSummary -SubscriptionId $sub.Id -Filter $filterQuery -ErrorAction SilentlyContinue
                                        
                                        if ($summary -and $summary.Results) {
                                            # Get non-compliant resources count
                                            $policyResult.'Non-Compliant Resources' = if ($summary.Results.PSObject.Properties['NonCompliantResources']) {
                                                $summary.Results.NonCompliantResources
                                            } else { 0 }
                                            
                                            # Get non-compliant policies count (for Initiatives only)
                                            if ($defId -like "*policySetDefinitions*") {
                                                # For Initiatives, get the count of individual policies that are non-compliant
                                                try {
                                                    $policyStates = Get-AzPolicyState -SubscriptionId $sub.Id -Filter $filterQuery -ErrorAction SilentlyContinue
                                                    
                                                    if ($policyStates) {
                                                        # Count unique non-compliant policy definition IDs
                                                        $nonCompliantPolicies = $policyStates | 
                                                            Where-Object { $_.ComplianceState -eq 'NonCompliant' } | 
                                                            Select-Object -ExpandProperty PolicyDefinitionId -Unique
                                                        $policyResult.'Non-Compliant Policies' = ($nonCompliantPolicies | Measure-Object).Count
                                                    } else {
                                                        $policyResult.'Non-Compliant Policies' = 0
                                                    }
                                                } catch {
                                                    # Fallback to summary if available
                                                    $policyResult.'Non-Compliant Policies' = if ($summary.Results.PSObject.Properties['NonCompliantPolicies']) {
                                                        $summary.Results.NonCompliantPolicies
                                                    } else { 0 }
                                                }
                                            } else {
                                                # For single policies, non-compliant policies is always 0 or 1
                                                $policyResult.'Non-Compliant Policies' = if ($policyResult.'Non-Compliant Resources' -gt 0) { 1 } else { 0 }
                                            }
                                        }
                                    }
                                } catch {
                                    # Silently continue - compliance data is optional
                                }
                            }
                        }
                        
                        if ($directRgAssignments -gt 0) {
                            Write-Host "  Direct assignments: $directRgAssignments" -ForegroundColor Cyan
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "  ⚠️ Error accessing subscription for RG enumeration: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    Write-Progress -Activity "Processing Resource Group Assignments" -Completed -Id 3
}

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
    Write-Host "    • Initiatives (Policy Sets): $totalInitiatives" -ForegroundColor Gray
    Write-Host "    • Single Policies: $totalSinglePolicies" -ForegroundColor Gray
    
    Write-Host "`n  Assignments by Scope:" -ForegroundColor White
    Write-Host "    • Management Groups: $mgAssignments" -ForegroundColor Gray
    if ($subAssignments -gt 0) {
        Write-Host "    • Subscriptions: $subAssignments" -ForegroundColor Gray
    }
    if ($rgAssignments -gt 0) {
        Write-Host "    • Resource Groups: $rgAssignments" -ForegroundColor Gray
    }
    
    Write-Host "`n  Enforcement Mode:" -ForegroundColor White
    Write-Host "    • Default (Enforced): $defaultEnforcePolicies" -ForegroundColor Gray
    Write-Host "    • DoNotEnforce: $doNotEnforcePolicies" -ForegroundColor Gray
    
    Write-Host "`n  Effect Types:" -ForegroundColor White
    foreach ($effect in $effectTypeCounts) {
        $effectName = if ([string]::IsNullOrWhiteSpace($effect.Name) -or $effect.Name -eq '(not specified)') { 
            '(not specified)' 
        } else { 
            $effect.Name 
        }
        Write-Host "    • $($effectName): $($effect.Count)" -ForegroundColor Gray
    }
    
    Write-Host "`n  Impact Analysis:" -ForegroundColor White
    Write-Host "    • High Security Impact: $highSecurityPolicies" -ForegroundColor Gray
    Write-Host "    • High Cost Impact: $highCostPolicies" -ForegroundColor Gray
    Write-Host "    • High Risk Level: $highRiskPolicies" -ForegroundColor Gray
    
    # Get recommended Azure Landing Zone policies (dynamically from GitHub or fallback)
    $recommendedALZPolicies = Get-ALZRecommendedPolicies -ALZVersion "main"
    
    Write-Host "`nAzure Landing Zone Policy Coverage Analysis:" -ForegroundColor Yellow
    Write-Host "(Based on official Azure Landing Zone Bicep repository)" -ForegroundColor Gray
    
    $missingCriticalPolicies = @()
    $doNotEnforceALZPolicies = @()
    $assignedPoliciesWithEnforcement = $results | Select-Object 'Assignment Name', 'Policy Name', 'Display Name', 'Enforcement Mode'
    
    foreach ($category in $recommendedALZPolicies.Keys) {
        if ($recommendedALZPolicies[$category].Count -eq 0) { continue }
        
        Write-Host "`n  $category" -ForegroundColor Cyan
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
                    Write-Host "    ⚠️  $policy (DoNotEnforce)" -ForegroundColor Yellow
                    $doNotEnforceALZPolicies += [PSCustomObject]@{
                        Category = $category
                        PolicyName = $policy
                        ActualName = $doNotEnforceMatch[0].'Policy Name'
                    }
                } else {
                    Write-Host "    ✓ $policy" -ForegroundColor Green
                }
            } else {
                Write-Host "    ✗ $policy (MISSING)" -ForegroundColor Red
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
        Write-Host "`n⚠️  HIGH PRIORITY:" -ForegroundColor Red
        Write-Host "   $highRiskPolicies policies are marked as high risk (disabled or critical misconfigurations)."
        Write-Host "   Review and remediate immediately." -ForegroundColor Red
    }
    
    if ($doNotEnforcePolicies -gt 0) {
        Write-Host "`n⚠️  ENFORCEMENT:" -ForegroundColor Yellow
        Write-Host "   $doNotEnforcePolicies policies are in DoNotEnforce mode."
        Write-Host "   These are not actively protecting your environment. Consider enabling enforcement." -ForegroundColor Yellow
        
        # Show ALZ-recommended policies in DoNotEnforce mode
        if ($doNotEnforceALZPolicies.Count -gt 0) {
            Write-Host "`n   ⚠️  ALZ-Recommended Policies in DoNotEnforce Mode:" -ForegroundColor Yellow
            $doNotEnforceByCategory = $doNotEnforceALZPolicies | Group-Object Category
            foreach ($group in $doNotEnforceByCategory) {
                Write-Host "`n      $($group.Name):" -ForegroundColor White
                foreach ($item in $group.Group) {
                    Write-Host "        • $($item.ActualName) - DoNotEnforce" -ForegroundColor Gray
                }
            }
            Write-Host "`n      These are recommended by Azure Landing Zones but not actively enforced." -ForegroundColor DarkYellow
        }
    }
    
    if ($highCostPolicies -gt 0) {
        Write-Host "`n💰 COST OPTIMIZATION:" -ForegroundColor Cyan
        Write-Host "   $highCostPolicies policies have high cost impact."
        
        # List high cost impact policies
        Write-Host "`n   High Cost Impact Policies:" -ForegroundColor White
        $results | Where-Object { $_.'Cost Impact' -eq 'High' } | ForEach-Object {
            $effectInfo = if ($_.'Effect Type' -ne '(not specified)') { "[$($_.'Effect Type')]" } else { "" }
            Write-Host "     • $($_.'Policy Name') $effectInfo" -ForegroundColor Gray
        }
        
        Write-Host "`n   Review these for budget planning. Consider:" -ForegroundColor Cyan
        Write-Host "   - Backup policies: Ensure retention is optimized"
        Write-Host "   - Monitoring policies: Use appropriate log retention"
        Write-Host "   - Defender for Cloud: Verify only necessary workloads are covered"
    }
    
    if ($missingCriticalPolicies.Count -gt 0) {
        Write-Host "`n🛡️  LANDING ZONE GAPS:" -ForegroundColor Magenta
        Write-Host "   $($missingCriticalPolicies.Count) recommended Azure Landing Zone policies are missing."
        Write-Host "   Consider implementing the following by category:" -ForegroundColor Magenta
        
        $missingByCategory = $missingCriticalPolicies | Group-Object Category
        foreach ($group in $missingByCategory) {
            Write-Host "`n   $($group.Name):" -ForegroundColor White
            foreach ($item in $group.Group) {
                Write-Host "     • $($item.PolicyPattern)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "`n✓ LANDING ZONE COVERAGE:" -ForegroundColor Green
        Write-Host "   Good coverage of recommended Azure Landing Zone policies." -ForegroundColor Green
    }
    
    # Security posture assessment
    Write-Host "`n🔒 SECURITY POSTURE:" -ForegroundColor Yellow
    
    # Combine security assessment with ALZ gap analysis
    $alzGapCount = $missingCriticalPolicies.Count
    $totalSecurityGaps = $alzGapCount
    
    if ($highSecurityPolicies -gt 10 -and $alzGapCount -eq 0) {
        Write-Host "   ✓ Strong - $highSecurityPolicies high-impact security policies in place with good ALZ coverage." -ForegroundColor Green
    } elseif ($highSecurityPolicies -gt 5 -and $alzGapCount -lt 10) {
        Write-Host "   Moderate - $highSecurityPolicies high-impact security policies deployed." -ForegroundColor Yellow
        if ($alzGapCount -gt 0) {
            Write-Host "   However, $alzGapCount Azure Landing Zone recommended policies are missing." -ForegroundColor Yellow
        }
    } else {
        Write-Host "   ⚠️  Weak - Security posture requires immediate attention." -ForegroundColor Red
        Write-Host "      • Only $highSecurityPolicies high-impact security policies deployed" -ForegroundColor Red
        if ($alzGapCount -gt 0) {
            Write-Host "      • $alzGapCount Azure Landing Zone recommended policies missing" -ForegroundColor Red
            Write-Host "      • This represents critical security and governance gaps" -ForegroundColor Red
        }
    }
    
    # List high security impact policies
    if ($highSecurityPolicies -gt 0) {
        Write-Host "`n   High Security Impact Policies Currently Deployed:" -ForegroundColor White
        $results | Where-Object { $_.'Security Impact' -eq 'High' } | ForEach-Object {
            $effectInfo = if ($_.'Effect Type' -ne '(not specified)') { "[$($_.'Effect Type')]" } else { "" }
            $enforcementInfo = if ($_.'Enforcement Mode' -eq 'DoNotEnforce') { " (NOT ENFORCED)" } else { "" }
            Write-Host "     • $($_.'Policy Name') $effectInfo$enforcementInfo" -ForegroundColor Gray
        }
        Write-Host "`n   Note: High security impact policies include:" -ForegroundColor DarkGray
        Write-Host "   - Deny/Block policies preventing non-compliant deployments" -ForegroundColor DarkGray
        Write-Host "   - DeployIfNotExists/Modify policies for automatic remediation" -ForegroundColor DarkGray
        Write-Host "   - Policies protecting network security, encryption, and data access" -ForegroundColor DarkGray
        Write-Host "   - Defender for Cloud and backup/disaster recovery policies" -ForegroundColor DarkGray
    } else {
        Write-Host "`n   ❌ CRITICAL: No high security impact policies found!" -ForegroundColor Red
        Write-Host "   Your environment lacks essential security controls." -ForegroundColor Red
    }
    
    # Azure Landing Zone specific recommendations
    if ($alzGapCount -gt 0) {
        Write-Host "`n   🛡️  AZURE LANDING ZONE RECOMMENDATIONS:" -ForegroundColor Cyan
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
            Write-Host "      • Security Controls ($($alzSecurityGaps.Count) missing): Network isolation, access control, encryption" -ForegroundColor Red
        }
        if ($alzRemediationGaps.Count -gt 0) {
            Write-Host "      • Auto-Remediation ($($alzRemediationGaps.Count) missing): Automated configuration and compliance" -ForegroundColor Yellow
        }
        if ($alzComplianceGaps.Count -gt 0) {
            Write-Host "      • Monitoring & Audit ($($alzComplianceGaps.Count) missing): Visibility and compliance tracking" -ForegroundColor Yellow
        }
        
        Write-Host "`n   📖 RECOMMENDED ACTIONS:" -ForegroundColor Cyan
        Write-Host "   1. Review the 'LANDING ZONE GAPS' section above for specific missing policies" -ForegroundColor White
        Write-Host "   2. Prioritize implementing Deny/Block policies for immediate security hardening" -ForegroundColor White
        Write-Host "   3. Deploy monitoring and audit policies for compliance visibility" -ForegroundColor White
        Write-Host "   4. Implement DeployIfNotExists policies for automated remediation" -ForegroundColor White
        Write-Host "   5. Reference Azure Landing Zone documentation: https://aka.ms/alz" -ForegroundColor White
    } else {
        Write-Host "`n   ✓ Azure Landing Zone coverage is complete" -ForegroundColor Green
    }
    
    # Best practices
    Write-Host "`n📋 BEST PRACTICES:" -ForegroundColor Yellow
    Write-Host "   1. Test blocking policies (Deny) in DoNotEnforce mode first"
    Write-Host "   2. Regularly review audit logs for Audit policies and consider upgrading to Deny"
    Write-Host "   3. Ensure DINE/Modify policies have proper managed identities and RBAC"
    Write-Host "   4. Monitor policy compliance in Azure Policy compliance dashboard"
    Write-Host "   5. Document exceptions using policy exemptions rather than disabling policies"
    Write-Host "   6. Review policies quarterly for relevance and effectiveness"
    
    # Compliance recommendations if frameworks were checked
    if ($complianceResults.Count -gt 0) {
        Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  REGULATORY COMPLIANCE RECOMMENDATIONS" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        
        $notAssigned = $complianceResults | Where-Object { $_.Status -eq 'Not Assigned' }
        $lowCompliance = $complianceResults | Where-Object { 
            $_.ComplianceScore -ne 'N/A' -and $_.ComplianceScore -ne 'null' -and 
            [double]($_.ComplianceScore -replace '%', '') -lt 80 
        }
        
        if ($notAssigned.Count -gt 0) {
            Write-Host "`n🔴 CRITICAL - Missing Compliance Frameworks:" -ForegroundColor Red
            foreach ($framework in $notAssigned) {
                Write-Host "   • $($framework.Framework) - Not assigned to any scope" -ForegroundColor Yellow
            }
            Write-Host "`n   Action Required: Assign these frameworks to appropriate management groups/subscriptions" -ForegroundColor Red
            Write-Host "   Use: Get-AzPolicySetDefinition | Where-Object { `$_.DisplayName -like '*PCI*' }" -ForegroundColor Gray
        }
        
        if ($lowCompliance.Count -gt 0) {
            Write-Host "`n🟡 WARNING - Low Compliance Scores:" -ForegroundColor Yellow
            foreach ($framework in $lowCompliance) {
                Write-Host "   • $($framework.Framework): $($framework.ComplianceScore) compliance" -ForegroundColor Yellow
                Write-Host "     - $($framework.NonCompliantResources) non-compliant resources require remediation" -ForegroundColor Gray
            }
            Write-Host "`n   Action Required: Review non-compliant resources and create remediation tasks" -ForegroundColor Yellow
            Write-Host "   Use: Get-AzPolicyState -Filter \"ComplianceState eq 'NonCompliant'\"" -ForegroundColor Gray
        }
        
        $assigned = $complianceResults | Where-Object { 
            $_.Status -notlike 'Not Assigned' -and $_.Status -notlike 'Error' 
        }
        if ($assigned.Count -gt 0) {
            Write-Host "`n✓ ACTIVE COMPLIANCE FRAMEWORKS:" -ForegroundColor Green
            foreach ($framework in $assigned) {
                $scoreColor = 'White'
                if ($framework.ComplianceScore -ne 'N/A') {
                    $score = [double]($framework.ComplianceScore -replace '%', '')
                    $scoreColor = if ($score -ge 90) { 'Green' } elseif ($score -ge 70) { 'Yellow' } else { 'Red' }
                }
                Write-Host "   • $($framework.Framework): " -NoNewline -ForegroundColor White
                Write-Host "$($framework.ComplianceScore)" -ForegroundColor $scoreColor
            }
        }
        
        Write-Host "`n💡 COMPLIANCE TIPS:" -ForegroundColor Cyan
        Write-Host "   • Enable Azure Policy compliance dashboard in Azure Portal" -ForegroundColor Gray
        Write-Host "   • Set up alerts for compliance score drops" -ForegroundColor Gray
        Write-Host "   • Create remediation tasks for DeployIfNotExists policies" -ForegroundColor Gray
        Write-Host "   • Document policy exemptions with business justification" -ForegroundColor Gray
        Write-Host "   • Schedule quarterly compliance reviews" -ForegroundColor Gray
    }
}

# Export to CSV if requested
if ($Export) {
    if ($FileName) {
        # Use custom filename
        $csvPath = $FileName
        # Ensure .csv extension
        if (-not $csvPath.EndsWith('.csv', [StringComparison]::OrdinalIgnoreCase)) {
            $csvPath += '.csv'
        }
    } else {
        # Use default timestamped filename
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = ".\PolicyAssignments_$timestamp.csv"
    }
    
    Write-Host "`nExporting policy assignments to CSV..." -ForegroundColor Cyan
    
    # Export with progress bar
    $totalItems = $results.Count
    $currentItem = 0
    $exportData = @()
    
    foreach ($item in $results) {
        $currentItem++
        $percentComplete = [math]::Round(($currentItem / $totalItems) * 100, 2)
        Write-Progress -Activity "Exporting Policy Assignments" -Status "Processing item $currentItem of $totalItems" -PercentComplete $percentComplete
        $exportData += $item
    }
    
    Write-Progress -Activity "Exporting Policy Assignments" -Status "Writing to file..." -PercentComplete 99
    $exportData | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Progress -Activity "Exporting Policy Assignments" -Completed
    
    Write-Host "Policy assignments exported to: $csvPath" -ForegroundColor Green
} else {
    Write-Host "`nNo export requested. Use -Export switch to save results to CSV." -ForegroundColor Gray
}

Write-Host "`nTotal policy assignments found: $($results.Count)" -ForegroundColor Green
