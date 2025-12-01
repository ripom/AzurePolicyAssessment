<#
.SYNOPSIS
    Lists all Azure Policy assignments from all management groups with detailed information.

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

.EXAMPLE
    .\Get-PolicyAssignments.ps1
    
.EXAMPLE
    .\Get-PolicyAssignments.ps1 -ShowRecommendations

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -Export

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -Export -FileName "MyPolicyReport.csv"

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -ShowRecommendations -Export -FileName "PolicyAudit_$(Get-Date -Format 'yyyy-MM').csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$ShowRecommendations,
    
    [Parameter(Mandatory=$false)]
    [switch]$Export,
    
    [Parameter(Mandatory=$false)]
    [string]$FileName
)

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

Write-Host "`nRetrieving all management groups..." -ForegroundColor Cyan

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

# Get all management groups recursively (including children)
$allManagementGroups = @()
$rootMgs = Get-AzManagementGroup

foreach ($rootMg in $rootMgs) {
    # Get the management group with expanded children
    $mgWithChildren = Get-AzManagementGroup -GroupId $rootMg.Name -Expand -Recurse
    
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
foreach ($mg in $allManagementGroups) {
    Write-Host "  - $($mg.DisplayName) ($($mg.Name))" -ForegroundColor Gray
}

# Create array to store results
$results = @()

Write-Host "`nRetrieving policy assignments for each management group..." -ForegroundColor Cyan

# Process each management group
foreach ($mg in $allManagementGroups) {
    Write-Host "`n  Processing MG: $($mg.DisplayName) ($($mg.Name))" -ForegroundColor Yellow
    
    # Get policy assignments directly assigned to this management group (not inherited)
    $mgAssignments = Get-AzPolicyAssignment -Scope "/providers/Microsoft.Management/managementGroups/$($mg.Name)" -ErrorAction SilentlyContinue
    
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
                
                # Create custom object
                $results += [PSCustomObject]@{
                    'Assignment Name'     = $assignment.Name
                    'Display Name'        = $assignment.DisplayName
                    'Policy Type'         = $policyType
                    'Effect Type'         = $effectType
                    'Enforcement Mode'    = $enforcementMode
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
            } else {
                Write-Host "      - Inherited: $($assignment.Name) (from $($assignment.Scope))" -ForegroundColor DarkGray
            }
        }
        Write-Host "    Direct assignments: $directAssignments" -ForegroundColor Cyan
    } else {
        Write-Host "    No assignments found" -ForegroundColor DarkGray
    }
}

Write-Host "`nProcessing complete!" -ForegroundColor Cyan

# Display results in table format
Write-Host "`nPolicy Assignments by Management Group:" -ForegroundColor Cyan
$results | Format-Table -AutoSize

# Generate overall recommendations if switch is enabled
if ($ShowRecommendations) {
    Write-Host "`nOVERALL ASSESSMENT & RECOMMENDATIONS" -ForegroundColor Cyan
    
    # Summary statistics
    $totalPolicies = $results.Count
    $highSecurityPolicies = ($results | Where-Object { $_.'Security Impact' -eq 'High' }).Count
    $highCostPolicies = ($results | Where-Object { $_.'Cost Impact' -eq 'High' }).Count
    $doNotEnforcePolicies = ($results | Where-Object { $_.'Enforcement Mode' -eq 'DoNotEnforce' }).Count
    $highRiskPolicies = ($results | Where-Object { $_.'Risk Level' -eq 'High' }).Count
    
    Write-Host "`nSummary Statistics:" -ForegroundColor Yellow
    Write-Host "  Total Policy Assignments: $totalPolicies"
    Write-Host "  High Security Impact: $highSecurityPolicies"
    Write-Host "  High Cost Impact: $highCostPolicies"
    Write-Host "  DoNotEnforce Mode: $doNotEnforcePolicies"
    Write-Host "  High Risk Level: $highRiskPolicies"
    
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
    if ($highSecurityPolicies -gt 10) {
        Write-Host "   Strong - $highSecurityPolicies high-impact security policies in place." -ForegroundColor Green
    } elseif ($highSecurityPolicies -gt 5) {
        Write-Host "   Moderate - $highSecurityPolicies high-impact security policies. Consider adding more." -ForegroundColor Yellow
    } else {
        Write-Host "   Weak - Only $highSecurityPolicies high-impact security policies. Requires attention." -ForegroundColor Red
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
        Write-Host "`n   ⚠️  No high security impact policies found!" -ForegroundColor Red
        Write-Host "   Your environment lacks critical security controls." -ForegroundColor Red
        Write-Host "   Consider implementing ALZ recommended policies from the gaps listed above." -ForegroundColor Yellow
    }
    
    # Best practices
    Write-Host "`n📋 BEST PRACTICES:" -ForegroundColor Yellow
    Write-Host "   1. Test blocking policies (Deny) in DoNotEnforce mode first"
    Write-Host "   2. Regularly review audit logs for Audit policies and consider upgrading to Deny"
    Write-Host "   3. Ensure DINE/Modify policies have proper managed identities and RBAC"
    Write-Host "   4. Monitor policy compliance in Azure Policy compliance dashboard"
    Write-Host "   5. Document exceptions using policy exemptions rather than disabling policies"
    Write-Host "   6. Review policies quarterly for relevance and effectiveness"
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
    
    $results | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "`nResults exported to: $csvPath" -ForegroundColor Green
} else {
    Write-Host "`nNo export requested. Use -Export switch to save results to CSV." -ForegroundColor Gray
}

Write-Host "`nTotal policy assignments found: $($results.Count)" -ForegroundColor Green
