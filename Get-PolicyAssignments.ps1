#Requires -Version 7.0

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

.PARAMETER ManagementGroup
    Filter the assessment to a specific Management Group by name or ID.
    Only policy assignments scoped to this MG (and its children) will be included.
    When not specified, all Management Groups in the tenant are assessed.
    Example: -ManagementGroup "Contoso-Root" or -ManagementGroup "mg-platform"

.PARAMETER Subscription
    Filter the assessment to a specific Subscription by name or ID.
    Only policy assignments scoped to this subscription (and its resource groups) will be included.
    When not specified, all subscriptions are assessed.
    Example: -Subscription "Production" or -Subscription "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.PARAMETER Output
    Controls which export outputs are generated. Accepts one or more comma-separated values.
    Values: CSV, HTML, NC, YAML, All
      CSV  — Export policy assignments to timestamped CSV file
      HTML — Generate comprehensive 7-section interactive HTML report
      NC   — Export all non-compliant resources to CSV
      YAML — Export full assessment database to YAML (offline analysis & delta)
      All  — All of the above
    Replaces the old -Export / -ExportHTML / -ExportNonCompliant switches.
    Example: -Output HTML,NC

.PARAMETER CEP
    Controls Cyber Essentials (CE/CE+) compliance features.
    Values: Show, Test, Export, Full
      Show   — Display CE v3.1 compliance analysis in console
      Test   — Run CE+ v3.2 Test Specification (TC1-TC5) — implies Show
      Export — Export CE compliance data to CSV — implies Show
      Full   — All of the above (Show + Test + Export)
    ⚠️ EXPERIMENTAL FEATURE.
    Based on: https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf

.PARAMETER TenantId
    Optional tenant ID to use for the assessment. When specified, skips the tenant selection prompt.
    Useful for automation scenarios or when working with a specific tenant.

.PARAMETER FileName
    Custom filename for the CSV export. If not provided, uses default timestamped format:
    PolicyAssignments_YYYYMMDD_HHMMSS.csv. Only used when -Output CSV is specified.

.PARAMETER QuickAssess
    When specified, produces a concise one-page Quick Assessment output showing only the top KPIs,
    top 5 enforcement gaps, top 5 non-compliant assignments, and key recommendations.
    Ideal for executives and busy engineers who want a fast overview without a full report.

.PARAMETER DeltaYAML
    Path to a previous YAML database file for detailed delta comparison.
    When specified, the script loads the previous snapshot and shows a comprehensive
    policy-by-policy comparison: new/removed assignments, compliance changes, effect
    changes, enforcement mode changes, and trend analysis.
    Requires a YAML file previously generated with -Output YAML.
    Example: -DeltaYAML ".\PolicyAssessment_20260218_141257.yaml"

.PARAMETER Full
    Runs a comprehensive assessment with all features enabled: recommendations,
    CE/CE+ compliance with tests, HTML report, CSV export, non-compliant resources,
    and YAML database.
    Equivalent to: -Output All -CEP Full

.PARAMETER Update
    Checks if a newer version of the script is available on GitHub and, if found,
    downloads it, verifies it has no parse errors, creates a backup of the current
    version, then replaces the local script file. The script exits after the update
    so you can re-run with the new version.
    Use: .\Get-PolicyAssignments.ps1 -Update

.PARAMETER CostEvidence
    Optional official monetary evidence. Accepts Off, RetailPrices, CostManagement, or All.
    RetailPrices requires -CostRegion and at least one -CostServiceName. CostManagement
    queries actual cost for the resolved subscription. Monetary values are omitted when
    source provenance is incomplete.

.PARAMETER CostRegion
    Azure ARM region used to filter Retail Prices API records, for example westeurope.

.PARAMETER CostCurrency
    ISO 4217 currency requested from the Retail Prices API. Default: USD.

.PARAMETER CostServiceName
    One or more exact Azure Retail Prices API service names. The script does not infer
    billable SKUs or services from policy names.

.EXAMPLE
    .\Get-PolicyAssignments.ps1
    Lists all policy assignments across all scopes (tenant-wide).

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -ManagementGroup "mg-platform"
    Assess only the "mg-platform" management group hierarchy.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -Subscription "Production"
    Assess only the "Production" subscription.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -Output CSV
    Exports policy assignments to CSV (all scopes).

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -Output HTML,NC
    Generates HTML report + non-compliant resource export.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -Output CSV -FileName "MyPolicyReport.csv"
    Exports to a custom-named CSV file.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -CEP Test
    Runs Cyber Essentials compliance analysis with CE+ v3.2 test cases (TC1-TC5).

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -CEP Full -Output HTML
    Full CE/CE+ analysis with HTML report.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -Subscription "Prod-Sub"
    Automated assessment of a specific tenant, filtered to one subscription.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -Full
    Runs a comprehensive assessment with all features enabled:
    CE/CE+ compliance, test results, HTML report, CSV, and NC export.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -QuickAssess
    Produces a one-page Quick Assessment: posture verdict, top 5 gaps,
    top 5 non-compliant assignments, category breakdown, and key actions.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -Output YAML
    Exports full assessment database to a timestamped YAML file for offline analysis.

.EXAMPLE
    .\Get-PolicyAssignments.ps1 -Output YAML -DeltaYAML ".\PolicyAssessment_20260217_120428.yaml"
    Exports YAML database and shows detailed delta against a previous assessment.

.NOTES
    Version: 4.0.0
    Last Updated: July 17, 2026
    Author: Riccardo Pomato
    
    Requires PowerShell 7.0 or later (Windows PowerShell 5.1 is not supported)
    Requires Azure PowerShell modules: Az.Accounts, Az.Resources, Az.ResourceGraph
    Requires appropriate Azure RBAC permissions (typically Management Group Reader)
    For compliance data, policies must be assigned and evaluated (may take time for new assignments)
    Performance: Uses Azure Resource Graph for fast queries (10-50x faster than traditional enumeration)
    
    CE/CE+ Reference Documentation:
    - NCSC CE+ v3.2 Test Specification : https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf
    - Azure CE+ Compliance Offering    : https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus
    
    Version History:
    - 4.0.0 (2026-07-17): Deterministic-only reporting and audience architecture redesign.
                          • Removed the generative AI integration and credential requirements.
                          • Unified Overview and Executive into an outcome-led Summary.
                          • Added five direct audience pages with explicit content ownership.
                          • Added measured compliance and Landing Zone results to Summary.
                          • Reworked responsive disclosure, KPI, finding, and action presentation.
    - 3.2.0 (2026-07-15): Deterministic assessment and official-source refresh.
                          • Findings, recommendations, and reports are generated from collected evidence and rules.
                          • No external generative-analysis service or model credentials are required.
                          • Versioned ALZ release assets with definition-ID matching.
                          • Framework initiatives discovered from official Azure metadata.
                          • CE+ percentage is a tool indicator, not a certification threshold.
                          • DINE non-compliance requires remediation verification.
    - 3.1.1 (2026-02-20): Bug fix — YAML/HTML/console numeric fields now handle "N/A" values
                          gracefully instead of failing with Int32 conversion errors.
    - 3.1.0 (2026-02-20): CE+ multi-assignment awareness — auto-detects initiative assigned at
                          multiple scopes, strictest-state-wins deduplication, per-scope compliance
                          breakdown in HTML/console/YAML, per-scope control group bars, per-scope
                          policy detail and test summary cards inside collapsible scope cards.
    - 3.0.2 (2026-02-19): Update mechanism — VERSION.json uses history array exclusively;
                          update banner and -Update flow show cumulative per-version changes.
                          Display — simplified update banner and success box to horizontal lines.
    - 3.0.1 (2026-02-19): Performance optimisation — replaced O(n²) array += with List<T>.Add().
    - 3.0.0 (2026-02-19): Major release — see WHATS-NEW-v3.0.md for full details.
                          • Automatic update check: fetches VERSION.json from GitHub at startup
                            to detect newer releases and show highlights (non-blocking, 5s timeout).
                          • Policy exemptions: queries all exemptions from ARG, integrated into
                            HTML report and YAML database, delta comparison tracks changes.
                          • YAML database export (-Output YAML) and delta comparison (-DeltaYAML).
                          • Azure Landing Zone Analysis section in HTML report (section 6) with
                            ALZ coverage metrics, category breakdown, missing policies, audit-only detail.
                          • HTML report now has 8 base sections (+ optional Delta Assessment).
                          • Disclaimer updated: project made and maintained by Riccardo Pomato.
                          • Scope handling: all scopes included by default; new -ManagementGroup
                            and -Subscription filters replace -IncludeSubscriptions/-IncludeResourceGroups.
                          • Simplified command interface: -Output (CSV,HTML,NC,All) and
                            -CEP (Show|Test|Export|Full) replace legacy switches.
                          • Accuracy overhaul: real policy definition metadata via batch ARG query
                            replaces heuristic name-regex classifications.
                          • Initiative effect resolution: shows actual member-policy effects.
                          • New -QuickAssess for concise one-page summary.
                          • CE+ v3.1 initiative-based compliance replaces static policy mapping.
                          • CE+ v3.2 Test Specification (TC1-TC5) with MANUAL status type.
                          • Simplified HTML report with tightened sections.
    - 2.2.1 (2026-02-06): Added #Requires -Version 7.0 directive to enforce PowerShell 7+ requirement
    - 2.1.0 (2026-02-05): Major performance enhancement using Azure Resource Graph (ARG)
    - 2.0.1 (2026-02-05): Enhanced summary statistics with detailed breakdowns
    - 2.0.0 (2026-02-05): Enhanced with subscription/RG enumeration, multi-tenant support
    - 1.0.0 (Initial): Azure Landing Zone policy assessment with ALZ Library integration
#>

[CmdletBinding()]
param(
    # ── Primary parameters (simplified interface) ──
    [Parameter(Mandatory=$false)]
    [ValidateSet('CSV', 'HTML', 'NC', 'YAML', 'All')]
    [string[]]$Output,

    [Parameter(Mandatory=$false)]
    [ValidateSet('Show', 'Test', 'Export', 'Full')]
    [string]$CEP,

    [Parameter(Mandatory=$false)]
    [string]$CEPDefinitionId = '',

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$CEPDefinitionVersion = '3.1',

    [Parameter(Mandatory=$false)]
    [string]$ManagementGroup,

    [Parameter(Mandatory=$false)]
    [string]$Subscription,

    [Parameter(Mandatory=$false)]
    [string]$FileName,

    [Parameter(Mandatory=$false)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [switch]$Full,

    [Parameter(Mandatory=$false)]
    [switch]$QuickAssess,

    [Parameter(Mandatory=$false)]
    [switch]$Update,

    [Parameter(Mandatory=$false)]
    [string]$DeltaYAML,

    [Parameter(Mandatory=$false)]
    [ValidateSet('Off', 'RetailPrices', 'CostManagement', 'All')]
    [string]$CostEvidence = 'Off',

    [Parameter(Mandatory=$false)]
    [string]$CostRegion = '',

    [Parameter(Mandatory=$false)]
    [ValidatePattern('^[A-Za-z]{3}$')]
    [string]$CostCurrency = 'USD',

    [Parameter(Mandatory=$false)]
    [string[]]$CostServiceName = @(),

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 365)]
    [int]$CostLookbackDays = 30,

    # ── Legacy output switches (backward compatibility — hidden from tab-completion) ──
    [Parameter(Mandatory=$false, DontShow)]
    [switch]$Export,

    [Parameter(Mandatory=$false, DontShow)]
    [switch]$ExportNonCompliant,

    [Parameter(Mandatory=$false, DontShow)]
    [switch]$ExportHTML
)

# Script Version
$ScriptVersion = "4.0.0"
$ScriptLastUpdated = "2026-07-15"

# ═══════════════════════════════════════════════════════════════════════════
# Update check: fetches VERSION.json from GitHub to detect newer releases
# ═══════════════════════════════════════════════════════════════════════════
$script:VersionCheckUrl = "https://raw.githubusercontent.com/ripom/AzurePolicyAssessment/main/VERSION.json"

function Test-ScriptUpdate {
    <#
    .SYNOPSIS
        Checks the GitHub repository for a newer version of the script.
    .DESCRIPTION
        Fetches VERSION.json from the repo, compares with the running $ScriptVersion,
        and returns a hashtable with update info. Non-blocking — returns $null on any error.
    #>
    try {
        $response = Invoke-RestMethod -Uri $script:VersionCheckUrl `
            -Headers @{ 'User-Agent' = 'PowerShell-AzurePolicyAssessment'; 'Accept' = 'application/json' } `
            -Method Get -TimeoutSec 5 -ErrorAction Stop

        $remoteVersion  = [version]$response.version
        $currentVersion = [version]$ScriptVersion

        if ($remoteVersion -gt $currentVersion) {
            # Collect history entries newer than the running version
            $newEntries = @()
            if ($response.history) {
                $newEntries = @($response.history | Where-Object {
                    [version]$_.version -gt $currentVersion
                } | Sort-Object { [version]$_.version } -Descending)
            }

            return @{
                CurrentVersion  = $ScriptVersion
                LatestVersion   = $response.version
                ReleaseDate     = $response.releaseDate
                History         = $newEntries
                ReleaseNotesUrl = $response.releaseNotesUrl
                ScriptUrl       = $response.scriptUrl
            }
        }
        return $null   # up to date
    }
    catch {
        # Silently ignore — network errors, offline, rate-limited, etc.
        return $null
    }
}

function Show-UpdateNotification {
    <#
    .SYNOPSIS
        Displays a prominent update banner if a newer version is available,
        listing all changes since the user's current version grouped by release.
    #>
    param([hashtable]$UpdateInfo)
    if (-not $UpdateInfo) { return }

    $line = '════════════════════════════════════════════════════════════════════════════'
    $thin = '────────────────────────────────────────────────────────────────────────────'

    Write-Host ""
    Write-Host "  $line" -ForegroundColor Yellow
    Write-Host "  UPDATE AVAILABLE: v$($UpdateInfo.CurrentVersion) → v$($UpdateInfo.LatestVersion) (released $($UpdateInfo.ReleaseDate))" -ForegroundColor Yellow
    Write-Host "  $line" -ForegroundColor Yellow

    # Show changes grouped by version (history entries are already filtered & sorted)
    if ($UpdateInfo.History -and $UpdateInfo.History.Count -gt 0) {
        $maxVersions = [Math]::Min(5, $UpdateInfo.History.Count)
        for ($v = 0; $v -lt $maxVersions; $v++) {
            $entry = $UpdateInfo.History[$v]
            if ($v -gt 0) {
                Write-Host "  $thin" -ForegroundColor DarkGray
            }
            Write-Host "  v$($entry.version) — $($entry.releaseDate)" -ForegroundColor White

            $maxHighlights = [Math]::Min(5, $entry.highlights.Count)
            for ($i = 0; $i -lt $maxHighlights; $i++) {
                Write-Host "    • $($entry.highlights[$i])" -ForegroundColor Cyan
            }
            if ($entry.highlights.Count -gt 5) {
                Write-Host "      ...and $($entry.highlights.Count - 5) more changes" -ForegroundColor DarkCyan
            }
        }
        if ($UpdateInfo.History.Count -gt 5) {
            Write-Host "  $thin" -ForegroundColor DarkGray
            Write-Host "  ...and $($UpdateInfo.History.Count - 5) more version(s) — see full changelog" -ForegroundColor DarkCyan
        }
    }

    Write-Host "  $line" -ForegroundColor Yellow
    Write-Host "  Run with -Update to upgrade automatically" -ForegroundColor Green
    Write-Host "  Full changelog: $($UpdateInfo.ReleaseNotesUrl)" -ForegroundColor Gray
    Write-Host "  $line" -ForegroundColor Yellow
    Write-Host ""
}

function Update-ScriptFromRepo {
    <#
    .SYNOPSIS
        Downloads the latest script from GitHub, validates it, backs up the current
        version, and replaces the local file. Exits after successful update.
    #>
    $scriptPath = $PSCommandPath   # full path of the currently running script
    if (-not $scriptPath) {
        Write-Host "  ERROR: Cannot determine current script path. Update aborted." -ForegroundColor Red
        exit 1
    }

    Write-Host ""
    Write-Host "  Checking for updates..." -ForegroundColor Cyan

    # 1. Fetch VERSION.json
    try {
        $versionInfo = Invoke-RestMethod -Uri $script:VersionCheckUrl `
            -Headers @{ 'User-Agent' = 'PowerShell-AzurePolicyAssessment'; 'Accept' = 'application/json' } `
            -Method Get -TimeoutSec 10 -ErrorAction Stop
    }
    catch {
        Write-Host "  ERROR: Unable to reach GitHub. Check your internet connection." -ForegroundColor Red
        Write-Host "  Detail: $($_.Exception.Message)" -ForegroundColor DarkGray
        exit 1
    }

    $remoteVersion  = [version]$versionInfo.version
    $currentVersion = [version]$ScriptVersion

    if ($remoteVersion -le $currentVersion) {
        Write-Host "  ✓ You are already running the latest version (v$ScriptVersion)." -ForegroundColor Green
        Write-Host ""
        exit 0
    }

    Write-Host "  New version found: v$($versionInfo.version) (released $($versionInfo.releaseDate))" -ForegroundColor Yellow
    Write-Host ""

    # Show what's changed since the current version
    if ($versionInfo.history) {
        $newEntries = @($versionInfo.history | Where-Object {
            [version]$_.version -gt $currentVersion
        } | Sort-Object { [version]$_.version } -Descending)

        if ($newEntries.Count -gt 0) {
            Write-Host "  What's new since v$ScriptVersion :" -ForegroundColor Cyan
            Write-Host ""
            foreach ($entry in $newEntries) {
                Write-Host "    v$($entry.version) — $($entry.releaseDate)" -ForegroundColor White
                foreach ($h in $entry.highlights) {
                    Write-Host "      • $h" -ForegroundColor Gray
                }
                Write-Host ""
            }
        }
    }

    # 2. Check scriptUrl
    $scriptUrl = $versionInfo.scriptUrl
    if (-not $scriptUrl) {
        Write-Host "  ERROR: VERSION.json does not contain a 'scriptUrl' field. Update aborted." -ForegroundColor Red
        exit 1
    }

    # 3. Download to temp file
    $tempFile = "$scriptPath.update-temp"
    Write-Host "  Downloading v$($versionInfo.version)..." -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $scriptUrl `
            -Headers @{ 'User-Agent' = 'PowerShell-AzurePolicyAssessment' } `
            -OutFile $tempFile -TimeoutSec 30 -ErrorAction Stop
    }
    catch {
        Write-Host "  ERROR: Download failed: $($_.Exception.Message)" -ForegroundColor Red
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
        exit 1
    }

    # 4. Validate — must parse without errors
    Write-Host "  Validating downloaded script..." -ForegroundColor Gray
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($tempFile, [ref]$null, [ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count -gt 0) {
        Write-Host "  ERROR: Downloaded script has $($parseErrors.Count) parse error(s). Update aborted." -ForegroundColor Red
        foreach ($pe in $parseErrors | Select-Object -First 3) {
            Write-Host "    Line $($pe.Extent.StartLineNumber): $($pe.Message)" -ForegroundColor DarkRed
        }
        Remove-Item $tempFile -Force
        exit 1
    }

    # 5. Verify the downloaded script claims the expected version
    $downloadedContent = Get-Content $tempFile -Raw
    if ($downloadedContent -match '\`$ScriptVersion\s*=\s*"([^"]+)"') {
        $downloadedVersion = [version]$Matches[1]
        if ($downloadedVersion -ne $remoteVersion) {
            Write-Host "  WARNING: Downloaded script reports v$($Matches[1]) but VERSION.json says v$($versionInfo.version)." -ForegroundColor Yellow
        }
    }

    # 6. Back up current script
    $backupName = [System.IO.Path]::GetFileNameWithoutExtension($scriptPath)
    $backupPath = Join-Path (Split-Path $scriptPath) "$backupName-v$ScriptVersion-backup.ps1"
    Write-Host "  Backing up current script to: $(Split-Path $backupPath -Leaf)" -ForegroundColor Gray
    try {
        Copy-Item -Path $scriptPath -Destination $backupPath -Force -ErrorAction Stop
    }
    catch {
        Write-Host "  ERROR: Backup failed: $($_.Exception.Message)" -ForegroundColor Red
        Remove-Item $tempFile -Force
        exit 1
    }

    # 7. Replace current script with downloaded version
    Write-Host "  Replacing script..." -ForegroundColor Gray
    try {
        Move-Item -Path $tempFile -Destination $scriptPath -Force -ErrorAction Stop
    }
    catch {
        Write-Host "  ERROR: Could not replace script file: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Your backup is safe at: $backupPath" -ForegroundColor Yellow
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
        exit 1
    }

    # 8. Success
    $successLine = '════════════════════════════════════════════════════════════════════════════'

    Write-Host ""
    Write-Host "  $successLine" -ForegroundColor Green
    Write-Host "  ✓ UPDATE SUCCESSFUL: v$ScriptVersion → v$($versionInfo.version)" -ForegroundColor Green
    Write-Host "" -ForegroundColor Green
    Write-Host "  Backup saved as: $(Split-Path $backupPath -Leaf)" -ForegroundColor Green
    Write-Host "  Please re-run the script to use the new version." -ForegroundColor Green
    Write-Host "  $successLine" -ForegroundColor Green
    Write-Host ""
    exit 0
}

function Resolve-AzureTenantSubscriptionContext {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [string]$RequestedSubscription = '',
        $CurrentContext = $null,
        [AllowNull()][AllowEmptyCollection()][object[]]$TenantSubscriptions = $null
    )

    if ($null -eq $CurrentContext) { $CurrentContext = Get-AzContext }
    if ($null -eq $TenantSubscriptions) {
        $TenantSubscriptions = @(Get-AzSubscription -TenantId $TenantId -ErrorAction Stop)
    }
    $available = @($TenantSubscriptions | Where-Object { -not $_.State -or $_.State -eq 'Enabled' })

    if ($RequestedSubscription) {
        $match = $available | Where-Object {
            [string]::Equals([string]$_.Id, $RequestedSubscription, [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals([string]$_.Name, $RequestedSubscription, [System.StringComparison]::OrdinalIgnoreCase)
        } | Select-Object -First 1
        return [PSCustomObject][ordered]@{
            State = if ($match) { 'Resolved' } else { 'RequestedSubscriptionUnavailable' }
            Subscription = $match
            Message = if ($match) { 'The requested subscription belongs to the selected tenant.' } else { 'The requested subscription is not available in the selected tenant.' }
        }
    }

    $currentSubscriptionId = [string]$CurrentContext.Subscription.Id
    $currentMatch = $available | Where-Object {
        [string]::Equals([string]$_.Id, $currentSubscriptionId, [System.StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    $resolved = if ($currentMatch) { $currentMatch } else { $available | Select-Object -First 1 }
    $currentSubscriptionOwner = $null
    if (-not $resolved -and $currentSubscriptionId) {
        try {
            $currentSubscriptionOwner = Get-AzSubscription -SubscriptionId $currentSubscriptionId -ErrorAction Stop | Select-Object -First 1
        } catch {
            $currentSubscriptionOwner = $null
        }
    }

    [PSCustomObject][ordered]@{
        State = if ($resolved) { 'Resolved' } else { 'NoCompatibleSubscription' }
        Subscription = $resolved
        SuggestedTenantId = if ($currentSubscriptionOwner) { [string]$currentSubscriptionOwner.TenantId } else { '' }
        CurrentSubscriptionName = if ($currentSubscriptionOwner) { [string]$currentSubscriptionOwner.Name } else { [string]$CurrentContext.Subscription.Name }
        Message = if ($currentMatch) {
            'The current subscription belongs to the selected tenant.'
        } elseif ($resolved) {
            'The current subscription belongs to another tenant; a compatible subscription was selected.'
        } else {
            'No enabled subscription is available in the selected tenant.'
        }
    }
}

function Test-CostEvidenceRecord {
    param([Parameter(Mandatory)]$Record)

    $requiredProperties = @('EvidenceType', 'Amount', 'Currency', 'Region', 'Source', 'SourceUri', 'RetrievedAt', 'PriceOrCostDate')
    foreach ($property in $requiredProperties) {
        if (-not $Record.PSObject.Properties[$property] -or $null -eq $Record.$property -or [string]::IsNullOrWhiteSpace([string]$Record.$property)) {
            return $false
        }
    }
    if ($Record.EvidenceType -notin @('RetailPrice', 'ActualCost')) { return $false }
    if ($Record.Source -notin @('Azure Retail Prices API', 'Azure Cost Management')) { return $false }
    try { $sourceUri = [uri]$Record.SourceUri } catch { return $false }
    if ($Record.EvidenceType -eq 'RetailPrice' -and ($sourceUri.Scheme -ne 'https' -or $sourceUri.Host -ne 'prices.azure.com')) { return $false }
    if ($Record.EvidenceType -eq 'ActualCost' -and ($sourceUri.Scheme -ne 'https' -or $sourceUri.Host -ne 'management.azure.com' -or $sourceUri.AbsolutePath -notmatch '/providers/Microsoft\.CostManagement/query$')) { return $false }
    if ([string]$Record.Currency -notmatch '^[A-Z]{3}$') { return $false }
    if ([string]$Record.RetrievedAt -notmatch '^\d{4}-\d{2}-\d{2}T') { return $false }
    if ([string]$Record.PriceOrCostDate -notmatch '^\d{4}-\d{2}-\d{2}') { return $false }
    try { [void][decimal]$Record.Amount } catch { return $false }
    return $true
}

function Get-AzureRetailPriceEvidence {
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Region,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]{3}$')][string]$Currency,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$ServiceNames
    )

    $retrievedAt = (Get-Date).ToUniversalTime().ToString('o')
    $evidence = [System.Collections.Generic.List[object]]::new()
    foreach ($serviceName in @($ServiceNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        $escapedService = $serviceName.Replace("'", "''")
        $escapedRegion = $Region.Replace("'", "''")
        $filter = [uri]::EscapeDataString("armRegionName eq '$escapedRegion' and serviceName eq '$escapedService' and priceType eq 'Consumption'")
        $uri = "https://prices.azure.com/api/retail/prices?currencyCode=$($Currency.ToUpperInvariant())&`$filter=$filter"
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Accept = 'application/json' } -ErrorAction Stop
        foreach ($item in @($response.Items | Select-Object -First 50)) {
            if ($null -eq $item.retailPrice) { continue }
            $record = [PSCustomObject][ordered]@{
                EvidenceType = 'RetailPrice'
                Description = "$($item.serviceName) | $($item.productName) | $($item.skuName)"
                Amount = [decimal]$item.retailPrice
                Unit = [string]$item.unitOfMeasure
                Currency = [string]$item.currencyCode
                Region = [string]$item.armRegionName
                Source = 'Azure Retail Prices API'
                SourceUri = $uri
                RetrievedAt = $retrievedAt
                PriceOrCostDate = if ($item.effectiveStartDate) { ([datetime]$item.effectiveStartDate).ToUniversalTime().ToString('o') } else { $retrievedAt }
            }
            if (Test-CostEvidenceRecord -Record $record) { [void]$evidence.Add($record) }
        }
    }
    @($evidence)
}

function Get-AzureCostManagementEvidence {
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SubscriptionId,
        [ValidateRange(1, 365)][int]$LookbackDays = 30
    )

    $periodEnd = (Get-Date).ToUniversalTime()
    $periodStart = $periodEnd.AddDays(-$LookbackDays)
    $path = "/subscriptions/$SubscriptionId/providers/Microsoft.CostManagement/query?api-version=2023-11-01"
    $body = [ordered]@{
        type = 'ActualCost'
        timeframe = 'Custom'
        timePeriod = [ordered]@{ from = $periodStart.ToString('o'); to = $periodEnd.ToString('o') }
        dataset = [ordered]@{
            granularity = 'None'
            aggregation = [ordered]@{ totalCost = [ordered]@{ name = 'Cost'; function = 'Sum' } }
            grouping = @(
                [ordered]@{ type = 'Dimension'; name = 'ResourceLocation' },
                [ordered]@{ type = 'Dimension'; name = 'Currency' }
            )
        }
    }
    $response = Invoke-AzRestMethod -Method POST -Path $path -Payload ($body | ConvertTo-Json -Depth 10 -Compress) -ErrorAction Stop
    $content = $response.Content | ConvertFrom-Json -Depth 20
    $columns = @($content.properties.columns)
    $columnIndexes = @{}
    for ($index = 0; $index -lt $columns.Count; $index++) { $columnIndexes[[string]$columns[$index].name] = $index }
    if (-not $columnIndexes.ContainsKey('Cost') -or -not $columnIndexes.ContainsKey('Currency')) { return @() }

    $retrievedAt = (Get-Date).ToUniversalTime().ToString('o')
    $costRows = @($content.properties.rows)
    if ($costRows.Count -gt 0 -and $costRows[0] -isnot [System.Array]) { $costRows = @(, $costRows) }
    @($costRows | ForEach-Object {
        $row = @($_)
        $region = if ($columnIndexes.ContainsKey('ResourceLocation')) { [string]$row[$columnIndexes.ResourceLocation] } else { 'Unspecified' }
        if ([string]::IsNullOrWhiteSpace($region)) { $region = 'Unspecified' }
        $record = [PSCustomObject][ordered]@{
            EvidenceType = 'ActualCost'
            Description = "Actual subscription cost for $($periodStart.ToString('yyyy-MM-dd')) to $($periodEnd.ToString('yyyy-MM-dd'))"
            Amount = [decimal]$row[$columnIndexes.Cost]
            Unit = 'Actual cost for period'
            Currency = [string]$row[$columnIndexes.Currency]
            Region = $region
            Source = 'Azure Cost Management'
            SourceUri = "https://management.azure.com$path"
            RetrievedAt = $retrievedAt
            PriceOrCostDate = $periodEnd.ToString('o')
        }
        if (Test-CostEvidenceRecord -Record $record) { $record }
    })
}

# ═══════════════════════════════════════════════════════════════════════════
# Parameter resolution: bridge new params ↔ legacy switches (backward compat)
# ═══════════════════════════════════════════════════════════════════════════

# -Full overrides everything
if ($Full) {
    $Output = @('All')
    $CEP = 'Full'
}

# ── Bridge: legacy switches → new params (so rest of script uses internal flags) ──
if ($ExportHTML -or $Export -or $ExportNonCompliant) {
    $outputList = [System.Collections.ArrayList]@()
    if ($Output) { foreach ($o in $Output) { [void]$outputList.Add($o) } }
    if ($Export -and 'CSV' -notin $outputList -and 'All' -notin $outputList) { [void]$outputList.Add('CSV') }
    if ($ExportHTML -and 'HTML' -notin $outputList -and 'All' -notin $outputList) { [void]$outputList.Add('HTML') }
    if ($ExportNonCompliant -and 'NC' -notin $outputList -and 'All' -notin $outputList) { [void]$outputList.Add('NC') }
    $Output = @($outputList)
}

# ── Resolve new params → internal boolean flags used by the rest of the script ──
# Output flags
$Export = $Output -and ($Output -contains 'CSV' -or $Output -contains 'All')
$ExportHTML = $Output -and ($Output -contains 'HTML' -or $Output -contains 'All')
$ExportNonCompliant = $Output -and ($Output -contains 'NC' -or $Output -contains 'All')
$ExportYAML = $Output -and ($Output -contains 'YAML' -or $Output -contains 'All')

# CEP flags (cascading: Full → Test+Export+Show, Test → Show, Export → Show)
$ShowCEPCompliance = $CEP -in @('Show', 'Test', 'Export', 'Full')
$RunCEPTests = $CEP -in @('Test', 'Full')
$ExportCEPCompliance = $CEP -in @('Export', 'Full')

# ── Filter guard: CEP requires tenant-wide scope ──
if (($ManagementGroup -or $Subscription) -and ($ShowCEPCompliance -or $RunCEPTests -or $ExportCEPCompliance)) {
    $filterTarget = if ($ManagementGroup) { "-ManagementGroup '$ManagementGroup'" } else { "-Subscription '$Subscription'" }
    # Was CEP explicitly requested, or implicitly set by -Full?
    $cepExplicit = $PSBoundParameters.ContainsKey('CEP')
    if ($cepExplicit) {
        # User explicitly asked for CEP + a scope filter — stop with clear error
        Write-Host ""
        Write-Error ("PARAMETER CONFLICT: -CEP '$CEP' cannot be used with $filterTarget.`n" +
            "Cyber Essentials Plus compliance requires a tenant-wide assessment to produce accurate results.`n" +
            "Please choose one of the following:`n" +
            "  1) Remove $filterTarget to run the full assessment including CEP.`n" +
            "  2) Remove -CEP '$CEP' to run a filtered assessment without CEP.`n") -ErrorAction Stop
    } else {
        # CEP was implicitly enabled by -Full — warn and disable gracefully
        Write-Host ""
        Write-Host "  NOTE: CEP automatically disabled — Cyber Essentials Plus requires a tenant-wide assessment." -ForegroundColor Yellow
        Write-Host "  Filtered to $filterTarget — all other assessment sections will run normally." -ForegroundColor Yellow
        Write-Host "  To include CEP, run without $filterTarget." -ForegroundColor Gray
        Write-Host ""
        $ShowCEPCompliance = $false
        $RunCEPTests = $false
        $ExportCEPCompliance = $false
    }
}

# Cyber Essentials compliance is assessed using the built-in
# 'UK NCSC Cyber Essentials v3.1' Azure Policy Initiative (policy set definition).
# This provides accurate, Microsoft-maintained mappings of CE requirements to Azure policies.
# The CE+ v3.2 test specification tests (TC1-TC5) are based on the official NCSC document.
#
# References:
#   - NCSC CE+ v3.2 Test Specification : https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf
#   - Azure CE+ Compliance Offering    : https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus

# Display version banner
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Azure Policy & Compliance Assessment Tool" -ForegroundColor Cyan
Write-Host "  Version: $ScriptVersion | Last Updated: $ScriptLastUpdated" -ForegroundColor Cyan
Write-Host "  Performance: Azure Resource Graph Integration" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

# Handle -Update: self-update from GitHub and exit
if ($Update) {
    Update-ScriptFromRepo
    # Update-ScriptFromRepo calls exit — this line is never reached
}

# Check for updates (non-blocking, silent on failure)
$updateInfo = Test-ScriptUpdate
Show-UpdateNotification -UpdateInfo $updateInfo

# Show active configuration
$filterLabel = if ($ManagementGroup) { "MG: $ManagementGroup" } elseif ($Subscription) { "Sub: $Subscription" } else { 'All (tenant-wide)' }
$outputLabel = if ($Output) { ($Output -join ', ') } else { 'Console only' }
$cepLabel = if ($CEP) { $CEP } else { 'Off' }
Write-Host "  Filter: $filterLabel | Output: $outputLabel | CEP: $cepLabel$(if ($QuickAssess) { ' | QuickAssess: On' })" -ForegroundColor DarkGray
Write-Host ""
Write-Host "⚠️  DISCLAIMER:" -ForegroundColor Yellow
Write-Host "   This project is made and maintained by Riccardo Pomato. It is NOT an official Microsoft tool." -ForegroundColor Gray
Write-Host "   Results may not be 100% accurate. Always verify against Azure Portal and official tools." -ForegroundColor Gray
Write-Host "   Use at your own risk. No warranties or guarantees provided." -ForegroundColor Gray
Write-Host ""

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

try {
    $tenantContextResolution = Resolve-AzureTenantSubscriptionContext `
        -TenantId $selectedTenant.Id `
        -RequestedSubscription $Subscription
    if ($tenantContextResolution.Subscription) {
        $resolvedSubscription = $tenantContextResolution.Subscription
        Set-AzContext -TenantId $selectedTenant.Id -SubscriptionId $resolvedSubscription.Id -ErrorAction Stop | Out-Null
        if ($tenantContextResolution.Message -match 'another tenant') {
            Write-Host "Selected compatible subscription: $($resolvedSubscription.Name) ($($resolvedSubscription.Id))" -ForegroundColor Yellow
        }
    } elseif ($CEP -ne 'Off') {
        Write-Host 'ERROR: Cyber Essentials assessment requires a subscription associated with the selected tenant.' -ForegroundColor Red
        Write-Host $tenantContextResolution.Message -ForegroundColor Yellow
        if ($tenantContextResolution.SuggestedTenantId) {
            Write-Host "The current subscription '$($tenantContextResolution.CurrentSubscriptionName)' belongs to tenant $($tenantContextResolution.SuggestedTenantId)." -ForegroundColor Yellow
            Write-Host "Run Connect-AzAccount -TenantId $($tenantContextResolution.SuggestedTenantId), then rerun with -TenantId $($tenantContextResolution.SuggestedTenantId)." -ForegroundColor Yellow
        } else {
            Write-Host 'Reconnect with Connect-AzAccount -TenantId <subscription-tenant-id>, then rerun with that tenant.' -ForegroundColor Yellow
        }
        exit 1
    }
} catch {
    if ($CEP -ne 'Off') {
        Write-Host 'ERROR: Unable to establish a tenant/subscription context required for Cyber Essentials assessment.' -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor DarkGray
        exit 1
    }
}

#region Function Definitions

# ═══════════════════════════════════════════════════════════════════════════
# YAML DATABASE — export full assessment snapshot & delta comparison
# ═══════════════════════════════════════════════════════════════════════════

function Export-AssessmentYAML {
    <#
    .SYNOPSIS
        Exports the full assessment data to a YAML database file for offline analysis.
    #>
    param(
        [string]$OutputPath,
        [array]$PolicyResults,
        [hashtable]$ComplianceData,
        $CEPAssessment = $null,
        [array]$CEPExportData,
        [array]$CEPTestResults,
        [array]$CEPPerScopeData,
        [hashtable]$CEPPerScopeGroupData = @{},
        [hashtable]$CEPPerScopeGroupRaw = @{},
        [hashtable]$CEPRefIdToGroupDisplay = @{},
        [array]$NCExportData,
        [array]$ExemptionData,
        [string]$TenantId,
        [string]$TenantName,
        [string]$FilterLabel,
        [int]$PolicyCount,
        [int]$InitiativeCount,
        [int]$RegulatoryCount,
        [int]$EnforcedCount,
        [int]$AuditOnlyCount,
        [int]$TotalNCResources,
        $DataQuality = $null,
        [array]$AssessmentFindings = @(),
        [string]$ScriptVersion
    )

    # Ensure powershell-yaml module is available
    if (-not (Get-Module -ListAvailable -Name 'powershell-yaml')) {
        Write-Host "  Installing powershell-yaml module..." -ForegroundColor Yellow
        try {
            Install-Module -Name 'powershell-yaml' -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
        } catch {
            Write-Host "  ✗ Failed to install powershell-yaml: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "    Install manually: Install-Module -Name powershell-yaml -Force" -ForegroundColor Gray
            return $null
        }
    }
    Import-Module 'powershell-yaml' -ErrorAction Stop

    # Build the comprehensive database object
    $yamlDatabase = [ordered]@{
        metadata = [ordered]@{
            timestamp     = (Get-Date).ToString('o')
            scriptVersion = $ScriptVersion
            tenantId      = $TenantId
            tenantName    = $TenantName
            filter        = $FilterLabel
            powershell    = $PSVersionTable.PSVersion.ToString()
            hostname      = [System.Environment]::MachineName
        }
        summary = [ordered]@{
            totalAssignments     = $PolicyResults.Count
            totalPolicies        = $PolicyCount
            totalInitiatives     = $InitiativeCount
            totalRegulatory      = $RegulatoryCount
            enforcedCount        = $EnforcedCount
            auditOnlyCount       = $AuditOnlyCount
            totalNonCompliant    = $TotalNCResources
            nonCompliantCountSemantics = 'Sum of distinct non-compliant resources per assignment; the same Azure resource may contribute to more than one assignment.'
            highRiskCount        = @($PolicyResults | Where-Object { $_.'Risk Level' -eq 'High' }).Count
            effectTypes          = [ordered]@{}
            remediationStates    = [ordered]@{}
            scopeBreakdown       = [ordered]@{
                managementGroups = @($PolicyResults | Where-Object { $_.'Scope Type' -eq 'Management Group' }).Count
                subscriptions    = @($PolicyResults | Where-Object { $_.'Scope Type' -eq 'Subscription' }).Count
                resourceGroups   = @($PolicyResults | Where-Object { $_.'Scope Type' -eq 'Resource Group' }).Count
            }
            categories           = [ordered]@{}
        }
        assignments = @()
        compliance  = @()
        dataQuality = $DataQuality
        cepAssessment = $CEPAssessment
        assessmentFindings = @($AssessmentFindings)
        assessmentActions = @(ConvertTo-AssessmentActions -AssessmentFindings $AssessmentFindings)
    }

    # Effect type breakdown
    $yamlEffectCounts = Get-EffectivePolicyEffectCounts -PolicyResults $PolicyResults
    $yamlEffectCounts.Breakdown | ForEach-Object {
        $yamlDatabase.summary.effectTypes[$_.Effect] = $_.Count
    }
    $PolicyResults | Where-Object { $_.'Remediation Evidence' } | Group-Object { $_.'Remediation Evidence'.State } | ForEach-Object {
        $yamlDatabase.summary.remediationStates[$_.Name] = $_.Count
    }

    # Category breakdown
    $PolicyResults | Where-Object { $_.'Category' -and $_.'Category' -ne '' } | Group-Object 'Category' | Sort-Object Count -Descending | ForEach-Object {
        $catNC = ($_.Group | ForEach-Object { if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 } } | Measure-Object -Sum).Sum
        $yamlDatabase.summary.categories[$_.Name] = [ordered]@{ count = $_.Count; nonCompliant = $catNC }
    }

    # Full assignment records
    $yamlDatabase.assignments = @($PolicyResults | ForEach-Object {
        [ordered]@{
            assignmentId         = $_.'Assignment ID'
            assignmentName       = $_.'Assignment Name'
            displayName          = $_.'Display Name'
            policyType           = $_.'Policy Type'
            category             = $_.'Category'
            effectType           = $_.'Effect Type'
            effectiveEffects     = @($_.'Effective Effects')
            primaryEffect        = $_.'Primary Effect'
            isPreventive         = [bool]$_.'Is Preventive'
            isDetective          = [bool]$_.'Is Detective'
            isRemediating        = [bool]$_.'Is Remediating'
            isParameterised      = [bool]$_.'Is Parameterised'
            isDisabled           = [bool]$_.'Is Disabled'
            enforcementMode      = $_.'Enforcement Mode'
            complianceState      = $_.'Compliance State'
            nonCompliantResources= if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 }
            nonCompliantPolicies = if ($_.'Non-Compliant Policies' -match '^\d+$') { [int]$_.'Non-Compliant Policies' } else { 0 }
            totalResources       = if ($_.'Total Resources' -match '^\d+$') { [int]$_.'Total Resources' } else { 0 }
            securityImpact       = $_.'Security Impact'
            costImpact           = $_.'Cost Exposure'
            complianceImpact     = $_.'Compliance Impact'
            operationalOverhead  = $_.'Operational Overhead'
            riskLevel            = $_.'Risk Level'
            scopeType            = $_.'Scope Type'
            scopeName            = $_.'Scope Name'
            managementGroupId    = $_.'Management Group ID'
            policyName           = $_.'Policy Name'
            parameters           = $_.'Parameters'
            recommendation       = $_.'Recommendation'
            scope                = $_.'Scope'
            exemptions           = if ($_.'Exemptions' -match '^\d+$') { [int]$_.'Exemptions' } else { 0 }
            remediationEvidence  = $_.'Remediation Evidence'
        }
    })

    # Compliance data (from ARG)
    if ($ComplianceData -and $ComplianceData.Count -gt 0) {
        $yamlDatabase.compliance = @($ComplianceData.GetEnumerator() | ForEach-Object {
            [ordered]@{
                policyAssignmentId    = $_.Key
                complianceState       = $_.Value.ComplianceState
                compliantResources    = $_.Value.CompliantResources
                nonCompliantResources = $_.Value.NonCompliantResources
                nonCompliantPolicies  = $_.Value.NonCompliantPolicyDefs
                totalResources        = $_.Value.TotalResources
            }
        })
    }

    # CE+ compliance data (if available)
    if ($CEPExportData -and $CEPExportData.Count -gt 0) {
        $yamlDatabase['cepCompliance'] = @($CEPExportData | ForEach-Object {
            [ordered]@{
                controlGroup         = $_.'CE Control Group'
                policyReference      = $_.'Policy Reference'
                policyDisplayName    = $_.'Policy Display Name'
                status               = $_.'Status'
                nonCompliantResources= if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 }
                compliantResources   = if ($_.'Compliant Resources' -match '^\d+$') { [int]$_.'Compliant Resources' } else { 0 }
                exemptResources      = if ($_.'Exempt Resources' -match '^\d+$') { [int]$_.'Exempt Resources' } else { 0 }
                totalResources       = if ($_.'Total Resources' -match '^\d+$') { [int]$_.'Total Resources' } else { 0 }
                recommendation       = $_.'Recommendation'
            }
        })
    }

    # CE+ test results (if available)
    if ($CEPTestResults -and $CEPTestResults.Count -gt 0) {
        $yamlDatabase['cepTestResults'] = @($CEPTestResults | ForEach-Object {
            [ordered]@{
                testNumber      = $_.'Test #'
                controlGroup    = $_.'Control Group'
                testName        = $_.'Test Name'
                status          = $_.'Status'
                details         = $_.'Details'
                nonCompliant    = if ($_.'Non-Compliant' -match '^\d+$') { [int]$_.'Non-Compliant' } else { 0 }
                compliant       = if ($_.'Compliant' -match '^\d+$') { [int]$_.'Compliant' } else { 0 }
                totalResources  = if ($_.'Total Resources' -match '^\d+$') { [int]$_.'Total Resources' } else { 0 }
            }
        })
    }

    # CE+ per-scope compliance breakdown (multi-assignment only)
    if ($CEPPerScopeData -and $CEPPerScopeData.Count -gt 0) {
        $yamlDatabase['cepPerScopeCompliance'] = @($CEPPerScopeData | ForEach-Object {
            [ordered]@{
                assignmentId    = $_.AssignmentId
                displayName     = $_.DisplayName
                scopeType       = $_.ScopeType
                enforcementMode = $_.EnforcementMode
                compliancePct   = $_.CompliancePct
                compliant       = if ($_.Compliant -match '^\d+$') { [int]$_.Compliant } else { 0 }
                nonCompliant    = if ($_.NonCompliant -match '^\d+$') { [int]$_.NonCompliant } else { 0 }
                exempt          = if ($_.Exempt -match '^\d+$') { [int]$_.Exempt } else { 0 }
                total           = if ($_.Total -match '^\d+$') { [int]$_.Total } else { 0 }
            }
        })
    }

    # Non-compliant resources (if available)
    if ($NCExportData -and $NCExportData.Count -gt 0) {
        $yamlDatabase['nonCompliantResources'] = @($NCExportData | ForEach-Object {
            [ordered]@{
                resourceId           = $_.'Resource ID'
                resourceName         = $_.'Resource Name'
                resourceType         = $_.'Resource Type'
                resourceGroup        = $_.'Resource Group'
                subscriptionId       = $_.'Subscription ID'
                policyName           = $_.'Policy Name'
                policyDefinitionId   = $_.'Policy Definition ID'
                initiativeName       = $_.'Initiative Name'
                policyAssignmentName = $_.'Policy Assignment Name'
                policyAssignmentId   = $_.'Policy Assignment ID'
            }
        })
    }

    # Policy exemptions
    if ($ExemptionData -and $ExemptionData.Count -gt 0) {
        $yamlDatabase['exemptions'] = @($ExemptionData | ForEach-Object {
            [ordered]@{
                exemptionName       = $_.'Exemption Name'
                displayName         = $_.'Display Name'
                description         = $_.'Description'
                category            = $_.'Category'
                policyAssignment    = $_.'Policy Assignment'
                policyAssignmentId  = $_.'Policy Assignment ID'
                scopeType           = $_.'Scope Type'
                scopeName           = $_.'Scope Name'
                scope               = $_.'Scope'
                expiresOn           = $_.'Expires On'
                isExpired           = $_.'Is Expired'
                createdOn           = $_.'Created On'
                partialExemption    = $_.'Partial Exemption'
                exemptedPolicies    = $_.'Exempted Policies'
                exemptionId         = $_.'Exemption ID'
            }
        })
        $yamlDatabase.summary['totalExemptions'] = $ExemptionData.Count
        $yamlDatabase.summary['activeExemptions'] = @($ExemptionData | Where-Object { -not $_.'Is Expired' }).Count
        $yamlDatabase.summary['expiredExemptions'] = @($ExemptionData | Where-Object { $_.'Is Expired' }).Count
        $yamlDatabase.summary['waiverExemptions'] = @($ExemptionData | Where-Object { $_.'Category' -eq 'Waiver' }).Count
        $yamlDatabase.summary['mitigatedExemptions'] = @($ExemptionData | Where-Object { $_.'Category' -eq 'Mitigated' }).Count
    }

    # Convert to YAML and write
    try {
        $yamlContent = ConvertTo-Yaml $yamlDatabase -Options EmitDefaults
        # Add header comment
        $header = @"
# ═══════════════════════════════════════════════════════════════════════════
# Azure Policy Assessment Database (YAML)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Script:    Get-PolicyAssignments.ps1 v$ScriptVersion
# Purpose:   Offline assessment database — use with -DeltaYAML for comparisons
# ═══════════════════════════════════════════════════════════════════════════
"@
        "$header`n$yamlContent" | Set-Content -Path $OutputPath -Encoding UTF8
        return $OutputPath
    } catch {
        Write-Host "  ✗ YAML export failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


function Get-YAMLDeltaData {
    <#
    .SYNOPSIS
        Loads a previous YAML assessment database and computes a structured delta against the current results.
        Returns a hashtable with all delta information, or $null on failure.
    #>
    param(
        [string]$PreviousYAMLPath,
        [array]$CurrentResults,
        [array]$CurrentExemptions = @(),
        [string]$ScopeFilter = ''
    )

    if (-not (Test-Path $PreviousYAMLPath)) {
        Write-Host "  ✗ Previous YAML database not found: $PreviousYAMLPath" -ForegroundColor Red
        return $null
    }

    # Ensure powershell-yaml module is available
    if (-not (Get-Module -ListAvailable -Name 'powershell-yaml')) {
        Write-Host "  Installing powershell-yaml module..." -ForegroundColor Yellow
        try {
            Install-Module -Name 'powershell-yaml' -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
        } catch {
            Write-Host "  ✗ Failed to install powershell-yaml: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
    Import-Module 'powershell-yaml' -ErrorAction Stop

    try {
        $rawYAML = Get-Content $PreviousYAMLPath -Raw
        $previous = ConvertFrom-Yaml $rawYAML -Ordered
    } catch {
        Write-Host "  ✗ Failed to parse previous YAML database: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }

    $prevTimestamp = if ($previous.metadata.timestamp) {
        try { ([datetime]$previous.metadata.timestamp).ToString('yyyy-MM-dd HH:mm') } catch { $previous.metadata.timestamp }
    } else { 'Unknown' }
    $prevVersion = if ($previous.metadata.scriptVersion) { $previous.metadata.scriptVersion } else { '?' }

    # ── Scope-filter previous data to match current run ──
    # When the current run uses -ManagementGroup or -Subscription, the previous YAML
    # may have been generated tenant-wide. Filter previous assignments/exemptions to
    # only include entries whose scope matches the current filter, preventing false
    # "removed" entries for assignments outside the current scope.
    $prevFilteredAssignments = $previous.assignments
    $prevFilteredExemptions  = $previous.exemptions
    $scopeFilterApplied = $false
    if ($ScopeFilter -and $previous.assignments) {
        $lowerFilter = $ScopeFilter.ToLower()
        $prevFilteredAssignments = @($previous.assignments | Where-Object {
            $s = if ($_.scope) { $_.scope.ToLower() } else { '' }
            $s -like "*$lowerFilter*"
        })
        if ($previous.exemptions) {
            $prevFilteredExemptions = @($previous.exemptions | Where-Object {
                $s = if ($_.scope) { $_.scope.ToLower() } else { '' }
                $s -like "*$lowerFilter*"
            })
        }
        $scopeFilterApplied = $true
        $filteredOutCount = $previous.assignments.Count - $prevFilteredAssignments.Count
        if ($filteredOutCount -gt 0) {
            Write-Host "  Scope filter active: $filteredOutCount of $($previous.assignments.Count) previous assignments outside current scope (excluded from delta)" -ForegroundColor DarkGray
        }
    }

    # Build lookup tables using composite key (assignmentName + scope) to avoid
    # false positives when the same assignment name exists at multiple scopes
    $prevAssignments = @{}
    if ($prevFilteredAssignments) {
        foreach ($a in $prevFilteredAssignments) {
            $key = "$($a.assignmentName)|||$($a.scope)"
            $prevAssignments[$key] = $a
        }
    }

    $currAssignments = @{}
    foreach ($r in $CurrentResults) {
        $key = "$($r.'Assignment Name')|||$($r.'Scope')"
        $currAssignments[$key] = $r
    }

    # Compute deltas
    $newAssignments = @($CurrentResults | Where-Object {
        $k = "$($_.'Assignment Name')|||$($_.'Scope')"
        -not $prevAssignments.ContainsKey($k)
    })
    $removedAssignments = @()
    if ($prevFilteredAssignments) {
        $removedAssignments = @($prevFilteredAssignments | Where-Object {
            $k = "$($_.assignmentName)|||$($_.scope)"
            -not $currAssignments.ContainsKey($k)
        })
    }

    # Changed assignments (effect, enforcement, compliance changes)
    $changedAssignments = @()
    foreach ($curr in $CurrentResults) {
        $key = "$($curr.'Assignment Name')|||$($curr.'Scope')"
        if ($prevAssignments.ContainsKey($key)) {
            $prev = $prevAssignments[$key]
            $changes = @()
            if ($prev.effectType -ne $curr.'Effect Type') {
                $changes += [PSCustomObject]@{ Property = 'Effect'; Previous = $prev.effectType; Current = $curr.'Effect Type' }
            }
            if ($prev.enforcementMode -ne $curr.'Enforcement Mode') {
                $changes += [PSCustomObject]@{ Property = 'Enforcement'; Previous = $prev.enforcementMode; Current = $curr.'Enforcement Mode' }
            }
            $prevNCVal = [int]$prev.nonCompliantResources
            $currNCVal = [int]$curr.'Non-Compliant Resources'
            if ($prevNCVal -ne $currNCVal) {
                $changes += [PSCustomObject]@{ Property = 'Non-Compliant'; Previous = "$prevNCVal"; Current = "$currNCVal" }
            }
            if ($prev.riskLevel -ne $curr.'Risk Level') {
                $changes += [PSCustomObject]@{ Property = 'Risk Level'; Previous = $prev.riskLevel; Current = $curr.'Risk Level' }
            }
            $prevTotalRes = [int]$prev.totalResources
            $currTotalRes = [int]$curr.'Total Resources'
            if ($prevTotalRes -ne $currTotalRes) {
                $changes += [PSCustomObject]@{ Property = 'Total Resources'; Previous = "$prevTotalRes"; Current = "$currTotalRes" }
            }
            if ($changes.Count -gt 0) {
                $changedAssignments += [PSCustomObject]@{
                    Name      = $curr.'Assignment Name'
                    Display   = $curr.'Display Name'
                    ScopeName = $curr.'Scope Name'
                    Changes   = $changes
                }
            }
        }
    }

    # Summary deltas
    $prevSummary = $previous.summary
    # When scope-filtered, recalculate previous summary from filtered data
    if ($scopeFilterApplied -and $prevFilteredAssignments) {
        $prevTotal = $prevFilteredAssignments.Count
        $prevNC = ($prevFilteredAssignments | ForEach-Object { if ($_.nonCompliantResources -match '^\d+$') { [int]$_.nonCompliantResources } else { 0 } } | Measure-Object -Sum).Sum
        $prevHigh = @($prevFilteredAssignments | Where-Object { $_.riskLevel -eq 'High' }).Count
        $prevEnf = @($prevFilteredAssignments | Where-Object { $_.enforcementMode -eq 'Default' }).Count
    } else {
        $prevTotal = if ($prevSummary.totalAssignments) { [int]$prevSummary.totalAssignments } else { 0 }
        $prevNC = if ($prevSummary.totalNonCompliant) { [int]$prevSummary.totalNonCompliant } else { 0 }
        $prevHigh = if ($prevSummary.highRiskCount) { [int]$prevSummary.highRiskCount } else { 0 }
        $prevEnf = if ($prevSummary.enforcedCount) { [int]$prevSummary.enforcedCount } else { 0 }
    }
    $currTotal = $CurrentResults.Count
    $currNC = ($CurrentResults | ForEach-Object { if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 } } | Measure-Object -Sum).Sum

    $assignDelta = $currTotal - $prevTotal
    $ncDelta = $currNC - $prevNC
    $currHigh = @($CurrentResults | Where-Object { $_.'Risk Level' -eq 'High' }).Count
    $highDelta = $currHigh - $prevHigh

    $currEnf = @($CurrentResults | Where-Object { $_.'Enforcement Mode' -eq 'Default' }).Count
    $enfDelta = $currEnf - $prevEnf

    # Effect type changes
    $effectChanges = @()
    # When scope-filtered, recalculate previous effect types from filtered data
    $prevEffectTypes = $null
    if ($scopeFilterApplied -and $prevFilteredAssignments) {
        $prevEffectTypes = @{}
        (Get-EffectivePolicyEffectCounts -PolicyResults @($prevFilteredAssignments)).Breakdown | ForEach-Object {
            $prevEffectTypes[$_.Effect] = $_.Count
        }
    } elseif ($prevSummary.effectTypes) {
        $prevEffectTypes = $prevSummary.effectTypes
    }
    if ($prevEffectTypes) {
        $allEffects = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($e in $prevEffectTypes.Keys) { [void]$allEffects.Add($e) }
        $currEffectCounts = @{}
        (Get-EffectivePolicyEffectCounts -PolicyResults $CurrentResults).Breakdown | ForEach-Object {
            $currEffectCounts[$_.Effect] = $_.Count
            [void]$allEffects.Add($_.Effect)
        }
        foreach ($eff in $allEffects) {
            $pCount = if ($prevEffectTypes.Contains($eff)) { [int]$prevEffectTypes[$eff] } else { 0 }
            $cCount = if ($currEffectCounts.Contains($eff)) { [int]$currEffectCounts[$eff] } else { 0 }
            if ($pCount -ne $cCount) {
                $d = $cCount - $pCount
                $ds = if ($d -gt 0) { "+$d" } else { "$d" }
                $effectChanges += [PSCustomObject]@{ Effect = $eff; Previous = $pCount; Current = $cCount; Delta = $ds }
            }
        }
    }

    # CE+ test delta
    $cepPreviousResults = $null
    if ($previous.cepTestResults -and $previous.cepTestResults.Count -gt 0) {
        $cepPreviousResults = @{
            Pass   = @($previous.cepTestResults | Where-Object { $_.status -eq 'PASS' }).Count
            Fail   = @($previous.cepTestResults | Where-Object { $_.status -eq 'FAIL' }).Count
            Manual = @($previous.cepTestResults | Where-Object { $_.status -eq 'MANUAL' }).Count
        }
    }

    # Posture trend
    $trend = if ($ncDelta -lt 0 -and $highDelta -le 0 -and $enfDelta -ge 0) { 'IMPROVING' }
             elseif ($ncDelta -gt 0 -or $highDelta -gt 0) { 'DEGRADING' }
             elseif ($ncDelta -eq 0 -and $highDelta -eq 0) { 'STABLE' }
             else { 'MIXED' }

    # ── Exemption delta ──
    $prevExemptions = @{}
    if ($prevFilteredExemptions -and $prevFilteredExemptions.Count -gt 0) {
        foreach ($ex in $prevFilteredExemptions) {
            $exKey = "$($ex.exemptionName)|||$($ex.scope)"
            $prevExemptions[$exKey] = $ex
        }
    }

    $currExemptions = @{}
    foreach ($ex in $CurrentExemptions) {
        $exKey = "$($ex.'Exemption Name')|||$($ex.'Scope')"
        $currExemptions[$exKey] = $ex
    }

    $newExemptions = @($CurrentExemptions | Where-Object {
        $k = "$($_.'Exemption Name')|||$($_.'Scope')"
        -not $prevExemptions.ContainsKey($k)
    })
    $removedExemptions = @()
    if ($prevFilteredExemptions) {
        $removedExemptions = @($prevFilteredExemptions | Where-Object {
            $k = "$($_.exemptionName)|||$($_.scope)"
            -not $currExemptions.ContainsKey($k)
        })
    }

    $prevExTotal = if ($scopeFilterApplied) { if ($prevFilteredExemptions) { $prevFilteredExemptions.Count } else { 0 } } elseif ($previous.summary.totalExemptions) { [int]$previous.summary.totalExemptions } else { 0 }
    $prevExActive = if ($scopeFilterApplied -and $prevFilteredExemptions) {
        @($prevFilteredExemptions | Where-Object { -not $_.isExpired }).Count
    } elseif ($previous.summary.activeExemptions) { [int]$previous.summary.activeExemptions } else { 0 }
    $currExTotal = $CurrentExemptions.Count
    $currExActive = @($CurrentExemptions | Where-Object { -not $_.'Is Expired' }).Count
    $exTotalDelta = $currExTotal - $prevExTotal
    $exActiveDelta = $currExActive - $prevExActive

    # Return structured delta data
    return @{
        PreviousDate       = $prevTimestamp
        PreviousVersion    = $prevVersion
        PreviousFile       = $PreviousYAMLPath
        CurrTotal          = $currTotal
        PrevTotal          = $prevTotal
        AssignmentDelta    = $assignDelta
        CurrNC             = $currNC
        PrevNC             = $prevNC
        NCDelta            = $ncDelta
        CurrHigh           = $currHigh
        PrevHigh           = $prevHigh
        HighDelta          = $highDelta
        CurrEnforced       = $currEnf
        PrevEnforced       = $prevEnf
        EnfDelta           = $enfDelta
        NewAssignments     = $newAssignments
        RemovedAssignments = $removedAssignments
        ChangedAssignments = $changedAssignments
        EffectChanges      = $effectChanges
        CEPPreviousResults = $cepPreviousResults
        Trend              = $trend
        NewExemptions      = $newExemptions
        RemovedExemptions  = $removedExemptions
        CurrExTotal        = $currExTotal
        PrevExTotal        = $prevExTotal
        ExTotalDelta       = $exTotalDelta
        CurrExActive       = $currExActive
        PrevExActive       = $prevExActive
        ExActiveDelta      = $exActiveDelta
    }
}


function Show-YAMLDelta {
    <#
    .SYNOPSIS
        Displays a comprehensive delta comparison in the console using pre-computed delta data.
    #>
    param(
        [hashtable]$DeltaInfo
    )

    if (-not $DeltaInfo) { return }

    $assignSign = if ($DeltaInfo.AssignmentDelta -gt 0) { "+$($DeltaInfo.AssignmentDelta)" } elseif ($DeltaInfo.AssignmentDelta -lt 0) { "$($DeltaInfo.AssignmentDelta)" } else { "0" }
    $ncSign = if ($DeltaInfo.NCDelta -gt 0) { "+$($DeltaInfo.NCDelta)" } elseif ($DeltaInfo.NCDelta -lt 0) { "$($DeltaInfo.NCDelta)" } else { "0" }
    $ncColor = if ($DeltaInfo.NCDelta -gt 0) { 'Red' } elseif ($DeltaInfo.NCDelta -lt 0) { 'Green' } else { 'Gray' }
    $highSign = if ($DeltaInfo.HighDelta -gt 0) { "+$($DeltaInfo.HighDelta)" } elseif ($DeltaInfo.HighDelta -lt 0) { "$($DeltaInfo.HighDelta)" } else { "0" }
    $highColor = if ($DeltaInfo.HighDelta -gt 0) { 'Red' } elseif ($DeltaInfo.HighDelta -lt 0) { 'Green' } else { 'Gray' }
    $enfSign = if ($DeltaInfo.EnfDelta -gt 0) { "+$($DeltaInfo.EnfDelta)" } elseif ($DeltaInfo.EnfDelta -lt 0) { "$($DeltaInfo.EnfDelta)" } else { "0" }
    $enfColor = if ($DeltaInfo.EnfDelta -gt 0) { 'Green' } elseif ($DeltaInfo.EnfDelta -lt 0) { 'Yellow' } else { 'Gray' }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  📊 YAML DELTA ASSESSMENT" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  Previous: $($DeltaInfo.PreviousDate) (v$($DeltaInfo.PreviousVersion))" -ForegroundColor Gray
    Write-Host "  Current:  $(Get-Date -Format 'yyyy-MM-dd HH:mm') (v$ScriptVersion)" -ForegroundColor Gray
    Write-Host "───────────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

    Write-Host "  Assignments  : $($DeltaInfo.CurrTotal) ($assignSign)" -ForegroundColor White
    Write-Host "  Non-Compliant: $($DeltaInfo.CurrNC) ($ncSign)" -ForegroundColor $ncColor
    Write-Host "  High Risk    : $($DeltaInfo.CurrHigh) ($highSign)" -ForegroundColor $highColor
    Write-Host "  Enforced     : $($DeltaInfo.CurrEnforced) ($enfSign)" -ForegroundColor $enfColor

    if ($DeltaInfo.NewAssignments.Count -gt 0) {
        Write-Host ""
        Write-Host "  ➕ NEW ASSIGNMENTS ($($DeltaInfo.NewAssignments.Count)):" -ForegroundColor Green
        foreach ($na in ($DeltaInfo.NewAssignments | Select-Object -First 10)) {
            $dn = if ($na.'Display Name'.Length -gt 60) { $na.'Display Name'.Substring(0, 57) + '...' } else { $na.'Display Name' }
            Write-Host "    + $dn" -NoNewline -ForegroundColor Green
            Write-Host " [$($na.'Effect Type') | $($na.'Scope Name')]" -ForegroundColor DarkGray
        }
        if ($DeltaInfo.NewAssignments.Count -gt 10) {
            Write-Host "    ... and $($DeltaInfo.NewAssignments.Count - 10) more" -ForegroundColor DarkGray
        }
    }

    if ($DeltaInfo.RemovedAssignments.Count -gt 0) {
        Write-Host ""
        Write-Host "  ➖ REMOVED ASSIGNMENTS ($($DeltaInfo.RemovedAssignments.Count)):" -ForegroundColor Red
        foreach ($ra in ($DeltaInfo.RemovedAssignments | Select-Object -First 10)) {
            $dn = if ($ra.displayName.Length -gt 60) { $ra.displayName.Substring(0, 57) + '...' } else { $ra.displayName }
            Write-Host "    - $dn" -NoNewline -ForegroundColor Red
            Write-Host " [$($ra.effectType) | $($ra.scopeName)]" -ForegroundColor DarkGray
        }
        if ($DeltaInfo.RemovedAssignments.Count -gt 10) {
            Write-Host "    ... and $($DeltaInfo.RemovedAssignments.Count - 10) more" -ForegroundColor DarkGray
        }
    }

    if ($DeltaInfo.ChangedAssignments.Count -gt 0) {
        Write-Host ""
        Write-Host "  🔄 CHANGED ASSIGNMENTS ($($DeltaInfo.ChangedAssignments.Count)):" -ForegroundColor Yellow
        foreach ($ca in ($DeltaInfo.ChangedAssignments | Select-Object -First 15)) {
            $dn = if ($ca.Display.Length -gt 55) { $ca.Display.Substring(0, 52) + '...' } else { $ca.Display }
            Write-Host "    ~ $dn" -NoNewline -ForegroundColor Yellow
            Write-Host " @ $($ca.ScopeName)" -ForegroundColor DarkGray
            foreach ($change in $ca.Changes) {
                Write-Host "      → $($change.Property): " -NoNewline -ForegroundColor DarkYellow
                Write-Host "$($change.Previous)" -NoNewline -ForegroundColor Red
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "$($change.Current)" -ForegroundColor Green
            }
        }
        if ($DeltaInfo.ChangedAssignments.Count -gt 15) {
            Write-Host "    ... and $($DeltaInfo.ChangedAssignments.Count - 15) more" -ForegroundColor DarkGray
        }
    }

    if ($DeltaInfo.EffectChanges.Count -gt 0) {
        Write-Host ""
        Write-Host "  📈 EFFECT TYPE CHANGES:" -ForegroundColor Cyan
        foreach ($ec in $DeltaInfo.EffectChanges) {
            Write-Host "    $($ec.Effect): $($ec.Previous) → $($ec.Current) ($($ec.Delta))" -ForegroundColor Gray
        }
    }

    if ($DeltaInfo.CEPPreviousResults) {
        Write-Host ""
        Write-Host "  🛡️  CE+ TEST RESULTS (previous run):" -ForegroundColor Cyan
        Write-Host "    Previous: $($DeltaInfo.CEPPreviousResults.Pass) PASS | $($DeltaInfo.CEPPreviousResults.Fail) FAIL | $($DeltaInfo.CEPPreviousResults.Manual) MANUAL" -ForegroundColor Gray
        Write-Host "    (Run with -CEP Test to compare current CE+ test results)" -ForegroundColor DarkGray
    }

    # Exemption delta
    if ($DeltaInfo.CurrExTotal -gt 0 -or $DeltaInfo.PrevExTotal -gt 0) {
        $exSign = if ($DeltaInfo.ExTotalDelta -gt 0) { "+$($DeltaInfo.ExTotalDelta)" } elseif ($DeltaInfo.ExTotalDelta -lt 0) { "$($DeltaInfo.ExTotalDelta)" } else { "0" }
        Write-Host ""
        Write-Host "  📋 EXEMPTIONS: $($DeltaInfo.CurrExTotal) total ($exSign) | $($DeltaInfo.CurrExActive) active" -ForegroundColor Cyan

        if ($DeltaInfo.NewExemptions.Count -gt 0) {
            Write-Host "    ➕ $($DeltaInfo.NewExemptions.Count) new:" -ForegroundColor Green
            foreach ($ne in ($DeltaInfo.NewExemptions | Select-Object -First 5)) {
                $dn = if ($ne.'Display Name'.Length -gt 55) { $ne.'Display Name'.Substring(0, 52) + '...' } else { $ne.'Display Name' }
                Write-Host "      + $dn" -NoNewline -ForegroundColor Green
                Write-Host " [$($ne.'Category') | $($ne.'Scope Name')]" -ForegroundColor DarkGray
            }
            if ($DeltaInfo.NewExemptions.Count -gt 5) { Write-Host "      ... and $($DeltaInfo.NewExemptions.Count - 5) more" -ForegroundColor DarkGray }
        }

        if ($DeltaInfo.RemovedExemptions.Count -gt 0) {
            Write-Host "    ➖ $($DeltaInfo.RemovedExemptions.Count) removed:" -ForegroundColor Red
            foreach ($re in ($DeltaInfo.RemovedExemptions | Select-Object -First 5)) {
                $dn = if ($re.displayName.Length -gt 55) { $re.displayName.Substring(0, 52) + '...' } else { $re.displayName }
                Write-Host "      - $dn" -NoNewline -ForegroundColor Red
                Write-Host " [$($re.category) | $($re.scopeName)]" -ForegroundColor DarkGray
            }
            if ($DeltaInfo.RemovedExemptions.Count -gt 5) { Write-Host "      ... and $($DeltaInfo.RemovedExemptions.Count - 5) more" -ForegroundColor DarkGray }
        }
    }

    Write-Host ""
    $trendIcon = switch ($DeltaInfo.Trend) { 'IMPROVING' { '📈' }; 'DEGRADING' { '📉' }; 'STABLE' { '➡️ ' }; default { '↔️ ' } }
    $trendColor = switch ($DeltaInfo.Trend) { 'IMPROVING' { 'Green' }; 'DEGRADING' { 'Red' }; default { 'Yellow' } }
    Write-Host "  POSTURE TREND: $trendIcon $($DeltaInfo.Trend)" -ForegroundColor $trendColor

    if ($DeltaInfo.NewAssignments.Count -eq 0 -and $DeltaInfo.RemovedAssignments.Count -eq 0 -and $DeltaInfo.ChangedAssignments.Count -eq 0) {
        Write-Host "  No changes detected between snapshots." -ForegroundColor Green
    }

    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
}


# Helper: extract rows from Search-AzGraph PSResourceGraphResponse wrapper
function Expand-AzGraphResult {
    param([Parameter(ValueFromPipeline)]$InputObject)
    process {
        if ($null -eq $InputObject) { return }
        foreach ($row in $InputObject) { $row }
    }
}

function ConvertTo-ALZParameterSignature {
    param($Parameters)

    if ($null -eq $Parameters) { return '' }
    $parameterObject = $Parameters
    if ($Parameters -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Parameters)) { return '' }
        try { $parameterObject = $Parameters | ConvertFrom-Json -AsHashtable -ErrorAction Stop } catch { return $Parameters.Trim() }
    }

    function ConvertTo-OrderedALZValue {
        param($Value)
        if ($Value -is [System.Collections.IDictionary]) {
            $orderedValue = [ordered]@{}
            foreach ($key in @($Value.Keys | Sort-Object)) {
                $orderedValue[[string]$key] = ConvertTo-OrderedALZValue -Value $Value[$key]
            }
            return $orderedValue
        }
        if ($Value -is [PSCustomObject]) {
            $orderedValue = [ordered]@{}
            foreach ($property in @($Value.PSObject.Properties | Sort-Object Name)) {
                $orderedValue[$property.Name] = ConvertTo-OrderedALZValue -Value $property.Value
            }
            return $orderedValue
        }
        if ($Value -is [array]) { return @($Value | ForEach-Object { ConvertTo-OrderedALZValue -Value $_ }) }
        return $Value
    }

    (ConvertTo-OrderedALZValue -Value $parameterObject) | ConvertTo-Json -Depth 30 -Compress
}

function Test-ALZParameterCompatibility {
    param($ExpectedParameters, $AssignmentParameters)

    $expectedSignature = ConvertTo-ALZParameterSignature -Parameters $ExpectedParameters
    if (-not $expectedSignature -or $expectedSignature -eq '{}') { return $true }
    $assignmentSignature = ConvertTo-ALZParameterSignature -Parameters $AssignmentParameters
    if (-not $assignmentSignature) { return $false }
    $expectedSignature -eq $assignmentSignature
}

# Function to get Azure Landing Zone recommended policies from GitHub
function Get-ALZRecommendedPolicies {
    param(
        [string]$ALZVersion = 'latest'
    )
    
    Write-Host "  Fetching Azure Landing Zone recommended policies from official ALZ Library..." -ForegroundColor Gray
    
    try {
        $repositoryApiUrl = 'https://api.github.com/repos/Azure/Azure-Landing-Zones-Library'
        $headers = @{
            'Accept' = 'application/vnd.github.v3+json'
            'User-Agent' = 'PowerShell-AzurePolicyAssessment'
        }

        if ($ALZVersion -eq 'latest') {
            Write-Host "    Resolving latest official ALZ Library release..." -ForegroundColor Gray
            $release = Invoke-RestMethod -Uri "$repositoryApiUrl/releases/latest" -Headers $headers -Method Get -TimeoutSec 15 -ErrorAction Stop
            $resolvedVersion = $release.tag_name
            $archiveUrl = $release.zipball_url
        } else {
            $resolvedVersion = $ALZVersion
            $archiveUrl = "$repositoryApiUrl/zipball/$([uri]::EscapeDataString($ALZVersion))"
        }

        $script:ALZSourceVersion = $resolvedVersion
        $script:ALZSourceRetrievedAt = (Get-Date).ToUniversalTime().ToString('o')
        $script:ALZPolicyDefinitionIds = @{}
        $script:ALZAssets = [System.Collections.Generic.List[object]]::new()
        Write-Host "    Downloading ALZ Library $resolvedVersion..." -ForegroundColor Gray

        $archivePath = Join-Path ([System.IO.Path]::GetTempPath()) "alz-library-$([guid]::NewGuid().ToString('N')).zip"
        $extractPath = "$archivePath.extracted"
        try {
            Invoke-WebRequest -Uri $archiveUrl -Headers $headers -OutFile $archivePath -TimeoutSec 30 -ErrorAction Stop
            Expand-Archive -Path $archivePath -DestinationPath $extractPath -Force
            $policyFiles = @(Get-ChildItem -Path $extractPath -Filter '*.alz_policy_assignment.json' -Recurse -File |
                Where-Object { $_.FullName -match '[\\/]platform[\\/]alz[\\/]policy_assignments[\\/]' })
        } finally {
            if (Test-Path $archivePath) { Remove-Item $archivePath -Force -ErrorAction SilentlyContinue }
        }
        
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
            if ($file.Name -match '\.alz_policy_assignment\.json$') {
                # Extract policy name from filename (e.g., Deny-IP-forwarding.alz_policy_assignment.json -> Deny-IP-forwarding)
                $policyName = $file.Name -replace '\.alz_policy_assignment\.json$', ''

                try {
                    $assignmentDefinition = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json -Depth 30
                    $definitionId = "$($assignmentDefinition.properties.policyDefinitionId)".ToLowerInvariant()
                    if ($definitionId) { $script:ALZPolicyDefinitionIds[$policyName] = $definitionId }
                    $relativePath = $file.FullName.Substring($extractPath.Length).TrimStart('\', '/')
                    $archetype = if ($assignmentDefinition.properties.metadata.archetype) {
                        [string]$assignmentDefinition.properties.metadata.archetype
                    } elseif ($relativePath -match '(?i)[\\/]archetypes[\\/]([^\\/]+)') {
                        $Matches[1]
                    } else { '' }
                    [void]$script:ALZAssets.Add([PSCustomObject][ordered]@{
                        AssetName = $policyName
                        DefinitionId = $definitionId
                        Parameters = $assignmentDefinition.properties.parameters
                        ParameterSignature = ConvertTo-ALZParameterSignature -Parameters $assignmentDefinition.properties.parameters
                        Archetype = $archetype
                        SourcePath = $relativePath
                    })
                } catch {
                    Write-Verbose "Unable to read ALZ assignment '$($file.Name)': $($_.Exception.Message)"
                }
                
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
        $script:ALZAssets = @($script:ALZAssets |
            Group-Object { "$($_.AssetName)|$($_.DefinitionId)|$($_.ParameterSignature)|$($_.Archetype)" } |
            ForEach-Object { $_.Group | Select-Object -First 1 })
        
        Write-Host "    Successfully retrieved $totalFound policy recommendations from ALZ Library ($resolvedVersion)" -ForegroundColor Green
        return $discoveredPolicies
    }
    catch {
        Write-Host "    Error fetching from ALZ Library: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Using static fallback list..." -ForegroundColor Yellow
        $script:ALZSourceVersion = 'static-fallback'
        $script:ALZSourceRetrievedAt = (Get-Date).ToUniversalTime().ToString('o')
        $script:ALZPolicyDefinitionIds = @{}
        $script:ALZAssets = @()
        return Get-FallbackALZPolicies
    }
    finally {
        if ($extractPath -and (Test-Path $extractPath)) { Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue }
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

function New-DataQuality {
    param(
        [Parameter(Mandatory)][string]$QueryName,
        [Parameter(Mandatory)][bool]$QuerySucceeded,
        [int]$RecordCount = 0,
        [datetime]$Timestamp = [datetime]::UtcNow,
        [bool]$FallbackUsed = $false,
        [string]$ErrorMessage = ''
    )

    $query = [PSCustomObject]@{
        Name         = $QueryName
        Succeeded    = $QuerySucceeded
        Records      = [math]::Max(0, $RecordCount)
        Timestamp    = $Timestamp.ToUniversalTime().ToString('o')
        FallbackUsed = $FallbackUsed
        Error        = if ($QuerySucceeded) { '' } else { $ErrorMessage }
    }

    [PSCustomObject]@{
        SuccessfulQueries = @($query | Where-Object Succeeded)
        FailedQueries     = @($query | Where-Object { -not $_.Succeeded })
        TotalRecords      = $query.Records
        Timestamp         = $query.Timestamp
        FallbackUsed      = $FallbackUsed
        Queries           = @($query)
    }
}

function Resolve-ComplianceAssessmentState {
    param(
        [Parameter(Mandatory)][bool]$QuerySucceeded,
        [int]$QueryRecordCount = 0,
        [int]$EvaluatedResources = 0,
        [int]$CompliantResources = 0,
        [int]$NonCompliantResources = 0,
        [string]$QueryName = 'PolicyStates',
        [datetime]$Timestamp = [datetime]::UtcNow,
        [bool]$FallbackUsed = $false,
        [string]$ErrorMessage = ''
    )

    $state = if (-not $QuerySucceeded) {
        'DataUnavailable'
    } elseif ($EvaluatedResources -le 0) {
        'NotEvaluated'
    } elseif ($NonCompliantResources -gt 0) {
        'EvaluatedNonCompliant'
    } else {
        'EvaluatedCompliant'
    }

    [PSCustomObject]@{
        State                 = $state
        EvaluatedResources    = [math]::Max(0, $EvaluatedResources)
        CompliantResources    = [math]::Max(0, $CompliantResources)
        NonCompliantResources = [math]::Max(0, $NonCompliantResources)
        DataQuality           = New-DataQuality `
            -QueryName $QueryName `
            -QuerySucceeded $QuerySucceeded `
            -RecordCount $QueryRecordCount `
            -Timestamp $Timestamp `
            -FallbackUsed $FallbackUsed `
            -ErrorMessage $ErrorMessage
    }
}

function Resolve-QuickAssessmentPosture {
    param(
        [Parameter(Mandatory)][ValidateSet('DataUnavailable', 'NotEvaluated', 'EvaluatedCompliant', 'EvaluatedNonCompliant')][string]$ComplianceState,
        [int]$HighRiskPolicyCount = 0,
        [int]$HighSecurityDoNotEnforceCount = 0,
        [int]$NonCompliantObservationCount = 0,
        [int]$AuditOnlyCount = 0
    )

    if ($ComplianceState -eq 'DataUnavailable') { return '⚪ Data Unavailable' }
    if ($ComplianceState -eq 'NotEvaluated') { return '⚪ Not Evaluated' }
    if ($HighRiskPolicyCount -eq 0 -and $NonCompliantObservationCount -eq 0 -and $AuditOnlyCount -eq 0) { return '✅ Excellent' }
    if ($HighSecurityDoNotEnforceCount -eq 0 -and $NonCompliantObservationCount -le 10) { return '🟢 Good' }
    if ($HighRiskPolicyCount -le 5 -and $NonCompliantObservationCount -le 50) { return '🟠 Needs Improvement' }
    '🔴 At Risk'
}

function Resolve-EffectivePolicyEffects {
    param(
        [AllowNull()]$Effect,
        [AllowNull()]$AssignmentParameters
    )

    $canonicalEffects = @{
        'append'            = 'Append'
        'audit'             = 'Audit'
        'auditifnotexists'  = 'AuditIfNotExists'
        'deny'              = 'Deny'
        'denyaction'        = 'DenyAction'
        'deployifnotexists' = 'DeployIfNotExists'
        'dine'              = 'DeployIfNotExists'
        'disabled'          = 'Disabled'
        'manual'            = 'Manual'
        'modify'            = 'Modify'
        'parameterised'     = 'Parameterised'
        'parameterized'     = 'Parameterised'
    }
    $effectPriority = @(
        'Deny', 'DenyAction', 'DeployIfNotExists', 'Modify',
        'AuditIfNotExists', 'Audit', 'Append', 'Manual', 'Disabled',
        'Parameterised', 'Unknown'
    )
    $resolvedEffects = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $rawEffect = if ($null -eq $Effect) { '' } else { (@($Effect) -join ', ') }
    $isParameterised = $rawEffect -match '(?i)parameteri[sz]ed|\[\s*parameters\s*\('

    $parameterNames = @([regex]::Matches($rawEffect, '(?i)parameters\s*\(\s*[''"]([^''"]+)[''"]\s*\)') |
        ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $parameterObject = $AssignmentParameters
    if ($AssignmentParameters -is [string] -and -not [string]::IsNullOrWhiteSpace($AssignmentParameters)) {
        try { $parameterObject = $AssignmentParameters | ConvertFrom-Json -ErrorAction Stop } catch { $parameterObject = $null }
    }

    if ($parameterObject -and $parameterNames.Count -eq 0 -and $isParameterised) {
        $parameterNames = @($parameterObject.PSObject.Properties.Name | Where-Object { $_ -match '(?i)effect' })
        if ($parameterObject -is [System.Collections.IDictionary]) {
            $parameterNames = @($parameterObject.Keys | Where-Object { $_ -match '(?i)effect' })
        }
    }

    foreach ($parameterName in $parameterNames) {
        $parameterEntry = if ($parameterObject -is [System.Collections.IDictionary]) {
            $parameterObject[$parameterName]
        } elseif ($parameterObject) {
            $property = $parameterObject.PSObject.Properties[$parameterName]
            if ($property) { $property.Value }
        }
        $parameterValue = if ($parameterEntry -is [System.Collections.IDictionary] -and $parameterEntry.Contains('value')) {
            $parameterEntry['value']
        } elseif ($parameterEntry -and $parameterEntry.PSObject.Properties['value']) {
            $parameterEntry.value
        } else {
            $parameterEntry
        }
        foreach ($value in @($parameterValue)) {
            $key = "$value".Trim().ToLowerInvariant()
            if ($canonicalEffects.ContainsKey($key)) { [void]$resolvedEffects.Add($canonicalEffects[$key]) }
        }
    }

    $effectPattern = '(?i)(DeployIfNotExists|AuditIfNotExists|DenyAction|Parameterised|Parameterized|Disabled|Modify|Append|Manual|DINE|Deny|Audit)'
    foreach ($match in [regex]::Matches($rawEffect, $effectPattern)) {
        $key = $match.Value.ToLowerInvariant()
        $canonical = $canonicalEffects[$key]
        if ($canonical -eq 'Parameterised' -and $parameterNames.Count -gt 0 -and $resolvedEffects.Count -gt 0) { continue }
        [void]$resolvedEffects.Add($canonical)
    }

    if ($resolvedEffects.Count -eq 0) {
        [void]$resolvedEffects.Add($(if ($isParameterised) { 'Parameterised' } else { 'Unknown' }))
    }

    $effectiveEffects = @($effectPriority | Where-Object { $resolvedEffects.Contains($_) })
    $primaryEffect = $effectiveEffects | Select-Object -First 1

    [PSCustomObject]@{
        EffectiveEffects = $effectiveEffects
        PrimaryEffect    = $primaryEffect
        IsPreventive     = @($effectiveEffects | Where-Object { $_ -in @('Deny', 'DenyAction') }).Count -gt 0
        IsDetective      = @($effectiveEffects | Where-Object { $_ -in @('Audit', 'AuditIfNotExists', 'Manual') }).Count -gt 0
        IsRemediating    = @($effectiveEffects | Where-Object { $_ -in @('DeployIfNotExists', 'Modify') }).Count -gt 0
        IsParameterised  = $isParameterised
        IsDisabled       = $effectiveEffects.Count -gt 0 -and @($effectiveEffects | Where-Object { $_ -ne 'Disabled' }).Count -eq 0
    }
}

function Get-EffectivePolicyEffectCounts {
    param([Parameter(Mandatory)][array]$PolicyResults)

    $normalizedAssignments = @($PolicyResults | ForEach-Object {
        $effectiveEffectsProperty = $_.PSObject.Properties['Effective Effects']
        if (-not $effectiveEffectsProperty) { $effectiveEffectsProperty = $_.PSObject.Properties['effectiveEffects'] }
        $effectiveEffects = if ($effectiveEffectsProperty -and @($effectiveEffectsProperty.Value).Count -gt 0) {
            @($effectiveEffectsProperty.Value)
        } else {
            $rawEffectProperty = $_.PSObject.Properties['Effect Type']
            if (-not $rawEffectProperty) { $rawEffectProperty = $_.PSObject.Properties['effectType'] }
            @((Resolve-EffectivePolicyEffects -Effect $(if ($rawEffectProperty) { $rawEffectProperty.Value } else { $null })).EffectiveEffects)
        }

        [PSCustomObject]@{
            Effects       = $effectiveEffects
            IsPreventive  = @($effectiveEffects | Where-Object { $_ -in @('Deny', 'DenyAction') }).Count -gt 0
            IsDetective   = @($effectiveEffects | Where-Object { $_ -in @('Audit', 'AuditIfNotExists', 'Manual') }).Count -gt 0
            IsRemediating = @($effectiveEffects | Where-Object { $_ -in @('DeployIfNotExists', 'Modify') }).Count -gt 0
            IsDisabled    = $effectiveEffects.Count -gt 0 -and @($effectiveEffects | Where-Object { $_ -ne 'Disabled' }).Count -eq 0
        }
    })

    $allEffects = @($normalizedAssignments | ForEach-Object { $_.Effects })
    $breakdown = @($allEffects | Group-Object | Sort-Object Name | ForEach-Object {
        [PSCustomObject]@{ Effect = $_.Name; Count = $_.Count }
    })

    [PSCustomObject]@{
        Deny              = @($normalizedAssignments | Where-Object { $_.Effects -contains 'Deny' -or $_.Effects -contains 'DenyAction' }).Count
        Audit             = @($normalizedAssignments | Where-Object { $_.Effects -contains 'Audit' -or $_.Effects -contains 'AuditIfNotExists' }).Count
        DeployIfNotExists = @($normalizedAssignments | Where-Object { $_.Effects -contains 'DeployIfNotExists' }).Count
        Modify            = @($normalizedAssignments | Where-Object { $_.Effects -contains 'Modify' }).Count
        Remediating       = @($normalizedAssignments | Where-Object IsRemediating).Count
        Disabled          = @($normalizedAssignments | Where-Object IsDisabled).Count
        Breakdown         = $breakdown
    }
}

function New-AssessmentFinding {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)]$Evidence,
        [string[]]$AssignmentIds = @(),
        [string[]]$ScopeIds = @(),
        [Parameter(Mandatory)][string]$Recommendation,
        [string[]]$VerificationSteps = @(),
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][ValidateSet('High', 'Medium', 'Low')][string]$Confidence
    )

    [PSCustomObject][ordered]@{
        Id                = $Id
        Severity          = $Severity
        Category          = $Category
        Title             = $Title
        Evidence          = $Evidence
        AssignmentIds     = @($AssignmentIds | Where-Object { $_ } | Select-Object -Unique)
        ScopeIds          = @($ScopeIds | Where-Object { $_ } | Select-Object -Unique)
        Recommendation    = $Recommendation
        VerificationSteps = @($VerificationSteps)
        Source            = $Source
        Confidence        = $Confidence
    }
}

function Get-AssessmentFindingId {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Identity
    )

    $prefix = ($Category -replace '[^A-Za-z0-9]', '').ToUpperInvariant()
    if ($prefix.Length -gt 8) { $prefix = $prefix.Substring(0, 8) }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("$Category|$Identity".ToLowerInvariant())
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $suffix = ([System.BitConverter]::ToString($hash) -replace '-', '').Substring(0, 10)
    "F-$prefix-$suffix"
}

function Resolve-RemediationEvidenceState {
    param(
        [Parameter(Mandatory)]$Evidence,
        [bool]$TaskQuerySucceeded,
        [bool]$RoleQuerySucceeded
    )

    $requiredRoles = @($Evidence.RequiredRoles ?? $Evidence.requiredRoles) | Where-Object { $_ }
    $availableRoles = @($Evidence.AvailableRoles ?? $Evidence.availableRoles) | Where-Object { $_ }
    $availableRoleSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($role in $availableRoles) { [void]$availableRoleSet.Add([string]$role) }
    $missingRoles = if ($RoleQuerySucceeded) { @($requiredRoles | Where-Object { -not $availableRoleSet.Contains([string]$_) }) } else { @() }

    $taskId = [string]($Evidence.TaskId ?? $Evidence.remediationId)
    $taskState = [string]($Evidence.TaskState ?? $Evidence.state)
    $taskError = [string]($Evidence.TaskError ?? $Evidence.error)
    $failedDeployments = [int]($Evidence.FailedDeployments ?? 0)
    $applicableResourceCount = if ($null -ne $Evidence.ApplicableResourceCount) { [Nullable[int]][int]$Evidence.ApplicableResourceCount } else { $null }
    $conditions = [System.Collections.Generic.List[string]]::new()

    if ($RoleQuerySucceeded -and $missingRoles.Count -gt 0) { [void]$conditions.Add('MissingPermissions') }
    if ($TaskQuerySucceeded) {
        if ($taskState -match '^(Failed|Canceled|Cancelled)$' -or $failedDeployments -gt 0 -or $taskError) {
            [void]$conditions.Add('Failed')
        } elseif ($taskState -match '^(Accepted|Running|Evaluating|Pending|InProgress)$') {
            [void]$conditions.Add('Pending')
        } elseif (-not $taskId -and $null -ne $applicableResourceCount -and $applicableResourceCount -gt 0) {
            [void]$conditions.Add('NotStarted')
        }
    }

    $state = if (-not $TaskQuerySucceeded) {
        'NotAssessed'
    } elseif ($conditions.Contains('Failed')) {
        'Failed'
    } elseif ($conditions.Contains('MissingPermissions')) {
        'MissingPermissions'
    } elseif ($conditions.Contains('Pending')) {
        'Pending'
    } elseif ($conditions.Contains('NotStarted')) {
        'NotStarted'
    } elseif ($taskState -match '^(Succeeded|Complete|Completed)$' -and $taskId) {
        'Succeeded'
    } elseif (-not $taskId -and $null -ne $applicableResourceCount -and $applicableResourceCount -eq 0) {
        'NotRequired'
    } else {
        'NotAssessed'
    }

    [PSCustomObject][ordered]@{
        State = $state
        Conditions = @($conditions)
        TaskId = $taskId
        TaskState = $taskState
        TaskError = $taskError
        RequiredRoles = @($requiredRoles)
        AvailableRoles = @($availableRoles)
        MissingRoles = @($missingRoles)
        ApplicableResourceCount = $applicableResourceCount
        LastEvaluation = [string]$Evidence.LastEvaluation
        TaskQuerySucceeded = $TaskQuerySucceeded
        RoleQuerySucceeded = $RoleQuerySucceeded
    }
}

function New-RemediationEvidence {
    param(
        [Parameter(Mandatory)][string]$AssignmentId,
        [string]$Scope = '',
        [string]$IdentityType = 'None',
        [string]$PrincipalId = '',
        [array]$RequiredRoles = @(),
        [array]$RoleAssignments = @(),
        [array]$TaskRecords = @(),
        [bool]$TaskQuerySucceeded,
        [bool]$RoleQuerySucceeded,
        [string]$TaskQueryError = '',
        [string]$RoleQueryError = '',
        [datetime]$EvidenceTimestamp = [datetime]::UtcNow,
        [Nullable[int]]$ApplicableResourceCount = $null,
        [string]$LastEvaluation = '',
        [array]$Exemptions = @(),
        [array]$NotScopes = @(),
        [array]$ResourceSelectors = @(),
        [array]$Overrides = @()
    )

    $normalizedScope = $Scope.TrimEnd('/').ToLowerInvariant()
    $normalizedTaskRecords = @($TaskRecords | Where-Object { $null -ne $_ })
    $normalizedExemptions = @($Exemptions | Where-Object { $null -ne $_ })
    $normalizedNotScopes = @($NotScopes | Where-Object { $null -ne $_ })
    $normalizedResourceSelectors = @($ResourceSelectors | Where-Object { $null -ne $_ })
    $normalizedOverrides = @($Overrides | Where-Object { $null -ne $_ })
    $availableRoles = @($RoleAssignments | Where-Object { $null -ne $_ } | Where-Object {
        $roleScope = [string]$_.Scope
        $principalMatches = -not $PrincipalId -or [string]::Equals([string]$_.PrincipalId, $PrincipalId, [System.StringComparison]::OrdinalIgnoreCase)
        $scopeMatches = -not $normalizedScope -or (-not $roleScope) -or $normalizedScope.StartsWith($roleScope.TrimEnd('/').ToLowerInvariant())
        $principalMatches -and $scopeMatches
    } | ForEach-Object {
        $roleDefinitionId = [string]$_.RoleDefinitionId
        if ($roleDefinitionId -match '/([^/]+)$') { $Matches[1] } else { $roleDefinitionId }
    } | Where-Object { $_ } | Select-Object -Unique)

    $selectedTask = @($normalizedTaskRecords | Sort-Object @{
        Expression = {
            $timestamp = $_.LastUpdated ?? $_.CreatedOn
            if ($timestamp) { try { [datetime]$timestamp } catch { [datetime]::MinValue } } else { [datetime]::MinValue }
        }
        Descending = $true
    } | Select-Object -First 1)
    if ($selectedTask.Count -gt 0) { $selectedTask = $selectedTask[0] } else { $selectedTask = $null }

    $stateEvidence = [PSCustomObject]@{
        TaskId = if ($selectedTask) { [string]$selectedTask.TaskId } else { '' }
        TaskState = if ($selectedTask) { [string]$selectedTask.State } else { '' }
        TaskError = if ($selectedTask) { [string]$selectedTask.Error } else { '' }
        FailedDeployments = if ($selectedTask) { [int]($selectedTask.FailedDeployments ?? 0) } else { 0 }
        RequiredRoles = @($RequiredRoles | ForEach-Object { if ([string]$_ -match '/([^/]+)$') { $Matches[1] } else { [string]$_ } } | Where-Object { $_ } | Select-Object -Unique)
        AvailableRoles = $availableRoles
        ApplicableResourceCount = $ApplicableResourceCount
        LastEvaluation = $LastEvaluation
    }
    $resolvedState = Resolve-RemediationEvidenceState -Evidence $stateEvidence -TaskQuerySucceeded $TaskQuerySucceeded -RoleQuerySucceeded $RoleQuerySucceeded

    [PSCustomObject][ordered]@{
        AssignmentId = $AssignmentId
        State = $resolvedState.State
        Conditions = @($resolvedState.Conditions)
        ManagedIdentityPresent = $IdentityType -and $IdentityType -ne 'None' -and $PrincipalId
        IdentityType = if ($IdentityType) { $IdentityType } else { 'None' }
        PrincipalId = $PrincipalId
        RequiredRoles = @($resolvedState.RequiredRoles)
        AvailableRoles = @($resolvedState.AvailableRoles)
        MissingRoles = @($resolvedState.MissingRoles)
        TaskRecords = $normalizedTaskRecords
        SelectedTaskId = $resolvedState.TaskId
        SelectedTaskState = $resolvedState.TaskState
        Error = $resolvedState.TaskError
        ApplicableResourceCount = $resolvedState.ApplicableResourceCount
        LastEvaluation = $resolvedState.LastEvaluation
        Exemptions = $normalizedExemptions
        NotScopes = $normalizedNotScopes
        ResourceSelectors = $normalizedResourceSelectors
        Overrides = $normalizedOverrides
        TaskQuerySucceeded = $TaskQuerySucceeded
        RoleQuerySucceeded = $RoleQuerySucceeded
        TaskQueryError = $TaskQueryError
        RoleQueryError = $RoleQueryError
        EvidenceTimestamp = $EvidenceTimestamp.ToString('o')
    }
}

function New-AssessmentFindings {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$PolicyResults,
        [hashtable]$ALZData = $null
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($policy in $PolicyResults) {
        $assignmentId = if ($policy.'Assignment ID') { $policy.'Assignment ID' } else { $policy.'Assignment Name' }
        $scopeId = if ($policy.Scope) { $policy.Scope } else { $policy.'Scope Name' }
        $displayName = $policy.'Display Name'
        $ncResources = if ($policy.'Non-Compliant Resources' -match '^\d+$') { [int]$policy.'Non-Compliant Resources' } else { 0 }

        if ($policy.'Enforcement Mode' -eq 'DoNotEnforce' -and $policy.'Security Impact' -in @('High', 'Medium')) {
            $severity = if ($policy.'Security Impact' -eq 'High') { 'Critical' } else { 'High' }
            $id = Get-AssessmentFindingId -Category 'EnforcementGap' -Identity $assignmentId
            $findings.Add((New-AssessmentFinding -Id $id -Severity $severity -Category 'Enforcement Gap' `
                -Title "Enforcement disabled for '$displayName'" `
                -Evidence ([ordered]@{ EnforcementMode = $policy.'Enforcement Mode'; SecurityImpact = $policy.'Security Impact'; Effect = $policy.'Primary Effect'; NonCompliantResources = $ncResources }) `
                -AssignmentIds @($assignmentId) -ScopeIds @($scopeId) `
                -Recommendation "Validate impact, then change '$displayName' from DoNotEnforce to Default enforcement." `
                -VerificationSteps @('Confirm the assignment is intended to enforce its configured effect.', 'Test the change in a controlled scope.', 'Verify the assignment enforcementMode is Default after deployment.') `
                -Source 'Azure Policy assignment inventory' -Confidence 'High'))
        }

        if ($policy.'Cost Exposure' -eq 'High') {
            $id = Get-AssessmentFindingId -Category 'CostExposure' -Identity $assignmentId
            $findings.Add((New-AssessmentFinding -Id $id -Severity 'Medium' -Category 'Cost Exposure' `
                -Title "High cost exposure heuristic for '$displayName'" `
                -Evidence ([ordered]@{ CostExposure = $policy.'Cost Exposure'; Category = $policy.Category; Effects = @($policy.'Effective Effects'); EnforcementMode = $policy.'Enforcement Mode' }) `
                -AssignmentIds @($assignmentId) -ScopeIds @($scopeId) `
                -Recommendation "Review the services deployed or configured by '$displayName' and validate expected cost with official pricing or Cost Management data." `
                -VerificationSteps @('Identify resources deployed or modified by the policy.', 'Validate region and SKU assumptions.', 'Confirm actual cost in Azure Cost Management when available.') `
                -Source 'Deterministic cost-impact heuristic' -Confidence 'Medium'))
        }

        if ($policy.'Is Remediating' -and $policy.'Remediation Evidence') {
            $remediationEvidence = $policy.'Remediation Evidence'
            foreach ($condition in @($remediationEvidence.Conditions)) {
                $findingConfig = switch ($condition) {
                    'NotStarted' {
                        @{
                            Category = 'Remediation Not Started'; Severity = 'Medium'
                            Title = "Remediation not started for '$displayName'"
                            Recommendation = "Create and monitor an approved remediation task for '$displayName'."
                            Verification = @('Confirm applicable resources and exclusions.', 'Create the remediation task.', 'Verify task state and deployment counts after execution.')
                            Source = 'Azure Resource Graph remediation tasks and policy states'
                        }
                    }
                    'Failed' {
                        @{
                            Category = 'Remediation Failed'; Severity = 'High'
                            Title = "Remediation task failed for '$displayName'"
                            Recommendation = "Review the recorded remediation error for '$displayName', correct the cause, and retry with a new or updated task."
                            Verification = @('Review the task error and failed deployment count.', 'Correct permissions, template, or scope issues.', 'Retry and verify a subsequent task reaches Succeeded.')
                            Source = 'Azure Resource Graph remediation task state'
                        }
                    }
                    'Pending' {
                        @{
                            Category = 'Remediation Pending'; Severity = 'Medium'
                            Title = "Remediation task pending for '$displayName'"
                            Recommendation = "Monitor the current remediation task for '$displayName' and investigate only if it stops progressing or records failures."
                            Verification = @('Confirm the latest task state and timestamp.', 'Compare successful, failed, and total deployments.', 'Recheck policy state after task completion.')
                            Source = 'Azure Resource Graph remediation task state'
                        }
                    }
                    'MissingPermissions' {
                        @{
                            Category = 'Remediation Permissions'; Severity = 'High'
                            Title = "Required remediation roles missing for '$displayName'"
                            Recommendation = "Grant the assignment managed identity only the required missing roles at an applicable scope for '$displayName'."
                            Verification = @('Confirm the assignment principal ID.', 'Validate each required role definition against effective role assignments.', 'Re-run evidence collection after role propagation.')
                            Source = 'Azure Resource Graph policy definitions and role assignments'
                        }
                    }
                }
                if (-not $findingConfig) { continue }
                $id = Get-AssessmentFindingId -Category $findingConfig.Category -Identity $assignmentId
                $findings.Add((New-AssessmentFinding -Id $id -Severity $findingConfig.Severity -Category $findingConfig.Category `
                    -Title $findingConfig.Title `
                    -Evidence ([ordered]@{
                        State = $remediationEvidence.State
                        TaskId = $remediationEvidence.SelectedTaskId
                        TaskState = $remediationEvidence.SelectedTaskState
                        Error = $remediationEvidence.Error
                        ApplicableResources = $remediationEvidence.ApplicableResourceCount
                        LastEvaluation = $remediationEvidence.LastEvaluation
                        RequiredRoles = @($remediationEvidence.RequiredRoles)
                        AvailableRoles = @($remediationEvidence.AvailableRoles)
                        MissingRoles = @($remediationEvidence.MissingRoles)
                        Exemptions = @($remediationEvidence.Exemptions)
                        NotScopes = @($remediationEvidence.NotScopes)
                        ResourceSelectors = @($remediationEvidence.ResourceSelectors)
                        Overrides = @($remediationEvidence.Overrides)
                    }) `
                    -AssignmentIds @($assignmentId) -ScopeIds @($scopeId) `
                    -Recommendation $findingConfig.Recommendation -VerificationSteps $findingConfig.Verification `
                    -Source $findingConfig.Source -Confidence 'High'))
            }

            if ($remediationEvidence.State -eq 'NotAssessed' -and $ncResources -gt 0) {
                $id = Get-AssessmentFindingId -Category 'RemediationEvidence' -Identity $assignmentId
                $findings.Add((New-AssessmentFinding -Id $id -Severity 'Medium' -Category 'Remediation Evidence' `
                    -Title "Remediation state not assessed for '$displayName'" `
                    -Evidence ([ordered]@{
                        State = 'NotAssessed'
                        TaskQuerySucceeded = $remediationEvidence.TaskQuerySucceeded
                        RoleQuerySucceeded = $remediationEvidence.RoleQuerySucceeded
                        TaskQueryError = $remediationEvidence.TaskQueryError
                        RoleQueryError = $remediationEvidence.RoleQueryError
                        ApplicableResources = $remediationEvidence.ApplicableResourceCount
                        LastEvaluation = $remediationEvidence.LastEvaluation
                    }) `
                    -AssignmentIds @($assignmentId) -ScopeIds @($scopeId) `
                    -Recommendation "Restore remediation task and role evidence collection before classifying '$displayName' as working or failed." `
                    -VerificationSteps @('Review ARG query errors and permissions.', 'Re-run task and role evidence queries.', 'Classify remediation only after explicit evidence is available.') `
                    -Source 'Remediation evidence data quality' -Confidence 'High'))
            }
        }

        if ($ncResources -gt 0) {
            $severity = if ($policy.'Risk Level' -eq 'High' -or $ncResources -gt 50) { 'Critical' } else { 'High' }
            $id = Get-AssessmentFindingId -Category 'ActiveNonCompliance' -Identity $assignmentId
            $findings.Add((New-AssessmentFinding -Id $id -Severity $severity -Category 'Non-Compliance' `
                -Title "$ncResources non-compliant resources for '$displayName'" `
                -Evidence ([ordered]@{ NonCompliantResources = $ncResources; RiskLevel = $policy.'Risk Level'; ComplianceState = $policy.'Compliance State' }) `
                -AssignmentIds @($assignmentId) -ScopeIds @($scopeId) `
                -Recommendation "Remediate the $ncResources non-compliant resources for '$displayName'." `
                -VerificationSteps @('Review the non-compliant resource list.', 'Apply the approved remediation.', 'Confirm a subsequent policy evaluation reports the expected state.') `
                -Source 'Azure Policy compliance state' -Confidence 'High'))
        }

        if ($policy.'Is Disabled') {
            $id = Get-AssessmentFindingId -Category 'DisabledPolicy' -Identity $assignmentId
            $findings.Add((New-AssessmentFinding -Id $id -Severity 'Low' -Category 'Housekeeping' `
                -Title "Disabled policy '$displayName'" `
                -Evidence ([ordered]@{ IsDisabled = $true; Effect = $policy.'Primary Effect' }) `
                -AssignmentIds @($assignmentId) -ScopeIds @($scopeId) `
                -Recommendation "Review disabled policy '$displayName' and remove it if it is no longer required." `
                -VerificationSteps @('Confirm the business owner and intended state.', 'Remove or re-enable the assignment.', 'Verify the policy inventory after the change.') `
                -Source 'Azure Policy assignment inventory' -Confidence 'High'))
        }
    }

    $PolicyResults | Group-Object Scope | ForEach-Object {
        $scopeResults = @($_.Group)
        if ((Get-EffectivePolicyEffectCounts -PolicyResults $scopeResults).Deny -eq 0) {
            $scopeId = if ($_.Name) { $_.Name } else { $scopeResults[0].'Scope Name' }
            $assignmentIds = @($scopeResults | ForEach-Object { if ($_.'Assignment ID') { $_.'Assignment ID' } else { $_.'Assignment Name' } })
            $id = Get-AssessmentFindingId -Category 'MissingPreventiveControl' -Identity $scopeId
            $findings.Add((New-AssessmentFinding -Id $id -Severity 'Medium' -Category 'Missing Controls' `
                -Title "No directly assigned Deny effect detected at '$($scopeResults[0].'Scope Name')'" `
                -Evidence ([ordered]@{ DirectAssignmentCount = $scopeResults.Count; DirectPreventiveCount = 0; ScopeName = $scopeResults[0].'Scope Name'; InheritedCoverageEvaluated = $false }) `
                -AssignmentIds $assignmentIds -ScopeIds @($scopeId) `
                -Recommendation "Verify inherited Deny coverage at '$($scopeResults[0].'Scope Name')', then assess whether a direct preventive assignment is required." `
                -VerificationSteps @('Review inherited and directly assigned preventive controls.', 'Confirm which Deny controls are applicable.', 'Verify effective assignments after deployment.') `
                -Source 'Direct assignment inventory and normalized effects' -Confidence 'Medium'))
        }
    }

    if ($ALZData -and $ALZData.MissingPolicies) {
        $ALZData.MissingPolicies | Group-Object Category | ForEach-Object {
            $id = Get-AssessmentFindingId -Category 'ALZInventoryGap' -Identity $_.Name
            $assetNoun = if ($_.Count -eq 1) { 'asset' } else { 'assets' }
            $findings.Add((New-AssessmentFinding -Id $id -Severity 'High' -Category 'ALZ Inventory' `
                -Title "$($_.Count) applicable ALZ $assetNoun not detected in '$($_.Name)'" `
                -Evidence ([ordered]@{ ApplicableGapAssets = @($_.Group.PolicyPattern); Count = $_.Count; SourceVersion = $ALZData.SourceVersion; SourceRetrievedAt = $ALZData.SourceRetrievedAt }) `
                -ScopeIds @('Tenant-wide') `
                -Recommendation "Review and deploy or document an approved exception for the applicable ALZ assets in '$($_.Name)'." `
                -VerificationSteps @('Confirm the ALZ source version and retrieval timestamp.', 'Reconfirm asset applicability and parameters.', 'Verify effective assignments for applicable assets.') `
                -Source 'Official ALZ Library inventory comparison' -Confidence 'Medium'))
        }
    }

    @($findings | Sort-Object Id -Unique)
}

function New-CEPAssessmentFindings {
    param(
        [Parameter(Mandatory)]$CEPAssessment,
        [array]$CEPTestResults = @()
    )

    if (-not $CEPAssessment.Requested) { return @() }

    $findings = [System.Collections.Generic.List[object]]::new()

    if ($CEPAssessment.State -eq 'PrerequisiteUnavailable' -or $CEPAssessment.MappingState -eq 'Unavailable') {
        $reason = if ($CEPAssessment.PrerequisiteReason) { $CEPAssessment.PrerequisiteReason } else { 'CE initiative definition unavailable' }
        $id = Get-AssessmentFindingId -Category 'CEP Prerequisite' -Identity "$($CEPAssessment.MappingState)|$reason"
        $findings.Add((New-AssessmentFinding -Id $id -Severity 'Medium' -Category 'CEP Prerequisite' `
            -Title 'CE policy mapping prerequisite unavailable' `
            -Evidence ([ordered]@{
                Fact = $reason
                Interpretation = 'Policy-based CE mapping is unavailable; this is not a failed security control.'
                AssessmentState = $CEPAssessment.State
                MappingState = $CEPAssessment.MappingState
                MappingSourceState = $CEPAssessment.MappingSourceState
                ConfiguredDefinitionId = $CEPAssessment.DefinitionId
                ConfiguredDefinitionVersion = $CEPAssessment.DefinitionVersion
                CandidateDefinitions = @($CEPAssessment.CandidateDefinitions)
                ScoreState = $CEPAssessment.ScoreState
            }) `
            -ScopeIds @('Tenant-wide') `
            -Recommendation 'Select a supported mapping source or configure an explicit CE initiative definition ID.' `
            -VerificationSteps @('Check current built-in policy set definitions.', 'Verify Microsoft.Authorization provider and query availability.', 'Confirm the supported CE mapping source and definition ID.') `
            -Source 'Azure Policy built-in definition discovery' -Confidence 'Medium'))
    }

    $technicalFindings = @($CEPTestResults | Where-Object {
        $_.'Test #' -match '^TC[1-5]$' -and $_.Status -in @('FAIL', 'WARN')
    })
    foreach ($testResult in $technicalFindings) {
        $testId = [string]$testResult.'Test #'
        $testName = [string]$testResult.'Test Name'
        $normalizedTestName = $testName -replace ('(?i)^{0}\s*:\s*' -f [regex]::Escape($testId)), ''
        $status = [string]$testResult.Status
        $assignmentIds = @(@('AssignmentId', 'Assignment ID') | ForEach-Object {
            $property = $testResult.PSObject.Properties[$_]
            if ($property -and $property.Value) { [string]$property.Value }
        })
        $scopeIds = @(@('ScopeId', 'Scope ID', 'Scope') | ForEach-Object {
            $property = $testResult.PSObject.Properties[$_]
            if ($property -and $property.Value) { [string]$property.Value }
        })
        if ($scopeIds.Count -eq 0) { $scopeIds = @('Tenant-wide') }
        $id = Get-AssessmentFindingId -Category 'CEP Technical Control' -Identity "$testId|$status|$testName"
        $findings.Add((New-AssessmentFinding -Id $id -Severity $(if ($status -eq 'FAIL') { 'High' } else { 'Medium' }) -Category 'CEP Technical Control' `
            -Title "$testId`: $normalizedTestName requires review" `
            -Evidence ([ordered]@{
                Fact = "$testId returned $status."
                Interpretation = 'The technical result identifies a potential CE+ control gap within the evidence available to the automated assessment.'
                TestId = $testId
                Status = $status
                Details = $testResult.Details
                NonCompliant = $testResult.'Non-Compliant'
                Compliant = $testResult.Compliant
                TotalResources = $testResult.'Total Resources'
            }) `
            -AssignmentIds $assignmentIds -ScopeIds $scopeIds `
            -Recommendation "Review and remediate the evidence reported by $testId, then rerun the technical assessment." `
            -VerificationSteps @('Review the underlying Azure Resource Graph or Defender evidence.', 'Confirm applicability at the affected assignments and scopes.', 'Rerun the technical check after remediation.') `
            -Source 'NCSC CE+ v3.2 technical assessment mapped to Azure Resource Graph' `
            -Confidence $(if ($status -eq 'FAIL') { 'High' } else { 'Medium' })))
    }

    $skippedResults = @($CEPTestResults | Where-Object Status -eq 'SKIP')
    $dataQualityState = if ($CEPAssessment.DataQuality -and $CEPAssessment.DataQuality.State) { [string]$CEPAssessment.DataQuality.State } else { 'Unknown' }
    if ($CEPAssessment.State -in @('PrerequisiteUnavailable', 'PartiallyEvaluated', 'EvaluationFailed') -or $skippedResults.Count -gt 0 -or $dataQualityState -in @('Partial', 'Unavailable', 'Failed')) {
        $skippedIds = @($skippedResults | ForEach-Object { $_.'Test #' } | Sort-Object -Unique)
        $id = Get-AssessmentFindingId -Category 'CEP Data Quality' -Identity "$($CEPAssessment.State)|$dataQualityState|$($skippedIds -join ',')"
        $findings.Add((New-AssessmentFinding -Id $id -Severity $(if ($CEPAssessment.State -eq 'EvaluationFailed') { 'High' } else { 'Medium' }) -Category 'CEP Data Quality' `
            -Title 'CEP evidence is incomplete or unavailable' `
            -Evidence ([ordered]@{
                Fact = "$($skippedResults.Count) CEP test result(s) were skipped; data quality state is $dataQualityState."
                Interpretation = 'Missing or failed evidence limits the conclusions supported by the CEP assessment.'
                AssessmentState = $CEPAssessment.State
                DataQualityState = $dataQualityState
                SkippedTestIds = $skippedIds
                Limitations = @($CEPAssessment.DataQuality.Limitations)
            }) `
            -ScopeIds @('Tenant-wide') `
            -Recommendation 'Resolve unavailable CEP evidence sources and rerun the affected checks.' `
            -VerificationSteps @('Review skipped test details and data-quality limitations.', 'Verify access to the required Azure data providers.', 'Confirm the rerun returns evaluated evidence.') `
            -Source 'CEP assessment execution and data-quality metadata' `
            -Confidence $(if ($CEPAssessment.State -eq 'EvaluationFailed') { 'High' } else { 'Medium' })))
    }

    $manualResults = @($CEPTestResults | Where-Object Status -eq 'MANUAL')
    if ($manualResults.Count -gt 0) {
        $manualIds = @($manualResults | ForEach-Object { $_.'Test #' } | Sort-Object -Unique)
        $id = Get-AssessmentFindingId -Category 'CEP Manual Verification' -Identity ($manualIds -join ',')
        $findings.Add((New-AssessmentFinding -Id $id -Severity 'Medium' -Category 'CEP Manual Verification' `
            -Title "$($manualResults.Count) CEP checks require manual verification" `
            -Evidence ([ordered]@{
                Fact = "$($manualResults.Count) CE+ test item(s) cannot be verified automatically."
                Interpretation = 'The automated assessment is incomplete until the specified manual procedures are performed and recorded.'
                TestIds = $manualIds
                Tests = @($manualResults | ForEach-Object { $_.'Test Name' })
            }) `
            -ScopeIds @('Tenant-wide') `
            -Recommendation 'Complete and retain evidence for all outstanding CE+ manual verification procedures.' `
            -VerificationSteps @('Perform each listed manual test using the NCSC CE+ procedure.', 'Record assessor, timestamp, scope, and outcome.', 'Attach the retained evidence to the assessment record.') `
            -Source 'NCSC Cyber Essentials Plus v3.2 manual test specification' -Confidence 'High'))
    }

    @($findings | Sort-Object Id -Unique)
}

function ConvertTo-AssessmentActions {
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$AssessmentFindings)

    @($AssessmentFindings | Where-Object { $_.Recommendation } | ForEach-Object {
        $phase = switch ($_.Severity) { 'Critical' { '30-day' }; 'High' { '60-day' }; default { '90-day' } }
        [PSCustomObject]@{
            FindingIds = @($_.Id)
            Priority   = $_.Severity
            Phase      = $phase
            Action     = $_.Recommendation
            Category   = $_.Category
            Effort     = if ($_.Severity -eq 'Critical') { 'Medium' } else { 'Low' }
            Impact     = $_.Title
            Scope      = @($_.ScopeIds) -join ', '
            NCResources = if ($_.Evidence.NonCompliantResources) { [int]$_.Evidence.NonCompliantResources } else { 0 }
        }
    } | Sort-Object @{ Expression = { switch ($_.Priority) { 'Critical' { 0 }; 'High' { 1 }; 'Medium' { 2 }; 'Low' { 3 }; default { 4 } } } }, @{ Expression = { @($_.FindingIds)[0] } })
}

function Resolve-ALZPolicyMatchState {
    param([AllowEmptyCollection()][array]$MatchingAssignments = @())

    if (@($MatchingAssignments | Where-Object { $_.'Enforcement Mode' -eq 'Default' }).Count -gt 0) { return 'Enforced' }
    if (@($MatchingAssignments | Where-Object { $_.'Enforcement Mode' -eq 'DoNotEnforce' }).Count -gt 0) { return 'DoNotEnforce' }
    'Missing'
}

function Resolve-ALZAssetState {
    param(
        [ValidateSet('Enforced', 'DoNotEnforce', 'Missing')][string]$MatchState,
        [Nullable[bool]]$Applicable = $null,
        [bool]$ApplicabilityAssessed = $false
    )

    if ($MatchState -ne 'Missing') { return 'Detected' }
    if (-not $ApplicabilityAssessed) { return 'Applicability not assessed' }
    if ($null -eq $Applicable) { return 'Not detected' }
    if ($Applicable) { return 'Applicable gap' }
    'Not applicable'
}

function Find-ALZMatchingAssignments {
    param(
        [Parameter(Mandatory)][string]$AssetName,
        [string]$OfficialDefinitionId = '',
        $AssetParameters = $null,
        [string]$Archetype = '',
        [int]$SharedDefinitionIdCount = 1,
        [System.Collections.Generic.HashSet[string]]$ConsumedAssignmentKeys = $null,
        [AllowEmptyCollection()][array]$Assignments = @()
    )

    $normalizedDefinitionId = $OfficialDefinitionId.ToLowerInvariant()
    @($Assignments | Where-Object {
        $assignmentKey = if ($_.'Assignment ID') { [string]$_.'Assignment ID' } else { "$($_.'Assignment Name')|$($_.Scope)" }
        if ($ConsumedAssignmentKeys -and $ConsumedAssignmentKeys.Contains($assignmentKey)) { return $false }

        $nameMatches = [string]::Equals([string]$_.'Assignment Name', $AssetName, [System.StringComparison]::OrdinalIgnoreCase)
        if ($nameMatches) { return $true }

        $definitionMatches = $normalizedDefinitionId -and "$($_.'Policy Definition ID')".ToLowerInvariant() -eq $normalizedDefinitionId
        if (-not $definitionMatches) { return $false }

        $parametersMatch = Test-ALZParameterCompatibility -ExpectedParameters $AssetParameters -AssignmentParameters $_.Parameters
        $assignmentArchetype = if ($_.'Archetype') { [string]$_.'Archetype' } elseif ($_.'Scope Name') { [string]$_.'Scope Name' } else { '' }
        $archetypeMatches = -not $Archetype -or ($assignmentArchetype -and [string]::Equals($assignmentArchetype, $Archetype, [System.StringComparison]::OrdinalIgnoreCase))

        $parametersMatch -and $archetypeMatches -and ($SharedDefinitionIdCount -le 1 -or $AssetParameters -or $Archetype)
    })
}

# Function to generate policy recommendations — multi-signal point-based scoring
# ─────────────────────────────────────────────────────────────────────────────
# Methodology:
#   Each dimension (Security, Cost, etc.) accumulates points from multiple
#   independent signals: effect type, category, policy-name keywords, and
#   enforcement mode.  Points are summed and mapped to High / Medium / Low / None
#   via fixed thresholds.  This avoids the "first-match wins" problem of
#   simple if/elseif chains and produces more accurate, repeatable scores.
# ─────────────────────────────────────────────────────────────────────────────
function Get-PolicyRecommendation {
    param(
        [string]$PolicyName,
        [string]$EffectType,
        [string]$EnforcementMode,
        [string]$PolicyType,
        [string]$Category = ''
    )

    $nameLower = $PolicyName.ToLower()

    # ── Keyword detectors (regex against policy display name) ──
    $isSecurityName  = [bool]($nameLower -match 'encrypt|firewall|mfa|multi.?factor|defender|vulnerabilit|threat|malware|antivirus|intrusion|identity|access.?control|authenticat|authori[sz]|certific|tls|ssl|private.?endpoint|private.?link|network.?security|nsg|waf|ddos|key.?vault|secret|credential|password|rbac|privileged|conditional.?access|zero.?trust|secure.?transfer|ip.?restrict|security.?center|asc.?default')
    $isCostName      = [bool]($nameLower -match 'backup|disaster.?recov|log.?analytics|diagnostic|monitor|sentinel|defender|retention|replic|geo.?redundan|premium|workspace|archive|recovery.?vault|security.?center|asc.?default')
    $isLowCostName   = [bool]($nameLower -match '^(require|append|inherit).*(tag)|allowed.?location|resource.?lock|naming|convention|label')
    $isGovernanceName = [bool]($nameLower -match 'regulat|compliance|benchmark|cis |nist |iso.?27|pci|hipaa|soc.?2|fedramp|gdpr')

    # ═══════════════════════════════════════════════════════════════════════
    #  SECURITY IMPACT  — point-based (0–100 scale)
    #  Signals: effect type (±35), category (±15), name keywords (+10),
    #           enforcement mode (×0.7 multiplier)
    # ═══════════════════════════════════════════════════════════════════════
    $secPts = 50  # baseline = Medium

    # 1) Effect type — strongest signal
    switch -Regex ($EffectType) {
        '^Deny$'                { $secPts += 30; break }
        '^DeployIfNotExists$'   { $secPts += 25; break }
        '^Modify$'              { $secPts += 20; break }
        '^AuditIfNotExists$'    { $secPts +=  5; break }
        '^Audit$'               { $secPts +=  0; break }
        '^Disabled$'            { $secPts -= 35; break }
        default {
            # Initiative with summarised effects — look for strongest
            if     ($EffectType -match 'Deny')              { $secPts += 25 }
            elseif ($EffectType -match 'DeployIfNotExists')  { $secPts += 20 }
            elseif ($EffectType -match 'Modify')             { $secPts += 15 }
            elseif ($EffectType -match 'Parameterised|Multiple') {
                # Parameterised initiatives: infer security from category
                if     ($Category -in @('Security Center','Defender for Cloud','Key Vault','Encryption')) { $secPts += 15 }
                elseif ($Category -in @('Network','Identity','Guest Configuration'))                      { $secPts += 10 }
                else                                                                                      { $secPts +=  5 }
            }
        }
    }

    # 2) Category signal
    if     ($Category -in @('Security Center','Defender for Cloud','Key Vault','Encryption')) { $secPts += 15 }
    elseif ($Category -in @('Network','API Management','Identity','Guest Configuration'))    { $secPts += 10 }
    elseif ($Category -in @('Monitoring','Backup','Compute','Storage','SQL','Cosmos DB',
                            'App Service','Kubernetes','Container Registry','Data Factory'))  { $secPts +=  5 }
    elseif ($Category -in @('Tags','General'))                                                { $secPts -= 15 }

    # 3) Name keyword boost
    if ($isSecurityName)  { $secPts += 10 }
    if ($isGovernanceName) { $secPts += 5 }

    # 4) Enforcement modifier — DoNotEnforce reduces impact but does NOT zero it
    #    (the policy still REPORTS violations, so it has security value)
    if ($EnforcementMode -eq 'DoNotEnforce') {
        $secPts = [math]::Max(10, [math]::Floor($secPts * 0.65))
    }

    # 5) Map points → label
    $securityImpact = if     ($secPts -ge 75) { 'High'   }
                      elseif ($secPts -ge 40) { 'Medium' }
                      elseif ($secPts -ge 15) { 'Low'    }
                      else                    { 'None'   }

    # ═══════════════════════════════════════════════════════════════════════
    #  COST EXPOSURE — internal signals mapped to Low/Medium/High
    # ═══════════════════════════════════════════════════════════════════════
    $costPts = 20  # baseline = Low

    # 1) Effect × category matrix
    switch -Regex ($EffectType) {
        '^DeployIfNotExists$' {
            # DINE cost depends heavily on what it deploys
            if     ($Category -in @('Monitoring','Defender for Cloud','Security Center','Backup')) { $costPts += 45 }  # agents, workspaces, vaults
            elseif ($Category -in @('Network','Compute','SQL','Cosmos DB','App Service'))          { $costPts += 30 }  # diagnostics, NICs, configs
            elseif ($Category -in @('Storage','Container Registry','Data Factory'))                { $costPts += 20 }  # storage diagnostics
            else                                                                                   { $costPts += 15 }  # generic DINE
            break
        }
        '^Modify$' {
            # Modify cost depends on what it modifies
            if     ($Category -in @('Tags','General') -or $isLowCostName)                         { $costPts +=  0 }
            elseif ($Category -in @('Network','Compute','Storage'))                                { $costPts += 20 }  # infra property changes
            elseif ($Category -in @('Monitoring','Defender for Cloud','Security Center'))           { $costPts += 15 }  # config changes
            else                                                                                   { $costPts += 10 }  # generic Modify
            break
        }
        '^Deny$' {
            $costPts -= 5   # Deny prevents cost-generating deployments
            break
        }
        '^Audit$|^AuditIfNotExists$' {
            $costPts += 0
            break
        }
        '^Disabled$' {
            $costPts -= 10
            break
        }
        default {
            # Initiative — inspect effect summary
            if     ($EffectType -match 'DeployIfNotExists') { $costPts += 30 }
            elseif ($EffectType -match 'Modify')            { $costPts += 15 }
            elseif ($EffectType -match 'Parameterised|Multiple') {
                # Parameterised initiatives: member effects are parameter-driven,
                # so infer cost from category (Defender/Monitoring deploy agents → real cost)
                if     ($Category -in @('Monitoring','Defender for Cloud','Security Center','Backup')) { $costPts += 30 }
                elseif ($Category -in @('Network','Compute','SQL','App Service','Cosmos DB'))          { $costPts += 15 }
                else                                                                                   { $costPts +=  5 }
            }
        }
    }

    # 2) Name keyword signals
    if ($isCostName -and -not $isLowCostName)  { $costPts += 10 }
    if ($isLowCostName)                         { $costPts -= 10 }

    # 3) Map points → label
    $costImpact = if     ($costPts -ge 55) { 'High'   }
                  elseif ($costPts -ge 30) { 'Medium' }
                  else                     { 'Low'    }

    # ═══════════════════════════════════════════════════════════════════════
    #  COMPLIANCE IMPACT
    # ═══════════════════════════════════════════════════════════════════════
    $complianceImpact = 'Medium'
    if ($PolicyType -eq 'Initiative (Regulatory)' -or $Category -eq 'Regulatory Compliance' -or $isGovernanceName) {
        $complianceImpact = 'High'
    } elseif ($EffectType -eq 'Deny' -or $EffectType -match 'Deny' -or $Category -in @('Security Center','Network','Encryption','Key Vault','Defender for Cloud')) {
        $complianceImpact = 'High'
    } elseif ($EnforcementMode -eq 'DoNotEnforce') {
        $complianceImpact = 'Low'
    }

    # ═══════════════════════════════════════════════════════════════════════
    #  OPERATIONAL OVERHEAD  (effect type + category)
    # ═══════════════════════════════════════════════════════════════════════
    $operationalOverhead = 'Low'
    if ($EffectType -in @('DeployIfNotExists','Modify') -or $EffectType -match 'DeployIfNotExists|Modify') {
        # DINE/Modify on tags/general = low overhead; on infra = high
        if ($Category -in @('Tags','General') -and $EffectType -eq 'Modify') {
            $operationalOverhead = 'Low'
        } else {
            $operationalOverhead = 'High'
        }
    } elseif ($EffectType -eq 'Deny' -or $EffectType -match '^Deny') {
        $operationalOverhead = 'Medium'
    } elseif ($EffectType -match 'Parameterised|Multiple') {
        # Parameterised initiatives: infer overhead from category
        # Defender/Monitoring deploy agents → High; Network/Compute → Medium; Audit-heavy → Low
        if     ($Category -in @('Security Center','Defender for Cloud','Monitoring','Backup','Guest Configuration')) { $operationalOverhead = 'High' }
        elseif ($Category -in @('Network','Compute','SQL','Kubernetes','App Service','Cosmos DB'))                   { $operationalOverhead = 'Medium' }
        elseif ($Category -in @('Regulatory Compliance'))                                                            { $operationalOverhead = 'Medium' }
        else                                                                                                          { $operationalOverhead = 'Low' }
    }

    # ═══════════════════════════════════════════════════════════════════════
    #  RISK LEVEL  — composite of security impact, enforcement, and effect
    # ═══════════════════════════════════════════════════════════════════════
    $riskPts = 0
    # Security impact contribution
    switch ($securityImpact) {
        'High'   { $riskPts += 40 }
        'Medium' { $riskPts += 20 }
        'Low'    { $riskPts += 5  }
    }
    # Enforcement gap penalty
    if ($EnforcementMode -eq 'DoNotEnforce' -and $securityImpact -in @('High','Medium')) {
        $riskPts += 15  # audit-only on important policies = higher risk
    }
    # Active enforcement bonus (reduces risk)
    if ($EnforcementMode -ne 'DoNotEnforce' -and ($EffectType -in @('Deny','DeployIfNotExists','Modify') -or $EffectType -match 'DeployIfNotExists|Modify|Deny')) {
        $riskPts -= 10  # actively enforced = lower risk
    }
    # Disabled penalty
    if ($EffectType -eq 'Disabled') {
        $riskPts += 10  # disabled policy = risk of missing coverage
    }

    $riskLevel = if     ($riskPts -ge 40) { 'High'   }
                 elseif ($riskPts -ge 20) { 'Medium' }
                 else                     { 'Low'    }

    # ═══════════════════════════════════════════════════════════════════════
    #  RECOMMENDATION  — actionable, context-aware text
    # ═══════════════════════════════════════════════════════════════════════
    $recommendation = ''
    if ($EnforcementMode -eq 'DoNotEnforce') {
        if ($EffectType -match '(^|[, (])Deny($|[, )])') {
            $recommendation = "Preventive effect is in DoNotEnforce mode. Validate impact through safe deployment practices before enabling enforcement."
        } elseif ($EffectType -match 'DeployIfNotExists|Modify') {
            $recommendation = "Remediation effect is in DoNotEnforce mode. Review assignment identity and remediation tasks; manual remediation remains available."
        } else {
            $recommendation = "Policy is in DoNotEnforce mode. Azure still evaluates compliance; changing to Default does not turn an Audit effect into Deny."
        }
    } elseif ($EffectType -eq 'Audit' -or $EffectType -eq 'AuditIfNotExists') {
        if ($Category -in @('Security Center','Network','Encryption','Key Vault','Defender for Cloud') -or $isSecurityName) {
            $recommendation = "Security policy in audit mode. Review findings and consider upgrading to Deny or DINE effect."
        } else {
            $recommendation = "Audit policy in place. Review compliance findings regularly."
        }
    } elseif ($EffectType -eq 'Deny') {
        $recommendation = "Preventive control active. Ensure exception process is documented."
    } elseif ($EffectType -eq 'DeployIfNotExists' -or $EffectType -eq 'Modify') {
        if ($costImpact -eq 'High') {
            $recommendation = "A remediating effect is configured with high heuristic cost exposure. Verify task state, deployed resources, official pricing, actual spend, and managed identity permissions."
        } else {
            $recommendation = "A remediating effect is configured. Verify task state, applicable resources, evaluation timing, and managed identity permissions."
        }
    } elseif ($EffectType -eq 'Disabled') {
        $recommendation = "Policy is disabled. Review whether it should be enabled or removed to reduce evaluation overhead."
    } elseif ($EffectType -match 'Parameterised') {
        # Parameterised initiative — provide category-aware recommendation
        if ($Category -in @('Security Center','Defender for Cloud') -and $isCostName) {
            $recommendation = "Defender/Security Center initiative with parameterised effects. Review enabled plans and validate current charges through Azure Cost Management or the Azure Retail Prices API."
        } elseif ($Category -in @('Monitoring','Backup')) {
            $recommendation = "Parameterised initiative deploying monitoring/backup agents. Monitor Log Analytics ingestion costs and verify agent health regularly."
        } elseif ($Category -in @('Regulatory Compliance')) {
            $recommendation = "Regulatory compliance initiative. Review non-compliant findings and map to remediation plans by control group."
        } else {
            $recommendation = "Initiative with parameterised effects. Review member policy effects and ensure parameters are set to the intended enforcement level."
        }
    } elseif ($EffectType -match '\(' -and $EffectType -match ',') {
        $recommendation = "Initiative with mixed effects. Review member policies individually for enforcement gaps."
    } elseif ($EffectType -match 'Multiple') {
        $recommendation = "Initiative with multiple member policies. Check individual policy effects in the initiative definition."
    } else {
        $recommendation = "Review policy effectiveness regularly and adjust as needed."
    }

    return @{
        SecurityImpact      = $securityImpact
        CostImpact          = $costImpact
        ComplianceImpact    = $complianceImpact
        OperationalOverhead = $operationalOverhead
        RiskLevel           = $riskLevel
        Recommendation      = $recommendation
    }
}

# Generate comprehensive professional HTML report with 7 core sections and optional ALZ and delta sections
function Export-HTMLReport {
    param(
        [Parameter()][array]$PolicyResults = @(),
        [hashtable]$ComplianceData = @{},
        $CEPAssessment = $null,
        [array]$CEPExportData = @(),
        [array]$CEPTestResults = @(),
        [array]$CEPPerScopeData = @(),
        [hashtable]$CEPPerScopeGroupData = @{},
        [hashtable]$CEPPerScopeGroupRaw = @{},
        [hashtable]$CEPRefIdToGroupDisplay = @{},
        [array]$NCExportData = @(),
        [array]$ExemptionData = @(),
        [string]$TenantName = '',
        [string]$FilterLabel = '',
        [int]$PolicyCount = 0,
        [int]$InitiativeCount = 0,
        [int]$RegulatoryCount = 0,
        [string]$OutputPath,
        $DataQuality = $null,
        [hashtable]$ALZData = $null,
        [array]$AssessmentFindings = @(),
        [hashtable]$YAMLDeltaData = $null,
        [array]$CostEvidenceRecords = @()
    )

    function ConvertTo-CEPTestHtmlRow {
        param([Parameter(Mandatory)]$TestResult)

        $statusClass = switch ($TestResult.Status) { 'PASS' { 'status-pass' }; 'FAIL' { 'status-fail' }; 'WARN' { 'status-warn' }; 'SKIP' { 'status-skip' }; 'MANUAL' { 'status-manual' }; default { '' } }
        $testId = [string]$TestResult.'Test #'
        $details = [string]$TestResult.Details
        $displayStatus = if ($TestResult.Status -eq 'PASS' -and $testId -match '^TC[1-5]$' -and $details -match '[1-9]\d* manual subtests') { 'AUTOMATED PASS' } else { [string]$TestResult.Status }
        $evidenceType = if ($TestResult.PSObject.Properties['Evidence Type']) { [string]$TestResult.'Evidence Type' } else { '' }
        $evidenceSource = if ($TestResult.PSObject.Properties['Source']) { [string]$TestResult.Source } else { '' }
        $evidenceQuery = if ($TestResult.PSObject.Properties['Query']) { [string]$TestResult.Query } else { '' }
        $hasResourceCounts = ([int]$TestResult.'Non-Compliant' + [int]$TestResult.Compliant + [int]$TestResult.'Total Resources') -gt 0
        $useNotApplicableCounts = $false

        if ($evidenceType -eq 'Automated') {
            $details = "Automated check: $details"
            $useNotApplicableCounts = -not $hasResourceCounts
        } elseif ($testId -match '^TC[1-5]$') {
            $details = "$(if ($hasResourceCounts) { 'Resource evaluation' } else { 'Configuration checks' }): $details"
            $useNotApplicableCounts = -not $hasResourceCounts
        } elseif ($TestResult.Status -eq 'MANUAL') {
            $details = "Manual procedure: $details"
            $useNotApplicableCounts = -not $hasResourceCounts
        } elseif ($TestResult.'Control Group' -eq 'Prerequisites') {
            $details = "Prerequisite check: $details"
            $useNotApplicableCounts = -not $hasResourceCounts
        }

        if ($evidenceSource -or $evidenceQuery) {
            $encodedSource = [System.Net.WebUtility]::HtmlEncode($evidenceSource)
            $encodedQuery = [System.Net.WebUtility]::HtmlEncode($evidenceQuery.Trim())
            $details += "<details class=`"evidence-details`"><summary>Source and query</summary><p><strong>Source:</strong> $encodedSource</p><pre>$encodedQuery</pre></details>"
        }

        $nonCompliantDisplay = if ($useNotApplicableCounts) { 'N/A' } else { $TestResult.'Non-Compliant' }
        $compliantDisplay = if ($useNotApplicableCounts) { 'N/A' } else { $TestResult.Compliant }
        $totalDisplay = if ($useNotApplicableCounts) { 'N/A' } else { $TestResult.'Total Resources' }
        "<tr><td>$testId</td><td>$($TestResult.'Control Group')</td><td>$($TestResult.'Test Name')</td><td><span class=`"badge $statusClass`">$displayStatus</span></td><td>$details</td><td>$nonCompliantDisplay</td><td>$compliantDisplay</td><td>$totalDisplay</td></tr>"
    }

    # ═══════════════════════════════════════════════════════════════
    #  DATA COMPUTATION
    # ═══════════════════════════════════════════════════════════════

    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $assessmentState = if ($DataQuality -and $DataQuality.AssessmentState) { $DataQuality.AssessmentState } else { 'DataUnavailable' }
    $hasEvaluatedCompliance = $assessmentState -in @('EvaluatedCompliant', 'EvaluatedNonCompliant')
    $assessmentStatusLabel = switch ($assessmentState) {
        'EvaluatedCompliant' { 'Evaluated &middot; No non-compliant resources found' }
        'EvaluatedNonCompliant' { 'Evaluated &middot; Non-compliant resources found' }
        'NotEvaluated' { 'Not evaluated' }
        default { 'Data unavailable' }
    }
    $dataQualityLabel = switch ($assessmentState) {
        'EvaluatedCompliant' { 'Evaluated' }
        'EvaluatedNonCompliant' { 'Evaluated' }
        'NotEvaluated' { 'Not evaluated' }
        default { 'Unavailable' }
    }
    $successfulQueryCount = if ($DataQuality) { @($DataQuality.SuccessfulQueries).Count } else { 0 }
    $failedQueryCount = if ($DataQuality) { @($DataQuality.FailedQueries).Count } else { 1 }
    $dataQualityRecords = if ($DataQuality) { $DataQuality.TotalRecords } else { 0 }
    $dataQualityTimestamp = if ($DataQuality) { $DataQuality.Timestamp } else { 'unknown' }
    $dataQualityFallback = if ($DataQuality -and $DataQuality.FallbackUsed) { 'yes' } else { 'no' }
    $totalAssignments = $PolicyResults.Count
    if ($AssessmentFindings.Count -eq 0) {
        $AssessmentFindings = @(New-AssessmentFindings -PolicyResults $PolicyResults -ALZData $ALZData)
    }
    $hasALZSection = $null -ne $ALZData
    $hasDeltaSection = $null -ne $YAMLDeltaData
    $totalSections = 7 + [int]$hasALZSection + [int]$hasDeltaSection
    $costSectionNumber = 6 + [int]$hasALZSection
    $recommendationsSectionNumber = $costSectionNumber + 1
    $deltaSectionNumber = $recommendationsSectionNumber + 1
    $totalNC = if ($NCExportData.Count -gt 0) { ($NCExportData | Select-Object -Property 'Resource ID' -Unique).Count } else { 0 }
    $totalNCEntries = $NCExportData.Count
    $enforcedCount = ($PolicyResults | Where-Object { $_.'Enforcement Mode' -eq 'Default' }).Count
    $auditOnlyCount = ($PolicyResults | Where-Object { $_.'Enforcement Mode' -eq 'DoNotEnforce' }).Count
    $highSecurityCount = ($PolicyResults | Where-Object { $_.'Security Impact' -eq 'High' }).Count
    $highRiskCount = ($PolicyResults | Where-Object { $_.'Risk Level' -eq 'High' }).Count
    $medRiskCount = ($PolicyResults | Where-Object { $_.'Risk Level' -eq 'Medium' }).Count
    $lowRiskCount = ($PolicyResults | Where-Object { $_.'Risk Level' -eq 'Low' }).Count
    $assignmentsWithNC = ($PolicyResults | Where-Object { ($_.'Non-Compliant Resources' -match '^\d+$') -and ([int]$_.'Non-Compliant Resources' -gt 0) }).Count

    # Effect type counts
    $canonicalEffectCounts = Get-EffectivePolicyEffectCounts -PolicyResults $PolicyResults
    $denyCount = $canonicalEffectCounts.Deny
    $auditEffectCount = $canonicalEffectCounts.Audit
    $dineModifyCount = $canonicalEffectCounts.Remediating
    $disabledCount = $canonicalEffectCounts.Disabled

    # Cost & operational impact
    $costHigh = @($AssessmentFindings | Where-Object Category -eq 'Cost Exposure').Count
    $costMedium = @($PolicyResults | Where-Object { $_.'Cost Exposure' -eq 'Medium' }).Count
    $costLow = @($PolicyResults | Where-Object { $_.'Cost Exposure' -eq 'Low' }).Count
    $opsHigh = @($PolicyResults | Where-Object { $_.'Operational Overhead' -eq 'High' }).Count
    $opsMedium = @($PolicyResults | Where-Object { $_.'Operational Overhead' -eq 'Medium' }).Count
    $opsLow = @($PolicyResults | Where-Object { $_.'Operational Overhead' -eq 'Low' }).Count

    # Scope breakdown
    $scopeGroups = $PolicyResults | Group-Object 'Scope Type'
    $mgAssignments = ($scopeGroups | Where-Object { $_.Name -eq 'Management Group' } | ForEach-Object { $_.Count }) | Select-Object -First 1
    $subAssignments = ($scopeGroups | Where-Object { $_.Name -eq 'Subscription' } | ForEach-Object { $_.Count }) | Select-Object -First 1
    $rgAssignments = ($scopeGroups | Where-Object { $_.Name -eq 'Resource Group' } | ForEach-Object { $_.Count }) | Select-Object -First 1
    if (-not $mgAssignments) { $mgAssignments = 0 }
    if (-not $subAssignments) { $subAssignments = 0 }
    if (-not $rgAssignments) { $rgAssignments = 0 }

    $scopeBreakdownRows = ($scopeGroups | ForEach-Object {
        $ncInScope = ($_.Group | Where-Object { ($_.'Non-Compliant Resources' -match '^\d+$') -and ([int]$_.'Non-Compliant Resources' -gt 0) }).Count
        $ncResInScope = ($_.Group | ForEach-Object { if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 } } | Measure-Object -Sum).Sum
        "<tr><td>$($_.Name)</td><td>$($_.Count)</td><td>$ncInScope</td><td class=`"$(if ($ncResInScope -gt 0) { 'nc-bad' } else { 'nc-ok' })`">$ncResInScope</td></tr>"
    }) -join "`n"

    # Effect distribution uses every effective category once per assignment.
    $effectBreakdown = @($canonicalEffectCounts.Breakdown | Sort-Object Count -Descending)
    # Tooltip descriptions for each effect type
    $effectDescriptions = @{
        'Audit' = 'Flags non-compliant resources but does not block them'
        'AuditIfNotExists' = 'Checks for related resource existence; flags if missing'
        'Deny' = 'Blocks non-compliant resource creation or modification'
        'DenyAction' = 'Blocks specific actions on resources (e.g. delete)'
        'DeployIfNotExists' = 'Auto-deploys missing related resources (DINE)'
        'Modify' = 'Adds, updates, or removes properties on existing resources'
        'Disabled' = 'Policy exists but is not evaluated'
        'Manual' = 'Requires manual attestation of compliance'
        'Append' = 'Adds fields to resources during creation/update'
        'Parameterised' = 'Effect is set via an assignment parameter whose effective value could not be resolved'
        '(not specified)' = 'Effect type could not be determined'
    }
    $effectBreakdownRows = ($effectBreakdown | ForEach-Object {
        $effectName = $_.Effect
        $tip = if ($effectDescriptions.ContainsKey($effectName)) { $effectDescriptions[$effectName] } else { '' }
        $nameHtml = if ($tip) { "$effectName <span class=`"col-info`" data-tip=`"$tip`" title=`"$tip`">i</span>" } else { $effectName }
        $pctClass = if ($effectName -eq 'Disabled') { 'warn-text' } else { '' }
        "<tr><td>$nameHtml</td><td>$($_.Count)</td><td class=`"$pctClass`">$([math]::Round(($_.Count / [math]::Max($totalAssignments,1)) * 100))%</td></tr>"
    }) -join "`n"

    # Policy type distribution
    $policyTypeGroups = $PolicyResults | Group-Object 'Policy Type'
    $policyTypeDist = ($policyTypeGroups | ForEach-Object {
        "<tr><td>$($_.Name)</td><td>$($_.Count)</td><td>$([math]::Round(($_.Count / [math]::Max($totalAssignments,1)) * 100))%</td></tr>"
    }) -join "`n"

    # Top 10 NC assignments
    $topNC = $PolicyResults | Where-Object { ($_.'Non-Compliant Resources' -match '^\d+$') -and ([int]$_.'Non-Compliant Resources' -gt 0) } | Sort-Object { [int]$_.'Non-Compliant Resources' } -Descending | Select-Object -First 10
    $topNCRows = ($topNC | ForEach-Object {
        $typeClass = switch ($_.'Policy Type') { 'Initiative (Regulatory)' { 'type-regulatory' }; 'Initiative' { 'type-initiative' }; default { 'type-policy' } }
        "<tr><td>$($_.'Display Name')</td><td><span class=`"badge $typeClass`">$($_.'Policy Type')</span></td><td class=`"nc-bad`">$(if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 })</td><td>$($_.'Scope Name')</td><td>$($_.'Enforcement Mode')</td></tr>"
    }) -join "`n"

    if (-not $CEPAssessment) {
        $CEPAssessment = New-CEPAssessment -Requested $false -State NotRequested
    }

    # ── CE+ Score ──
    $ceScore = $CEPAssessment.Score; $tPass = 0; $tFail = 0; $tWarn = 0; $tSkip = 0; $tManual = 0
    if ($CEPTestResults.Count -gt 0) {
        $technicalVerdicts = @($CEPTestResults | Where-Object { $_.'Test #' -match '^TC[1-5]$' })
        $tPass = @($technicalVerdicts | Where-Object { $_.'Status' -eq 'PASS' }).Count
        $tFail = @($technicalVerdicts | Where-Object { $_.'Status' -eq 'FAIL' }).Count
        $tWarn = @($technicalVerdicts | Where-Object { $_.'Status' -eq 'WARN' }).Count
        $tSkip = @($CEPTestResults | Where-Object { $_.'Status' -eq 'SKIP' }).Count
        $tManual = @($CEPTestResults | Where-Object { $_.'Status' -eq 'MANUAL' }).Count
    }
    $tAutomated = $tPass + $tFail

    $cepDataQualityState = if ($CEPAssessment.DataQuality -and $CEPAssessment.DataQuality.State) { [string]$CEPAssessment.DataQuality.State } else { 'Unknown' }
    $cepConfidence = switch ($CEPAssessment.State) {
        'Evaluated' { if ($cepDataQualityState -eq 'Complete') { 'High' } else { 'Medium' } }
        'PartiallyEvaluated' { 'Medium' }
        default { 'Low' }
    }
    $cepConfidenceClass = switch ($cepConfidence) { 'High' { 'status-pass' }; 'Medium' { 'status-warn' }; default { 'status-skip' } }
    $cepStateClass = switch ($CEPAssessment.State) { 'Evaluated' { 'status-pass' }; 'EvaluationFailed' { 'status-fail' }; 'PartiallyEvaluated' { 'status-warn' }; default { 'status-ne' } }
    $cepMappingClass = switch ($CEPAssessment.MappingState) { 'Available' { 'status-pass' }; 'Failed' { 'status-fail' }; 'Pending' { 'status-warn' }; default { 'status-ne' } }
    $cepScoreClass = if ($CEPAssessment.ScoreState -eq 'Measured') { 'status-pass' } else { 'status-ne' }
    $cepDataQualityClass = switch ($cepDataQualityState) { 'Complete' { 'status-pass' }; 'Failed' { 'status-fail' }; 'Partial' { 'status-warn' }; default { 'status-ne' } }

    $cepPresentation = switch ($CEPAssessment.State) {
        'NotRequested' {
            @{
                Heading = 'CE+ assessment not requested'
                Fact = 'CEP assessment was not requested for this run.'
                Interpretation = 'No CE or CE+ conclusion is available.'
                Verify = 'Review the command parameters if CEP evidence is required.'
                Action = 'Run with -CEP Full to request policy mapping and technical tests.'
            }
        }
        'PrerequisiteUnavailable' {
            @{
                Heading = if ($CEPAssessment.TestState -eq 'PartiallyEvaluated') { 'Assessment partially evaluated' } else { 'Mapping unavailable' }
                Fact = if ($CEPAssessment.PrerequisiteReason) { $CEPAssessment.PrerequisiteReason } else { 'The CE initiative prerequisite was unavailable.' }
                Interpretation = 'Policy-based CE mapping is unavailable; independent CE+ technical checks may still provide partial evidence.'
                Verify = 'Check current built-in policy set definitions, provider availability, and the configured mapping source.'
                Action = 'Select a supported mapping source or configure an explicit definition ID; review the technical results separately.'
            }
        }
        'PartiallyEvaluated' {
            @{
                Heading = 'Assessment partially evaluated'
                Fact = 'Only part of the requested CEP evidence was evaluated.'
                Interpretation = 'Available results are usable only within their stated scope; no complete CE+ conclusion is supported.'
                Verify = 'Review skipped, warning, and manual checks together with data-quality limitations.'
                Action = 'Resolve unavailable queries and complete manual verification before reassessment.'
            }
        }
        'EvaluationFailed' {
            @{
                Heading = 'Evaluation failed'
                Fact = 'A CEP query or runtime operation failed.'
                Interpretation = 'The assessment did not complete and no positive or negative compliance conclusion is supported.'
                Verify = 'Review failed-query evidence and runtime diagnostics in the assessment data quality details.'
                Action = 'Correct the query or runtime failure and rerun the CEP assessment.'
            }
        }
        default {
            @{
                Heading = 'Assessment evaluated'
                Fact = "$tAutomated automated technical verdict(s) were evaluated."
                Interpretation = 'The displayed score is a tool indicator based only on technical PASS and FAIL verdicts.'
                Verify = 'Review policy mapping evidence, technical test details, and any remaining manual checks.'
                Action = 'Address failed controls and retain the evidence for independent assessment.'
            }
        }
    }

    $safeCEPHeading = [System.Web.HttpUtility]::HtmlEncode($cepPresentation.Heading)
    $safeCEPFact = [System.Web.HttpUtility]::HtmlEncode($cepPresentation.Fact)
    $safeCEPInterpretation = [System.Web.HttpUtility]::HtmlEncode($cepPresentation.Interpretation)
    $safeCEPVerify = [System.Web.HttpUtility]::HtmlEncode($cepPresentation.Verify)
    $safeCEPAction = [System.Web.HttpUtility]::HtmlEncode($cepPresentation.Action)
    $cepMappingSourceState = if ($CEPAssessment.MappingSourceState) { [string]$CEPAssessment.MappingSourceState } else { 'NotRequested' }
    $safeCEPDefinitionDisplayName = [System.Web.HttpUtility]::HtmlEncode($CEPAssessment.DefinitionDisplayName)
    $safeCEPDefinitionId = [System.Web.HttpUtility]::HtmlEncode($CEPAssessment.DefinitionId)
    $safeCEPSelectionMethod = [System.Web.HttpUtility]::HtmlEncode($CEPAssessment.SelectionMethod)
    $cepCandidateDefinitions = @($CEPAssessment.CandidateDefinitions)
    $cepCandidatesHtml = if ($cepCandidateDefinitions.Count -gt 0) {
        $candidateItems = $cepCandidateDefinitions | ForEach-Object {
            $candidateName = [System.Web.HttpUtility]::HtmlEncode($_.DisplayName)
            $candidateId = [System.Web.HttpUtility]::HtmlEncode($(if ($_.Id) { $_.Id } else { $_.Name }))
            $candidateVersion = [System.Web.HttpUtility]::HtmlEncode($_.Version)
            "<li><strong>$candidateName</strong><br><span class='text-dim'>ID: $candidateId$(if ($candidateVersion) { " &middot; Definition version: $candidateVersion" })</span></li>"
        }
        "<details><summary>Candidate CE policy set definitions ($($cepCandidateDefinitions.Count))</summary><ul>$($candidateItems -join '')</ul></details>"
    } else { '' }
    $cepSelectedSourceHtml = if ($safeCEPDefinitionDisplayName -or $safeCEPDefinitionId) {
        $cepSourceLabel = if ($cepMappingSourceState -eq 'Available') { 'Mapping source' } else { 'Requested mapping source' }
        "<p><strong>${cepSourceLabel}:</strong> $safeCEPDefinitionDisplayName$(if ($safeCEPDefinitionId) { "<br><span class='text-dim'>ID: $safeCEPDefinitionId</span>" })$(if ($safeCEPSelectionMethod) { "<br><span class='text-dim'>Selected by: $safeCEPSelectionMethod</span>" })</p>"
    } else { '' }
    $cepEvidenceHtml = @"
    <div class="callout callout-info" id="cep-assessment-evidence">
        <span class="callout-icon">&#x2139;&#xFE0F;</span>
        <div>
            <strong>$safeCEPHeading</strong>
            <p>
                <span class="badge $cepStateClass">Assessment: $($CEPAssessment.State)</span>
                <span class="badge $cepMappingClass">Mapping: $($CEPAssessment.MappingState)</span>
                <span class="badge $cepMappingClass">Source: $cepMappingSourceState</span>
                <span class="badge $cepScoreClass">Score: $($CEPAssessment.ScoreState)</span>
                <span class="badge $cepConfidenceClass">Confidence: $cepConfidence</span>
                <span class="badge $cepDataQualityClass">Data quality: $cepDataQualityState</span>
            </p>
            <p><strong>Fact:</strong> $safeCEPFact</p>
            <p><strong>Interpretation:</strong> $safeCEPInterpretation</p>
            <p><strong>Verify:</strong> $safeCEPVerify</p>
            <p><strong>Action:</strong> $safeCEPAction</p>
            $cepSelectedSourceHtml
            $cepCandidatesHtml
        </div>
    </div>
"@

    # ── CE+ Multi-Assignment Detection ──
    # Detect if the Cyber Essentials initiative is assigned at multiple scopes
    $ceMultiAssignmentBanner = ''
    $ceInitiativeAssignments = @($PolicyResults | Where-Object { 
        $_.'Display Name' -like '*Cyber Essentials*' -and $_.'Policy Type' -like '*Initiative*'
    })
    if ($ceInitiativeAssignments.Count -gt 1) {
        $ceEnforcedCount = @($ceInitiativeAssignments | Where-Object { $_.'Enforcement Mode' -ne 'DoNotEnforce' }).Count
        $ceAuditOnlyCount = $ceInitiativeAssignments.Count - $ceEnforcedCount

        # Determine if we have multi-assignment (controls conditional rendering later)
        $isMultiAssignment = $true

        # Build individual collapsible cards — one per scope
        $perScopeCards = ($ceInitiativeAssignments | ForEach-Object {
            $asgn = $_
            $scopeName = $asgn.'Scope Name'
            $scopeType = $asgn.'Scope Type'
            $displayName = $asgn.'Display Name'
            $enfMode = $asgn.'Enforcement Mode'
            $enfClass = if ($enfMode -eq 'DoNotEnforce') { 'status-warn' } else { 'status-pass' }
            $enfLabel = if ($enfMode -eq 'DoNotEnforce') { 'Enforcement disabled' } else { 'Enforced' }
            $enfIcon  = if ($enfMode -eq 'DoNotEnforce') { '&#x26A0;&#xFE0F;' } else { '&#x2705;' }

            # Match per-scope compliance data by display name
            $scopeData = $null
            if ($CEPPerScopeData -and $CEPPerScopeData.Count -gt 0) {
                $scopeData = $CEPPerScopeData | Where-Object { $_.DisplayName -eq $displayName } | Select-Object -First 1
            }

            # Compliance summary for the header badge
            $headerBadge = ''
            $complianceSection = ''
            if ($scopeData) {
                $pct = [int]$scopeData.CompliancePct
                $barColor = if ($pct -ge 90) { '#22c55e' } elseif ($pct -ge 50) { '#f0ad4e' } else { '#dc3545' }
                $headerBadge = "<span style=`"margin-left:10px;font-weight:700;color:${barColor};`">${pct}%</span>"
                $complianceSection = @"
                <details style="margin-top:6px;">
                    <summary style="cursor:pointer;font-size:0.85rem;font-weight:600;">&#x1F4CA; Overall Resource Compliance</summary>
                    <p style="font-size:0.78rem;color:var(--text-dim);margin:4px 0 8px 0;">Unique <strong>Azure resources</strong> evaluated against all policies in this initiative assignment. Each resource is counted once using strictest-state-wins deduplication.</p>
                    <div style="padding:10px 0 4px 0;">
                        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                            <div style="flex:1;background:var(--table-stripe);border-radius:4px;height:18px;overflow:hidden;">
                                <div style="width:${pct}%;height:100%;background:${barColor};border-radius:4px;transition:width .3s;"></div>
                            </div>
                            <span style="font-weight:700;font-size:1.1rem;min-width:48px;text-align:right;color:${barColor};">${pct}%</span>
                        </div>
                        <table style="font-size:0.85rem;width:100%;">
                            <thead><tr><th style="text-align:center;">Compliant</th><th style="text-align:center;color:#dc3545;">Non-Compliant</th><th style="text-align:center;">Exempt</th><th style="text-align:center;">Total Resources</th></tr></thead>
                            <tbody><tr>
                                <td style="text-align:center;color:#22c55e;font-weight:600;">$($scopeData.Compliant)</td>
                                <td style="text-align:center;color:#dc3545;font-weight:600;">$($scopeData.NonCompliant)</td>
                                <td style="text-align:center;">$($scopeData.Exempt)</td>
                                <td style="text-align:center;font-weight:600;">$($scopeData.Total)</td>
                            </tr></tbody>
                        </table>
                    </div>
                </details>
"@
            }

            # ── Control Group Compliance bars per scope (same data as standalone) ──
            $controlGroupSection = ''
            if ($CEPExportData -and $CEPExportData.Count -gt 0) {
                $scopeCeGroups = $CEPExportData | Group-Object 'CE Control Group'
                $totalPoliciesInGroups = $CEPExportData.Count
                $groupBars = ($scopeCeGroups | ForEach-Object {
                    $gName = $_.Name; $gTotal = $_.Count
                    $gCompliant = ($_.Group | Where-Object { $_.'Status' -like '*Compliant*' -and $_.'Status' -notlike '*Non*' }).Count
                    $gNC = ($_.Group | Where-Object { $_.'Status' -like '*Non-Compliant*' }).Count
                    $gNA = ($_.Group | Where-Object { $_.'Status' -eq 'Not Assigned' }).Count
                    $gPct = if ($gTotal -gt 0) { [math]::Round(($gCompliant / $gTotal) * 100) } else { 0 }
                    $gBarClass = if ($gPct -ge 80) { 'bar-green' } elseif ($gPct -ge 50) { 'bar-amber' } else { 'bar-red' }
                    @"
                    <div class="ce-group-card">
                        <div class="ce-group-name">$gName</div>
                        <div class="ce-bar-container"><div class="ce-bar $gBarClass" style="width:${gPct}%"></div></div>
                        <div class="ce-stats">$gCompliant / $gTotal compliant (${gPct}%) $(if ($gNC -gt 0) { "| <span class='nc-bad'>$gNC non-compliant</span>" }) $(if ($gNA -gt 0) { "| <span class='status-na-text'>$gNA not assigned</span>" })</div>
                    </div>
"@
                }) -join "`n"
                $controlGroupSection = @"
                <div style="margin-top:8px;">
                    <h4 style="font-size:0.9rem;font-weight:600;margin:0 0 6px 0;">CE+ Control Group Compliance <span class="experimental-tag">Experimental</span></h4>
                    <div class="legend" style="margin-bottom:10px;padding:10px;">
                        <h4 style="margin-top:0;">&#x1F3F7;&#xFE0F; Compliance Status Legend</h4>
                        <div class="legend-grid" style="margin-bottom:8px;">
                            <div class="legend-item"><span class="legend-dot dot-green"></span> <strong>Compliant</strong> &mdash; policy requirement met, resources are in desired state</div>
                            <div class="legend-item"><span class="legend-dot dot-red"></span> <strong>Non-Compliant</strong> &mdash; resources violate the policy, remediation needed</div>
                            <div class="legend-item"><span class="legend-dot dot-gray"></span> <strong>Not Evaluated</strong> &mdash; compliance data not yet available from Azure</div>
                            <div class="legend-item"><span class="legend-dot dot-amber"></span> <strong>Not Assigned</strong> &mdash; policy is not assigned to any scope</div>
                        </div>
                        <div class="legend-grid">
                            <div class="legend-item"><span class="legend-dot dot-green"></span> Automated pass-rate indicator only &mdash; not a certification threshold</div>
                            <div class="legend-item"><span class="legend-dot dot-amber"></span> Bar 50-79% &mdash; partial compliance, gaps exist</div>
                            <div class="legend-item"><span class="legend-dot dot-red"></span> Bar &lt; 50% &mdash; weak compliance, significant remediation required</div>
                        </div>
                    </div>
                    $groupBars
                </div>
"@
            }

            # ── CE+ Policy Compliance Detail per scope ──
            $policyDetailSection = ''
            if ($CEPExportData -and $CEPExportData.Count -gt 0) {
                $scopeCeRows = ($CEPExportData | ForEach-Object {
                    $ncVal = $_.'Non-Compliant Resources'; $ncClass = if ($ncVal -ne 'N/A' -and [int]$ncVal -gt 0) { 'nc-bad' } else { 'nc-ok' }
                    $sClass = switch -Wildcard ($_.'Status') { '*Non-Compliant*' { 'status-fail' }; '*Compliant*' { 'status-pass' }; 'Not Assigned' { 'status-warn' }; default { 'status-skip' } }
                    "<tr><td>$($_.'CE Control Group')</td><td>$($_.'Policy Display Name')</td><td><span class=`"badge $sClass`">$($_.'Status')</span></td><td class=`"$ncClass`">$ncVal</td><td>$($_.'Compliant Resources')</td><td>$($_.'Total Resources')</td><td class=`"rec-cell`">$($_.'Recommendation')</td></tr>"
                }) -join "`n"
                $policyDetailSection = @"
                <details style="margin-top:6px;">
                    <summary style="cursor:pointer;font-size:0.85rem;font-weight:600;">&#x1F4CB; CE+ Policy Compliance Detail ($($CEPExportData.Count) policies) <span style="font-size:0.75rem;color:var(--text-dim);font-weight:400;">shared across all scopes</span></summary>
                    <p style="font-size:0.78rem;color:var(--text-dim);margin:4px 0 0 0;padding:0 8px;">Per-<strong>policy</strong> compliance status for each policy definition in the CE initiative. Shows whether each policy has any non-compliant resources.</p>
                    <div style="padding:8px 0;">
                        <div class="table-wrap">
                        <table style="font-size:0.82rem;">
                        <thead><tr><th>Control Group</th><th>Policy</th><th>Status</th><th>NC Resources</th><th>Compliant</th><th>Total</th><th>Recommendation</th></tr></thead>
                        <tbody>$scopeCeRows</tbody>
                        </table>
                        </div>
                    </div>
                </details>
"@
            }

            # ── Test Results Detail per scope (shared data, collapsed) ──
            $testDetailSection = ''
            if ($CEPTestResults.Count -gt 0) {
                $scopeTestRows = ($CEPTestResults | ForEach-Object {
                    ConvertTo-CEPTestHtmlRow -TestResult $_
                }) -join "`n"
                $testDetailSection = @"
                <details style="margin-top:6px;">
                    <summary style="cursor:pointer;font-size:0.85rem;font-weight:600;">&#x1F9EA; CE+ Assessment Tests ($($CEPTestResults.Count) tests) <span style="font-size:0.75rem;color:var(--text-dim);font-weight:400;">shared across all scopes</span></summary>
                    <p style="font-size:0.78rem;color:var(--text-dim);margin:4px 0 0 0;padding:0 8px;">Automated <strong>assessment checks</strong> (prerequisites, per-group compliance, and CE+ v3.2 specification tests). These are tenant-wide evaluations shared across all assignments.</p>
                    <div style="padding:8px 0;">
                        <div class="note-box" style="margin-bottom:8px;"><span class="note-icon">&#x1F4AC;</span><span><strong>Test Statuses:</strong> <span class="badge status-pass">AUTOMATED PASS</span> = automated configuration checks passed, but listed manual verification may remain. <span class="badge status-fail">FAIL</span> = requirement not met, action needed. <span class="badge status-warn">WARN</span> = partial compliance, review recommended. <span class="badge status-skip">SKIP</span> = test could not run (data unavailable). <span class="badge status-manual">MANUAL</span> = requires human verification (cannot be automated).</span></div>
                        <p style="font-size:0.78rem;color:var(--text-dim);margin:0 0 8px 0;">Resource count columns show <strong>N/A</strong> when a verdict is based on configuration, prerequisite, or manual evidence rather than evaluated Azure resources.</p>
                        <div class="summary-cards" style="margin-bottom:10px;">
                            <div class="card card-green"><div class="card-num">$tPass</div><div class="card-label">Passed</div></div>
                            <div class="card card-red"><div class="card-num">$tFail</div><div class="card-label">Failed</div></div>
                            <div class="card card-amber"><div class="card-num">$tWarn</div><div class="card-label">Warnings</div></div>
                            <div class="card card-gray"><div class="card-num">$tSkip</div><div class="card-label">Skipped</div></div>
                            <div class="card card-purple"><div class="card-num">$tManual</div><div class="card-label">Manual</div></div>
                        </div>
                        <div class="table-wrap">
                        <table style="font-size:0.82rem;">
                        <thead><tr><th>Test #</th><th>Control Group</th><th>Test Name</th><th>Status</th><th>Details</th><th>NC</th><th>Compliant</th><th>Total</th></tr></thead>
                        <tbody>$scopeTestRows</tbody>
                        </table>
                        </div>
                    </div>
                </details>
"@
            }

            # Assignment details collapsible
            $assignmentSection = @"
                <details style="margin-top:6px;">
                    <summary style="cursor:pointer;font-size:0.85rem;">Show assignment details</summary>
                    <div style="padding:8px 0;">
                        <table style="font-size:0.85rem;width:100%;">
                            <tbody>
                                <tr><td style="font-weight:600;width:130px;">Display Name</td><td>${displayName}</td></tr>
                                <tr><td style="font-weight:600;">Scope Name</td><td>${scopeName}</td></tr>
                                <tr><td style="font-weight:600;">Scope Type</td><td>${scopeType}</td></tr>
                                <tr><td style="font-weight:600;">Enforcement</td><td><span class="badge ${enfClass}">${enfIcon} ${enfLabel}</span></td></tr>
                            </tbody>
                        </table>
                    </div>
                </details>
"@

            # Outer card per scope
            @"
        <details style="margin-top:8px;border:1px solid var(--table-border);border-radius:6px;padding:2px 12px;">
            <summary style="cursor:pointer;font-size:0.9rem;font-weight:600;padding:6px 0;">
                ${scopeName} <span style="font-size:0.8rem;color:var(--text-dim);font-weight:400;">(${scopeType})</span>
                <span class="badge ${enfClass}" style="margin-left:8px;font-size:0.75rem;">${enfIcon} ${enfLabel}</span>
                ${headerBadge}
            </summary>
            <div style="padding:4px 0 8px 0;">
                ${complianceSection}
                ${controlGroupSection}
                ${policyDetailSection}
                ${testDetailSection}
                ${assignmentSection}
            </div>
        </details>
"@
        }) -join "`n"

        $ceMultiAssignmentBanner = @"
    <div class="note-box" style="border-left:4px solid #f0ad4e;"><span class="note-icon">&#x26A0;&#xFE0F;</span><span>
        <strong>Multi-Assignment Detected: $($ceInitiativeAssignments.Count) Cyber Essentials initiative assignments</strong>
        <span style="margin-left:12px;font-size:0.85rem;">($ceEnforcedCount enforced, $ceAuditOnlyCount enforcement disabled)</span>
        <br><span style="font-size:0.85rem;color:var(--text-dim);">Compliance data is <strong>deduplicated</strong> using strictest-state-wins per resource &mdash; if any assignment reports a resource as non-compliant, it is treated as non-compliant regardless of other assignments. This prevents double-counting when scopes overlap.</span>
        $perScopeCards
    </span></div>
"@
    } else {
        $isMultiAssignment = $false
    }

    # ── Build Policy Assignments rows (with category column) ──
    $policyRows = ($PolicyResults | ForEach-Object {
        $typeClass = switch ($_.'Policy Type') { 'Initiative (Regulatory)' { 'type-regulatory' }; 'Initiative' { 'type-initiative' }; default { 'type-policy' } }
        $ncVal = if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 }; $ncClass = if ($ncVal -gt 0) { 'nc-bad' } else { 'nc-ok' }
        $riskClass = switch ($_.'Risk Level') { 'High' { 'risk-high' }; 'Medium' { 'risk-med' }; default { 'risk-low' } }
        $cat = if ($_.'Category') { $_.'Category' } else { '—' }
        $compImpact = if ($_.'Compliance Impact') { $_.'Compliance Impact' } else { '—' }
        $recommendation = if ($_.'Recommendation') { $_.'Recommendation' } else { '—' }
        "<tr class=`"$typeClass`"><td>$($_.'Display Name')</td><td><span class=`"badge $typeClass`">$($_.'Policy Type')</span></td><td>$cat</td><td>$($_.'Effect Type')</td><td>$($_.'Enforcement Mode')</td><td class=`"$ncClass`">$ncVal</td><td>$($_.'Scope Type')</td><td>$($_.'Scope Name')</td><td><span class=`"badge $riskClass`">$($_.'Risk Level')</span></td><td>$($_.'Security Impact')</td><td>$compImpact</td><td class=`"rec-cell`">$recommendation</td></tr>"
    }) -join "`n"

    # ── Category breakdown for insights ──
    $categoryBreakdown = $PolicyResults | Where-Object { $_.'Category' -and $_.'Category' -ne '' } | Group-Object 'Category' | Sort-Object Count -Descending
    $categoryRows = ($categoryBreakdown | ForEach-Object {
        $catNC = ($_.Group | ForEach-Object { if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 } } | Measure-Object -Sum).Sum
        $ncClass = if ($catNC -gt 0) { 'nc-bad' } else { 'nc-ok' }
        "<tr><td><strong>$($_.Name)</strong></td><td>$($_.Count)</td><td class=`"$ncClass`">$catNC</td><td>$([math]::Round(($_.Count / [math]::Max($totalAssignments,1)) * 100))%</td></tr>"
    }) -join "`n"

    # ── Exemptions sub-section HTML (rendered inside Engineering Report) ──
    $exemptionSubHtml = ''
    if ($ExemptionData.Count -gt 0) {
        $exActiveCount = @($ExemptionData | Where-Object { -not $_.'Is Expired' }).Count
        $exExpiredCount = @($ExemptionData | Where-Object { $_.'Is Expired' }).Count
        $exWaiverCount = @($ExemptionData | Where-Object { $_.'Category' -eq 'Waiver' }).Count
        $exMitigatedCount = @($ExemptionData | Where-Object { $_.'Category' -eq 'Mitigated' }).Count
        $exMgCount = @($ExemptionData | Where-Object { $_.'Scope Type' -eq 'Management Group' }).Count
        $exSubCount = @($ExemptionData | Where-Object { $_.'Scope Type' -eq 'Subscription' }).Count
        $exRgCount = @($ExemptionData | Where-Object { $_.'Scope Type' -eq 'Resource Group' }).Count
        $exResCount = @($ExemptionData | Where-Object { $_.'Scope Type' -eq 'Resource' }).Count
        $exPartialCount = @($ExemptionData | Where-Object { $_.'Partial Exemption' }).Count
        $exAssignmentsCovered = ($ExemptionData | Select-Object -Property 'Policy Assignment' -Unique).Count

        # Build exemption rows
        $exRows = ($ExemptionData | ForEach-Object {
            $catClass = if ($_.'Category' -eq 'Waiver') { 'status-warn' } else { 'status-pass' }
            $expiredClass = if ($_.'Is Expired') { 'nc-bad' } else { '' }
            $scopeClass = switch ($_.'Scope Type') { 'Management Group' { 'type-initiative' }; 'Subscription' { 'type-policy' }; 'Resource Group' { 'type-regulatory' }; default { '' } }
            $partialBadge = if ($_.'Partial Exemption') { "<span class='badge status-warn'>Partial ($($_.'Exempted Policies'))</span>" } else { "<span class='badge status-pass'>Full</span>" }
            $expiryDisplay = if ($_.'Expires On' -eq 'Never') { '<span style=\"color:var(--text-dim)\">Never</span>' } else {
                $expiryColor = if ($_.'Is Expired') { 'var(--red)' } else { 'var(--green)' }
                "<span style='color:$expiryColor'>$($_.'Expires On')</span>"
            }
            "<tr class='$expiredClass'><td>$($_.'Display Name')</td><td><span class='badge $catClass'>$($_.'Category')</span></td><td>$($_.'Policy Assignment')</td><td><span class='badge $scopeClass'>$($_.'Scope Type')</span></td><td>$($_.'Scope Name')</td><td>$partialBadge</td><td>$expiryDisplay</td><td class='mono' style='font-size:0.75em;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;' title='$($_.'Description')'>$($_.'Description')</td></tr>"
        }) -join "`n"

        # Exemptions by assignment (grouped)
        $exByAssignment = $ExemptionData | Group-Object 'Policy Assignment' | Sort-Object Count -Descending
        $exByAssignmentRows = ($exByAssignment | ForEach-Object {
            $assignName = $_.Name
            $exCount = $_.Count
            $activeCountForAssign = @($_.Group | Where-Object { -not $_.'Is Expired' }).Count
            $scopes = ($_.Group | ForEach-Object { $_.'Scope Name' } | Select-Object -Unique) -join ', '
            $categories = ($_.Group | ForEach-Object { $_.'Category' } | Select-Object -Unique) -join ', '
            $severityBadge = if ($exCount -ge 5) { "<span class='badge status-fail'>$exCount</span>" } elseif ($exCount -ge 2) { "<span class='badge status-warn'>$exCount</span>" } else { "<span class='badge status-pass'>$exCount</span>" }
            "<tr><td>$assignName</td><td>$severityBadge</td><td>$activeCountForAssign</td><td>$categories</td><td>$scopes</td></tr>"
        }) -join "`n"

        $exemptionSubHtml = @"

    <hr style="border:none; border-top:1px solid var(--border); margin:32px 0;">

    <h3 class="sub-title" id="sec-exemptions">&#x1F4CB; Policy Exemptions</h3>

    <div class="section-intro">
        <p><strong>Purpose:</strong> Lists all policy exemptions across management groups, subscriptions, resource groups, and individual resources. Exemptions allow specific scopes to be excluded from policy evaluation, either as <strong>Waivers</strong> (accepted risk) or <strong>Mitigated</strong> (alternative control in place).</p>
        <p>Review exemptions regularly to ensure they are still justified. Expired exemptions are highlighted. Assignments with many exemptions may indicate policies that need tuning.</p>
    </div>

    <div class="summary-cards">
        <div class="card card-blue"><div class="card-num">$($ExemptionData.Count)</div><div class="card-label">Total Exemptions</div></div>
        <div class="card card-green"><div class="card-num">$exActiveCount</div><div class="card-label">Active</div></div>
        <div class="card card-red"><div class="card-num">$exExpiredCount</div><div class="card-label">Expired</div></div>
        <div class="card card-amber"><div class="card-num">$exWaiverCount</div><div class="card-label">Waivers</div></div>
        <div class="card card-purple"><div class="card-num">$exMitigatedCount</div><div class="card-label">Mitigated</div></div>
        <div class="card card-gray"><div class="card-num">$exAssignmentsCovered</div><div class="card-label">Assignments Covered</div></div>
    </div>

    <div class="note-box"><span class="note-icon">&#x2139;&#xFE0F;</span><span><strong>Scope Distribution:</strong> MG: $exMgCount &nbsp;|&nbsp; Subscription: $exSubCount &nbsp;|&nbsp; Resource Group: $exRgCount &nbsp;|&nbsp; Resource: $exResCount$(if ($exPartialCount -gt 0) { " &nbsp;|&nbsp; <strong>$exPartialCount partial exemptions</strong> (only specific policies within an initiative are exempted)" })</span></div>

    <details class="report-disclosure depth-3">
        <summary>&#x1F4CB; All Exemptions ($($ExemptionData.Count))</summary>
        <div class="details-content">
            <div class="filter-bar">
                <input type="text" id="filter-exemptions" placeholder="Search exemptions..." oninput="filterTable('exemptions-table','filter-exemptions')">
                <span class="count" id="count-exemptions">$($ExemptionData.Count) exemptions</span>
                <button class="copy-btn" onclick="copyTable('exemptions-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            </div>
            <div class="table-wrap">
            <table id="exemptions-table">
            <thead><tr><th class="sortable" onclick="sortTable('exemptions-table',0)">Exemption</th><th class="sortable" onclick="sortTable('exemptions-table',1)">Category</th><th class="sortable" onclick="sortTable('exemptions-table',2)">Policy Assignment</th><th class="sortable" onclick="sortTable('exemptions-table',3)">Scope Type</th><th class="sortable" onclick="sortTable('exemptions-table',4)">Scope Name</th><th class="sortable" onclick="sortTable('exemptions-table',5)">Coverage</th><th class="sortable" onclick="sortTable('exemptions-table',6)">Expires</th><th>Description</th></tr></thead>
            <tbody>$exRows</tbody>
            </table>
            </div>
        </div>
    </details>

    <details>
        <summary>&#x1F4CA; Exemptions by Assignment ($($exByAssignment.Count) assignments)</summary>
        <div class="details-content">
            <div class="table-wrap">
            <table id="exemptions-by-assignment-table">
            <thead><tr><th class="sortable" onclick="sortTable('exemptions-by-assignment-table',0)">Policy Assignment</th><th class="sortable" onclick="sortTable('exemptions-by-assignment-table',1)">Exemptions</th><th class="sortable" onclick="sortTable('exemptions-by-assignment-table',2)">Active</th><th>Categories</th><th>Scopes</th></tr></thead>
            <tbody>$exByAssignmentRows</tbody>
            </table>
            </div>
        </div>
    </details>

$(if ($exExpiredCount -gt 0) {
    "<div class='callout callout-warn'><span class='callout-icon'>&#x26A0;&#xFE0F;</span><div><strong>$exExpiredCount Expired Exemption$(if ($exExpiredCount -gt 1) {'s'})</strong><p>Expired exemptions no longer exclude resources from policy evaluation. Review and remove or renew them.</p></div></div>"
})
"@
    }

    # ── Azure Landing Zone Analysis section HTML ──
    $alzSectionHtml = ''
    if ($ALZData) {
        $alzTotal = $ALZData.TotalRecommended
        $alzMatched = $ALZData.TotalMatched
        $alzMissing = $ALZData.TotalMissing
        $alzDoNotEnforce = $ALZData.TotalDoNotEnforce
        $alzNotDetected = $ALZData.TotalNotDetected
        $alzApplicabilityNotAssessed = $ALZData.TotalApplicabilityNotAssessed
        $alzNotApplicable = $ALZData.TotalNotApplicable
        $alzCoveragePct = $ALZData.CoveragePercent
        $alzEnforcedPct = $ALZData.EnforcedCoveragePercent
        $alzDeployed = $alzMatched + $alzDoNotEnforce
        $alzSourceVersion = [System.Net.WebUtility]::HtmlEncode([string]$ALZData.SourceVersion)
        $alzSourceRetrievedAt = [System.Net.WebUtility]::HtmlEncode([string]$ALZData.SourceRetrievedAt)

        # Coverage rating
        $alzRating = if ($alzCoveragePct -ge 90 -and $alzDoNotEnforce -eq 0) { 'Excellent' }
                     elseif ($alzCoveragePct -ge 75) { 'Good' }
                     elseif ($alzCoveragePct -ge 50) { 'Moderate' }
                     else { 'Weak' }
        $alzRatingClass = switch ($alzRating) { 'Excellent' { 'card-green' }; 'Good' { 'card-green' }; 'Moderate' { 'card-amber' }; default { 'card-red' } }
        $alzRatingIcon = switch ($alzRating) { 'Excellent' { '&#x2705;' }; 'Good' { '&#x1F7E2;' }; 'Moderate' { '&#x1F7E1;' }; default { '&#x1F534;' } }
        $alzCoverageColor = if ($alzCoveragePct -ge 75) { 'var(--green)' } elseif ($alzCoveragePct -ge 50) { 'var(--amber)' } else { 'var(--red)' }
        $alzEnforcedColor = if ($alzEnforcedPct -ge 75) { 'var(--green)' } elseif ($alzEnforcedPct -ge 50) { 'var(--amber)' } else { 'var(--red)' }

        # Build per-category breakdown rows
        $alzCategoryRows = ''
        foreach ($category in ($ALZData.RecommendedPolicies.Keys | Sort-Object)) {
            $catPolicies = $ALZData.RecommendedPolicies[$category]
            if ($catPolicies.Count -eq 0) { continue }
            $catMatched = @($ALZData.MatchedPolicies | Where-Object { $_.Category -eq $category }).Count
            $catDNE = @($ALZData.DoNotEnforcePolicies | Where-Object { $_.Category -eq $category }).Count
            $catMissing = @($ALZData.AssetAssessments | Where-Object { $_.Category -eq $category -and $_.State -eq 'Applicable gap' }).Count
            $catUnassessed = @($ALZData.AssetAssessments | Where-Object { $_.Category -eq $category -and $_.State -eq 'Applicability not assessed' }).Count
            $catTotal = $catPolicies.Count
            $catPct = if ($catTotal -gt 0) { [math]::Round((($catMatched + $catDNE) / $catTotal) * 100) } else { 0 }
            $catPctClass = if ($catPct -ge 75) { 'nc-ok' } elseif ($catPct -ge 50) { 'warn-text' } else { 'nc-bad' }
            $alzCategoryRows += "<tr><td><strong>$category</strong></td><td>$catTotal</td><td class='nc-ok'>$catMatched</td><td class='warn-text'>$catDNE</td><td class='nc-bad'>$catMissing</td><td>$catUnassessed</td><td class='$catPctClass'>$catPct%</td></tr>`n"
        }

        # Build missing policies detail rows
        $alzMissingRows = ''
        if ($ALZData.MissingPolicies.Count -gt 0) {
            $missingByCategory = $ALZData.MissingPolicies | Group-Object Category | Sort-Object Name
            foreach ($group in $missingByCategory) {
                foreach ($item in $group.Group) {
                    $impactType = if ($item.PolicyPattern -match 'Deny|Block|Prevent|Disable|Restrict') { '<span class="badge status-fail">Preventive</span>' }
                                  elseif ($item.PolicyPattern -match 'Deploy|Configure|Enforce') { '<span class="badge status-warn">Remediation</span>' }
                                  elseif ($item.PolicyPattern -match 'Audit|Monitor|Log|Enable') { '<span class="badge status-nc">Detective</span>' }
                                  else { '<span class="badge status-dim">Other</span>' }
                    $alzMissingRows += "<tr><td>$($item.PolicyPattern)</td><td>$($group.Name)</td><td>$impactType</td></tr>`n"
                }
            }
        }

        # Build DoNotEnforce detail rows
        $alzDNERows = ''
        if ($ALZData.DoNotEnforcePolicies.Count -gt 0) {
            foreach ($item in $ALZData.DoNotEnforcePolicies) {
                $alzDNERows += "<tr><td>$($item.PolicyName)</td><td>$($item.Category)</td><td class='warn-text'>DoNotEnforce</td><td>$($item.ActualName)</td></tr>`n"
            }
        }

        $alzSectionHtml = @"
<!-- ══════════════════════════════════════════════════════ -->
<!--  6. AZURE LANDING ZONE ANALYSIS                       -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="sec-alz" class="report-page" data-report-page data-page-group="page-csa">
<details class="section-disclosure">
    <summary>
        <span>Azure Landing Zone Analysis</span>
        <span class="section-num">Section 6 of $totalSections</span>
        <span class="disclosure-hint">$alzCoveragePct% detected · $alzEnforcedPct% enforced · $alzMissing applicable gaps</span>
    </summary>
    <div class="section-content">

    <div class="section-intro">
        <p><strong>Purpose:</strong> Compare your policy estate with the <a href="https://aka.ms/alz" target="_blank" style="color:var(--accent);">Azure Landing Zones (ALZ) Library</a>. Detection and applicability are reported separately; an asset is a governance gap only when applicability was assessed and the applicable asset was not detected.</p>
        <p><strong>Source release:</strong> $alzSourceVersion &nbsp;|&nbsp; <strong>Retrieved:</strong> $alzSourceRetrievedAt</p>
    </div>

    <div class="legend">
        <h4>&#x1F3F7;&#xFE0F; ALZ Coverage Legend</h4>
        <div class="legend-grid">
            <div class="legend-item"><span class="badge status-pass">Deployed</span> ALZ policy matched and actively enforced (Default mode)</div>
            <div class="legend-item"><span class="badge status-warn">DoNotEnforce</span> ALZ policy deployed with enforcement disabled &mdash; configured effects are not applied</div>
            <div class="legend-item"><span class="badge status-pass">Detected</span> Composite asset match found; enforcement is reported separately</div>
            <div class="legend-item"><span class="badge status-dim">Not detected</span> No composite assignment match found before applicability classification</div>
            <div class="legend-item"><span class="badge status-fail">Applicable gap</span> Applicability assessed as true, but no assignment matched</div>
            <div class="legend-item"><span class="badge status-dim">Applicability not assessed</span> No match and insufficient evidence to claim a governance gap</div>
            <div class="legend-item"><span class="badge status-dim">Not applicable</span> Applicability assessed as false</div>
            <div class="legend-item"><span class="badge status-fail">Preventive</span> = Deny/Block, <span class="badge status-warn">Remediation</span> = DINE/Modify, <span class="badge status-nc">Detective</span> = Audit/Monitor</div>
        </div>
    </div>

    <div class="summary-cards">
        <div class="card $alzRatingClass" title="Tool heuristic based only on ALZ inventory coverage; not an official Microsoft maturity rating"><div class="card-num">$alzRatingIcon $alzRating</div><div class="card-label">Tool Coverage Indicator <span class="col-info" data-tip="Opinionated tool heuristic: Excellent (≥90% + all enforced), Good (≥75%), Moderate (≥50%), Weak (<50%). Not an official ALZ maturity threshold." title="Tool coverage heuristic">&#9432;</span></div></div>
        <div class="card card-blue" title="Total number of policies recommended by ALZ Library"><div class="card-num">$alzTotal</div><div class="card-label">ALZ Recommended <span class="col-info" data-tip="Total policies from the official Azure Landing Zones Library across all categories" title="Total recommended">&#9432;</span></div></div>
        <div class="card card-green" title="ALZ policies found and actively enforced in your tenant"><div class="card-num">$alzMatched</div><div class="card-label">Deployed &amp; Enforced <span class="col-info" data-tip="ALZ policies matched to your assignments with Default enforcement mode" title="Deployed and enforced">&#9432;</span></div></div>
        <div class="card card-amber" title="ALZ policies deployed with DoNotEnforce mode"><div class="card-num">$alzDoNotEnforce</div><div class="card-label">Non-Enforcing <span class="col-info" data-tip="ALZ assignments found in DoNotEnforce mode. Azure evaluates them, but their configured effects are not applied." title="DoNotEnforce assignments">&#9432;</span></div></div>
        <div class="card card-red" title="Applicable ALZ assets not detected"><div class="card-num">$alzMissing</div><div class="card-label">Applicable Gaps</div></div>
        <div class="card card-gray" title="ALZ assets without a composite assignment match"><div class="card-num">$alzNotDetected</div><div class="card-label">Not Detected</div></div>
        <div class="card card-gray" title="Assets without enough evidence to assess applicability"><div class="card-num">$alzApplicabilityNotAssessed</div><div class="card-label">Applicability Not Assessed</div></div>
    </div>

    <div class="grid-3" style="margin-bottom:20px;">
        <div class="insight-box">
            <h4>&#x1F4CA; Overall Coverage <span class="col-info" data-tip="Percentage of ALZ policies deployed (Default + DoNotEnforce) out of total recommended" title="Overall coverage">&#9432;</span></h4>
            <div class="big-num" style="color:$alzCoverageColor">$alzCoveragePct%</div>
            <p>$alzDeployed of $alzTotal ALZ policies deployed</p>
        </div>
        <div class="insight-box">
            <h4>&#x1F512; Enforced Coverage <span class="col-info" data-tip="Percentage of ALZ policies that are both deployed AND actively enforced (Default mode)" title="Enforced coverage">&#9432;</span></h4>
            <div class="big-num" style="color:$alzEnforcedColor">$alzEnforcedPct%</div>
            <p>$alzMatched of $alzTotal ALZ policies actively enforced</p>
        </div>
        <div class="insight-box">
            <h4>&#x26A0;&#xFE0F; Governance Gaps <span class="col-info" data-tip="Applicable assets not detected plus detected assignments with enforcement disabled" title="Governance gaps">&#9432;</span></h4>
            <div class="big-num" style="color:$(if (($alzMissing + $alzDoNotEnforce) -gt 0) { 'var(--red)' } else { 'var(--green)' })">$($alzMissing + $alzDoNotEnforce)</div>
            <p>$alzMissing applicable gaps + $alzDoNotEnforce enforcement disabled; $alzNotApplicable not applicable</p>
        </div>
    </div>

    <h3 class="sub-title">Coverage by Category</h3>
    <div class="table-wrap">
    <table id="alz-category-table">
    <thead><tr><th>Category</th><th>Recommended</th><th>Deployed</th><th>Enforcement Disabled</th><th>Applicable Gaps</th><th>Applicability Not Assessed</th><th>Coverage</th></tr></thead>
    <tbody>$alzCategoryRows</tbody>
    </table>
    </div>

$(if ($alzMissingRows) {
@"
    <details style="margin-top:18px;">
        <summary>&#x1F534; Missing ALZ Policies ($alzMissing)</summary>
        <div class="details-content">
            <div class="filter-bar">
                <input type="text" id="filter-alz-missing" placeholder="Search missing policies..." oninput="filterTable('alz-missing-table','filter-alz-missing')">
                <span class="count" id="count-alz-missing">$alzMissing policies</span>
                <button class="copy-btn" onclick="copyTable('alz-missing-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            </div>
            <div class="table-wrap">
            <table id="alz-missing-table">
            <thead><tr><th class="sortable" onclick="sortTable('alz-missing-table',0)">Policy Name <span class="col-info" data-tip="ALZ-recommended policy that was not found in your assignments" title="Policy name">&#9432;</span></th><th class="sortable" onclick="sortTable('alz-missing-table',1)">Category <span class="col-info" data-tip="ALZ category this policy belongs to" title="Category">&#9432;</span></th><th>Control Type <span class="col-info" data-tip="Whether this policy is Preventive (Deny/Block), Remediation (DINE/Modify), or Detective (Audit/Monitor)" title="Control type">&#9432;</span></th></tr></thead>
            <tbody>$alzMissingRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
})

$(if ($alzDNERows) {
@"
    <details style="margin-top:12px;">
        <summary>&#x1F7E1; ALZ Policies with Enforcement Disabled ($alzDoNotEnforce)</summary>
        <div class="details-content">
            <div class="filter-bar">
                <input type="text" id="filter-alz-dne" placeholder="Search DoNotEnforce policies..." oninput="filterTable('alz-dne-table','filter-alz-dne')">
                <span class="count" id="count-alz-dne">$alzDoNotEnforce policies</span>
                <button class="copy-btn" onclick="copyTable('alz-dne-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            </div>
            <div class="table-wrap">
            <table id="alz-dne-table">
            <thead><tr><th class="sortable" onclick="sortTable('alz-dne-table',0)">ALZ Policy <span class="col-info" data-tip="The ALZ-recommended policy name" title="ALZ policy">&#9432;</span></th><th class="sortable" onclick="sortTable('alz-dne-table',1)">Category <span class="col-info" data-tip="ALZ category" title="Category">&#9432;</span></th><th>Enforcement <span class="col-info" data-tip="Current enforcement mode — DoNotEnforce means the policy reports but does not block" title="Enforcement">&#9432;</span></th><th>Assigned As <span class="col-info" data-tip="The actual assignment name in your tenant" title="Assignment name">&#9432;</span></th></tr></thead>
            <tbody>$alzDNERows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
})

    <p style="margin-top:16px;font-size:0.75rem;color:var(--text-dim);">&#x1F4DA; <strong>Reference:</strong> <a href="https://aka.ms/alz" target="_blank" style="color:var(--accent);">Azure Landing Zones documentation</a> | <a href="https://github.com/Azure/Azure-Landing-Zones-Library" target="_blank" style="color:var(--accent);">ALZ Library (GitHub)</a> | <a href="https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/" target="_blank" style="color:var(--accent);">Cloud Adoption Framework: Landing Zones</a></p>
    </div>
</details>
</section>
"@
    }

    # ── YAML Delta Assessment section HTML ──
    $yamlDeltaSectionHtml = ''
    if ($YAMLDeltaData) {
        $yd = $YAMLDeltaData
        # Helper formatters
        $ydAssignSign = if ($yd.AssignmentDelta -gt 0) { "+$($yd.AssignmentDelta)" } elseif ($yd.AssignmentDelta -lt 0) { "$($yd.AssignmentDelta)" } else { "0" }
        $ydNCSign = if ($yd.NCDelta -gt 0) { "+$($yd.NCDelta)" } elseif ($yd.NCDelta -lt 0) { "$($yd.NCDelta)" } else { "0" }
        $ydHighSign = if ($yd.HighDelta -gt 0) { "+$($yd.HighDelta)" } elseif ($yd.HighDelta -lt 0) { "$($yd.HighDelta)" } else { "0" }
        $ydEnfSign = if ($yd.EnfDelta -gt 0) { "+$($yd.EnfDelta)" } elseif ($yd.EnfDelta -lt 0) { "$($yd.EnfDelta)" } else { "0" }
        $ydNCClass = if ($yd.NCDelta -gt 0) { 'card-red' } elseif ($yd.NCDelta -lt 0) { 'card-green' } else { 'card-gray' }
        $ydHighClass = if ($yd.HighDelta -gt 0) { 'card-red' } elseif ($yd.HighDelta -lt 0) { 'card-green' } else { 'card-gray' }
        $ydEnfClass = if ($yd.EnfDelta -gt 0) { 'card-green' } elseif ($yd.EnfDelta -lt 0) { 'card-red' } else { 'card-gray' }
        $ydTrendIcon = switch ($yd.Trend) { 'IMPROVING' { '&#x1F4C8;' }; 'DEGRADING' { '&#x1F4C9;' }; 'STABLE' { '&#x27A1;&#xFE0F;' }; default { '&#x2194;&#xFE0F;' } }
        $ydTrendClass = switch ($yd.Trend) { 'IMPROVING' { 'card-green' }; 'DEGRADING' { 'card-red' }; default { 'card-amber' } }

        # New assignments rows
        $ydNewRows = ''
        if ($yd.NewAssignments.Count -gt 0) {
            $ydNewRows = ($yd.NewAssignments | ForEach-Object {
                $typeClass = switch ($_.'Policy Type') { 'Initiative (Regulatory)' { 'type-regulatory' }; 'Initiative' { 'type-initiative' }; default { 'type-policy' } }
                "<tr><td class='nc-ok'>+ $($_.'Display Name')</td><td><span class='badge $typeClass'>$($_.'Policy Type')</span></td><td>$($_.'Effect Type')</td><td>$($_.'Enforcement Mode')</td><td>$($_.'Scope Name')</td></tr>"
            }) -join "`n"
        }

        # Removed assignments rows
        $ydRemovedRows = ''
        if ($yd.RemovedAssignments.Count -gt 0) {
            $ydRemovedRows = ($yd.RemovedAssignments | ForEach-Object {
                "<tr><td class='nc-bad'>- $($_.displayName)</td><td>$($_.policyType)</td><td>$($_.effectType)</td><td>$($_.enforcementMode)</td><td>$($_.scopeName)</td></tr>"
            }) -join "`n"
        }

        # Changed assignments rows
        $ydChangedRows = ''
        if ($yd.ChangedAssignments.Count -gt 0) {
            $ydChangedRows = ($yd.ChangedAssignments | ForEach-Object {
                $changeList = ($_.Changes | ForEach-Object {
                    "<li><strong>$($_.Property):</strong> <span style='color:#e74c3c;text-decoration:line-through'>$($_.Previous)</span> &rarr; <span style='color:#27ae60;font-weight:600'>$($_.Current)</span></li>"
                }) -join ''
                "<tr><td class='warn-text'>$($_.Display)</td><td>$($_.ScopeName)</td><td colspan='3'><ul style='margin:0;padding-left:16px;'>$changeList</ul></td></tr>"
            }) -join "`n"
        }

        # Effect type change rows
        $ydEffectRows = ''
        if ($yd.EffectChanges.Count -gt 0) {
            $ydEffectRows = ($yd.EffectChanges | ForEach-Object {
                $deltaClass = if ([int]$_.Delta.TrimStart('+') -gt 0 -and $_.Effect -eq 'Deny') { 'nc-ok' } elseif ($_.Effect -eq 'Disabled' -and [int]$_.Delta.TrimStart('+') -gt 0) { 'nc-bad' } else { '' }
                "<tr><td>$($_.Effect)</td><td>$($_.Previous)</td><td>$($_.Current)</td><td class='$deltaClass'>$($_.Delta)</td></tr>"
            }) -join "`n"
        }

        # CE+ previous results card
        $ydCEPCard = ''
        if ($yd.CEPPreviousResults) {
            $cepDeltaGuidance = if ($CEPAssessment.Requested) {
                'Current CEP results are shown in the Governance &amp; Compliance section for comparison.'
            } else {
                'Run with <code>-CEP Test</code> to compare current CE+ test results.'
            }
            $ydCEPCard = @"
<div class="callout callout-info">
    <span class="callout-icon">&#x1F6E1;&#xFE0F;</span>
    <div>
        <strong>CE+ Test Results (Previous Run)</strong>
        <p>$($yd.CEPPreviousResults.Pass) PASS &nbsp;|&nbsp; $($yd.CEPPreviousResults.Fail) FAIL &nbsp;|&nbsp; $($yd.CEPPreviousResults.Manual) MANUAL</p>
        <p class="text-dim">$cepDeltaGuidance</p>
    </div>
</div>
"@
        }

        $yamlDeltaSectionHtml = @"
    <section id="sec-yaml-delta" class="report-page" data-report-page data-page-group="page-evidence">
<details class="section-disclosure">
    <summary>
        <span>Delta Assessment</span>
        <span class="section-num">Section $deltaSectionNumber of $totalSections</span>
        <span class="disclosure-hint">$($yd.CurrTotal) assignments ($ydAssignSign) · $($yd.CurrNC) non-compliant ($ydNCSign) · $($yd.Trend)</span>
    </summary>
    <div class="section-content">

    <div class="section-intro">
        <p><strong>Purpose:</strong> Comprehensive policy-by-policy comparison against a previous YAML assessment database. Shows new, removed, and changed assignments, compliance drift, effect type shifts, and overall posture trend.</p>
        <p><strong>Previous snapshot:</strong> $($yd.PreviousDate) (v$($yd.PreviousVersion)) &nbsp;&bull;&nbsp; <strong>Current:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm') (v$ScriptVersion)</p>
    </div>

    <div class="summary-cards">
        <div class="card card-blue"><div class="card-num">$($yd.CurrTotal) <span style="font-size:0.5em;opacity:0.7">($ydAssignSign)</span></div><div class="card-label">Assignments</div></div>
        <div class="card $ydNCClass"><div class="card-num">$($yd.CurrNC) <span style="font-size:0.5em;opacity:0.7">($ydNCSign)</span></div><div class="card-label">Non-Compliant</div></div>
        <div class="card $ydHighClass"><div class="card-num">$($yd.CurrHigh) <span style="font-size:0.5em;opacity:0.7">($ydHighSign)</span></div><div class="card-label">High Risk</div></div>
        <div class="card $ydEnfClass"><div class="card-num">$($yd.CurrEnforced) <span style="font-size:0.5em;opacity:0.7">($ydEnfSign)</span></div><div class="card-label">Enforced</div></div>
$(if ($yd.CurrExTotal -gt 0 -or $yd.PrevExTotal -gt 0) {
    $ydExSign = if ($yd.ExTotalDelta -gt 0) { "+$($yd.ExTotalDelta)" } elseif ($yd.ExTotalDelta -lt 0) { "$($yd.ExTotalDelta)" } else { "0" }
    $ydExClass = if ($yd.ExTotalDelta -gt 0) { 'card-amber' } elseif ($yd.ExTotalDelta -lt 0) { 'card-green' } else { 'card-gray' }
    "        <div class=`"card $ydExClass`"><div class=`"card-num`">$($yd.CurrExTotal) <span style=`"font-size:0.5em;opacity:0.7`">($ydExSign)</span></div><div class=`"card-label`">Exemptions</div></div>"
})
        <div class="card $ydTrendClass"><div class="card-num">$ydTrendIcon</div><div class="card-label">$($yd.Trend)</div></div>
    </div>

$(if ($yd.NewAssignments.Count -gt 0) {
@"
    <details class="report-disclosure depth-2">
        <summary>&#x2795; New Assignments ($($yd.NewAssignments.Count))</summary>
        <div class="details-content">
            <div class="table-wrap">
            <table id="delta-new-table">
            <thead><tr><th>Assignment</th><th>Type</th><th>Effect</th><th>Enforcement</th><th>Scope</th></tr></thead>
            <tbody>$ydNewRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
})

$(if ($yd.RemovedAssignments.Count -gt 0) {
@"
    <details class="report-disclosure depth-2">
        <summary>&#x2796; Removed Assignments ($($yd.RemovedAssignments.Count))</summary>
        <div class="details-content">
            <div class="table-wrap">
            <table id="delta-removed-table">
            <thead><tr><th>Assignment</th><th>Type</th><th>Effect</th><th>Enforcement</th><th>Scope</th></tr></thead>
            <tbody>$ydRemovedRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
})

$(if ($yd.ChangedAssignments.Count -gt 0) {
@"
    <details class="report-disclosure depth-2">
        <summary>&#x1F504; Changed Assignments ($($yd.ChangedAssignments.Count))</summary>
        <div class="details-content">
            <div class="table-wrap">
            <table id="delta-changed-table">
            <thead><tr><th>Assignment</th><th>Scope</th><th colspan="3">Changes</th></tr></thead>
            <tbody>$ydChangedRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
})

$(if ($yd.EffectChanges.Count -gt 0) {
@"
    <details>
        <summary>&#x1F4C8; Effect Type Changes ($($yd.EffectChanges.Count))</summary>
        <div class="details-content">
            <div class="table-wrap">
            <table id="delta-effects-table">
            <thead><tr><th>Effect Type</th><th>Previous</th><th>Current</th><th>Delta</th></tr></thead>
            <tbody>$ydEffectRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
})

$ydCEPCard

$(if ($yd.NewExemptions.Count -gt 0) {
    $ydNewExRows = ($yd.NewExemptions | ForEach-Object {
        $exDispName = $_.'Display Name'
        $exCat      = $_.'Category'
        $exAssign   = $_.'Policy Assignment'
        $exScopeT   = $_.'Scope Type'
        $exScopeN   = $_.'Scope Name'
        $catClass = if ($exCat -eq 'Waiver') { 'status-warn' } else { 'status-pass' }
        "<tr><td class='nc-ok'>+ $exDispName</td><td><span class='badge $catClass'>$exCat</span></td><td>$exAssign</td><td>$exScopeT</td><td>$exScopeN</td></tr>"
    }) -join "`n"
@"
    <details>
        <summary>&#x2795; New Exemptions ($($yd.NewExemptions.Count))</summary>
        <div class="details-content">
            <div class="table-wrap">
            <table id="delta-new-exemptions-table">
            <thead><tr><th>Exemption</th><th>Category</th><th>Policy Assignment</th><th>Scope Type</th><th>Scope</th></tr></thead>
            <tbody>$ydNewExRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
})

$(if ($yd.RemovedExemptions.Count -gt 0) {
    $ydRemovedExRows = ($yd.RemovedExemptions | ForEach-Object {
        $exDispName = if ($_.displayName) { $_.displayName } else { $_.'Display Name' }
        $exCat      = if ($_.category) { $_.category } else { $_.'Category' }
        $exAssign   = if ($_.policyAssignment) { $_.policyAssignment } else { $_.'Policy Assignment' }
        $exScopeT   = if ($_.scopeType) { $_.scopeType } else { $_.'Scope Type' }
        $exScopeN   = if ($_.scopeName) { $_.scopeName } else { $_.'Scope Name' }
        "<tr><td class='nc-bad'>- $exDispName</td><td>$exCat</td><td>$exAssign</td><td>$exScopeT</td><td>$exScopeN</td></tr>"
    }) -join "`n"
@"
    <details>
        <summary>&#x2796; Removed Exemptions ($($yd.RemovedExemptions.Count))</summary>
        <div class="details-content">
            <div class="table-wrap">
            <table id="delta-removed-exemptions-table">
            <thead><tr><th>Exemption</th><th>Category</th><th>Policy Assignment</th><th>Scope Type</th><th>Scope</th></tr></thead>
            <tbody>$ydRemovedExRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
})

$(if ($yd.NewAssignments.Count -eq 0 -and $yd.RemovedAssignments.Count -eq 0 -and $yd.ChangedAssignments.Count -eq 0 -and $yd.NewExemptions.Count -eq 0 -and $yd.RemovedExemptions.Count -eq 0) {
    '<div class="callout callout-success"><span class="callout-icon">&#x2705;</span><div><strong>No Changes Detected</strong><p>The policy landscape is identical to the previous snapshot.</p></div></div>'
})

    </div>
</details>
</section>
"@
    }

    # ── Build CE Compliance rows ──
    $ceRows = ''
    if ($CEPExportData.Count -gt 0) {
        $ceRows = ($CEPExportData | ForEach-Object {
            $statusClass = switch -Wildcard ($_.'Status') { '*Non-Compliant*' { 'status-nc' }; '*Not Assigned*' { 'status-na' }; '*Not Evaluated*' { 'status-ne' }; '*Compliant*' { 'status-ok' }; default { '' } }
            "<tr class=`"$statusClass`"><td>$($_.'CE Control Group')</td><td>$($_.'Policy Display Name')</td><td><span class=`"badge $statusClass`">$($_.'Status')</span></td><td>$($_.'Non-Compliant Resources')</td><td>$($_.'Compliant Resources')</td><td>$($_.'Total Resources')</td><td>$($_.'Recommendation')</td></tr>"
        }) -join "`n"
    }

    # ── Build CE+ Test rows ──
    $testRows = ''
    $testSummaryCards = ''
    if ($CEPTestResults.Count -gt 0) {
        $testRows = ($CEPTestResults | ForEach-Object {
            ConvertTo-CEPTestHtmlRow -TestResult $_
        }) -join "`n"
        $testSummaryCards = @"
<div class="summary-cards">
    <div class="card card-green"><div class="card-num">$tPass</div><div class="card-label">Passed</div></div>
    <div class="card card-red"><div class="card-num">$tFail</div><div class="card-label">Failed</div></div>
    <div class="card card-amber"><div class="card-num">$tWarn</div><div class="card-label">Warnings</div></div>
    <div class="card card-gray"><div class="card-num">$tSkip</div><div class="card-label">Skipped</div></div>
    <div class="card card-purple"><div class="card-num">$tManual</div><div class="card-label">Manual</div></div>
</div>
"@
    }

    # ── Build NC resource rows (grouped by unique resource) ──
    $ncResRows = ''
    if ($NCExportData.Count -gt 0) {
        $ncGrouped = $NCExportData | Group-Object 'Resource ID'
        $ncResRows = ($ncGrouped | ForEach-Object {
            $first = $_.Group[0]
            $policyNames = ($_.Group | ForEach-Object { $_.'Policy Name' } | Select-Object -Unique) -join '<br>'
            $initiatives = ($_.Group | ForEach-Object { $_.'Initiative Name' } | Where-Object { $_ -ne 'N/A (individual policy)' } | Select-Object -Unique) -join '<br>'
            if (-not $initiatives) { $initiatives = 'N/A' }
            $hitCount = $_.Count
            $hitBadge = if ($hitCount -gt 1) { "<span class=`"badge status-warn`">$hitCount policies</span>" } else { "<span class=`"badge status-pass`">1 policy</span>" }
            "<tr><td class=`"mono`">$($first.'Resource Name')</td><td>$($first.'Resource Type')</td><td>$($first.'Resource Group')</td><td>$policyNames</td><td>$initiatives</td><td>$($first.'Subscription ID')</td><td>$hitBadge</td></tr>"
        }) -join "`n"
    }

    # ── Build NC policy-view rows (grouped by policy) ──
    $ncPolicyRows = ''
    $ncPolicyCount = 0
    if ($NCExportData.Count -gt 0) {
        $ncByPolicy = $NCExportData | Group-Object 'Policy Name' | Sort-Object Count -Descending
        $ncPolicyCount = $ncByPolicy.Count
        $ncPolicyRows = ($ncByPolicy | ForEach-Object {
            $policyName = $_.Name
            $uniqueRes = ($_.Group | Select-Object -Property 'Resource ID' -Unique).Count
            $totalEvals = $_.Count
            $resTypes = ($_.Group | ForEach-Object { $_.'Resource Type' } | Select-Object -Unique) -join '<br>'
            $scopes = ($_.Group | ForEach-Object { $_.'Subscription ID' } | Select-Object -Unique).Count
            $initiatives = ($_.Group | ForEach-Object { $_.'Initiative Name' } | Where-Object { $_ -ne 'N/A (individual policy)' } | Select-Object -Unique) -join '<br>'
            if (-not $initiatives) { $initiatives = 'N/A' }
            $severityBadge = if ($uniqueRes -ge 20) { "<span class=`"badge status-fail`">Critical</span>" } elseif ($uniqueRes -ge 5) { "<span class=`"badge status-warn`">High</span>" } else { "<span class=`"badge status-pass`">Low</span>" }
            "<tr><td>$policyName</td><td class=`"nc-bad`">$uniqueRes</td><td>$totalEvals</td><td>$resTypes</td><td>$initiatives</td><td>$scopes</td><td>$severityBadge</td></tr>"
        }) -join "`n"
    }

    # NC resources by resource type (unique resources) — enhanced with policies, risk, and expandable resource list
    $ncByTypeRows = ''
    if ($NCExportData.Count -gt 0) {
        # Build a lookup from policy name to risk level from $PolicyResults
        $policyRiskLookup = @{}
        foreach ($pr in $PolicyResults) {
            $pName = $pr.'Display Name'
            if ($pName -and -not $policyRiskLookup.ContainsKey($pName)) {
                $policyRiskLookup[$pName] = @{ Risk = $pr.'Risk Level'; Security = $pr.'Security Impact' }
            }
        }

        # For NC policies not in $PolicyResults (initiative member policies), compute risk/security from $policyDefMetadata
        # Build a secondary lookup keyed by policy definition GUID → { Risk, Security }
        $ncPolicyDefLookup = @{}
        foreach ($ncEntry in $NCExportData) {
            $polName = $ncEntry.'Policy Name'
            if ($polName -and -not $policyRiskLookup.ContainsKey($polName) -and -not $ncPolicyDefLookup.ContainsKey($polName)) {
                $defId = "$($ncEntry.'Policy Definition ID')".ToLower()
                if ($defId -and $policyDefMetadata.ContainsKey($defId)) {
                    $defMeta = $policyDefMetadata[$defId]
                    $defEffect = "$($defMeta.Effect)"
                    $defCategory = "$($defMeta.Category)"

                    # Compute lightweight security impact from effect + category
                    $secPts = 50
                    switch -Regex ($defEffect) {
                        '^Deny$'                { $secPts += 30; break }
                        '^DeployIfNotExists$'   { $secPts += 25; break }
                        '^Modify$'              { $secPts += 20; break }
                        '^AuditIfNotExists$'    { $secPts +=  5; break }
                        '^Audit$'               { $secPts +=  0; break }
                        '^Disabled$'            { $secPts -= 35; break }
                    }
                    if     ($defCategory -in @('Security Center','Defender for Cloud','Key Vault','Encryption'))          { $secPts += 15 }
                    elseif ($defCategory -in @('Network','API Management','Identity','Guest Configuration'))              { $secPts += 10 }
                    elseif ($defCategory -in @('Monitoring','Backup','Compute','Storage','SQL','Cosmos DB',
                                               'App Service','Kubernetes','Container Registry','Data Factory'))          { $secPts +=  5 }
                    elseif ($defCategory -in @('Tags','General'))                                                         { $secPts -= 15 }
                    if ($polName -match 'security|encrypt|firewall|defender|identity|access|MFA|password|auth|TLS|SSL|vulnerability|antimalware') { $secPts += 10 }

                    $secImpact = if ($secPts -ge 75) { 'High' } elseif ($secPts -ge 40) { 'Medium' } elseif ($secPts -ge 15) { 'Low' } else { 'None' }

                    # Compute lightweight risk level
                    $riskPts = 0
                    switch ($secImpact) { 'High' { $riskPts += 40 }; 'Medium' { $riskPts += 20 }; 'Low' { $riskPts += 5 } }
                    $riskLvl = if ($riskPts -ge 40) { 'High' } elseif ($riskPts -ge 20) { 'Medium' } else { 'Low' }

                    $ncPolicyDefLookup[$polName] = @{ Risk = $riskLvl; Security = $secImpact }
                }
            }
        }

        # Merge: prefer $policyRiskLookup, fall back to $ncPolicyDefLookup
        $combinedRiskLookup = @{}
        foreach ($k in $policyRiskLookup.Keys) { $combinedRiskLookup[$k] = $policyRiskLookup[$k] }
        foreach ($k in $ncPolicyDefLookup.Keys) { if (-not $combinedRiskLookup.ContainsKey($k)) { $combinedRiskLookup[$k] = $ncPolicyDefLookup[$k] } }

        $ncByTypeGrouped = $NCExportData | Group-Object 'Resource Type' | Sort-Object Count -Descending | Select-Object -First 15
        $ncByTypeIdx = 0
        $ncByTypeRows = ($ncByTypeGrouped | ForEach-Object {
            $ncByTypeIdx++
            $resType = $_.Name
            $allEntries = $_.Group
            $uniqueResources = $allEntries | Select-Object 'Resource ID', 'Resource Name', 'Resource Group', 'Subscription ID' -Unique
            $uniqueCount = @($uniqueResources).Count

            # Policies affecting this resource type
            $affectedPolicies = @($allEntries | ForEach-Object { $_.'Policy Name' } | Select-Object -Unique)
            $policyCount = $affectedPolicies.Count

            # Determine highest risk level from policy data
            $maxRisk = 'Low'
            foreach ($pol in $affectedPolicies) {
                if ($combinedRiskLookup.ContainsKey($pol)) {
                    $r = $combinedRiskLookup[$pol].Risk
                    if ($r -eq 'High') { $maxRisk = 'High'; break }
                    elseif ($r -eq 'Medium' -and $maxRisk -ne 'High') { $maxRisk = 'Medium' }
                }
            }
            $severityBadge = switch ($maxRisk) { 'High' { "<span class=`"badge status-fail`">High</span>" }; 'Medium' { "<span class=`"badge status-warn`">Medium</span>" }; default { "<span class=`"badge status-pass`">Low</span>" } }

            # Build expandable policy sections — each policy shows risk, security impact, and its violating resources
            $policySections = ($affectedPolicies | Sort-Object | ForEach-Object {
                $polName = $_
                $polRisk = if ($combinedRiskLookup.ContainsKey($polName)) { $combinedRiskLookup[$polName].Risk } else { '—' }
                $polSec = if ($combinedRiskLookup.ContainsKey($polName)) { $combinedRiskLookup[$polName].Security } else { '—' }
                $prClass = switch ($polRisk) { 'High' { 'risk-high' }; 'Medium' { 'risk-med' }; default { 'risk-low' } }

                # Resources violating this specific policy for this resource type
                $polResources = @($allEntries | Where-Object { $_.'Policy Name' -eq $polName } | Select-Object 'Resource Name', 'Resource Group', 'Subscription ID' -Unique)
                $polResCount = $polResources.Count
                $polResRows = ($polResources | Select-Object -First 10 | ForEach-Object {
                    "<tr><td class=`"mono`" style=`"font-size:0.75rem;`">$($_.'Resource Name')</td><td style=`"font-size:0.75rem;`">$($_.'Resource Group')</td><td style=`"font-size:0.75rem;`">$($_.'Subscription ID')</td></tr>"
                }) -join "`n"
                $polMoreIndicator = if ($polResCount -gt 10) { "<div class=`"table-footnote`">Showing 10 of $polResCount resources. Export Non-Compliant CSV for the full list.</div>" } else { '' }

                @"
<div style="margin-bottom:10px;border-left:2px solid var(--border);padding-left:10px;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <span style="font-size:0.78rem;font-weight:600;color:var(--text);flex:1;">$polName</span>
        <span class="badge $prClass" style="flex-shrink:0;">$polRisk</span>
        <span style="font-size:0.72rem;color:var(--text-dim);flex-shrink:0;">Security: $polSec</span>
    </div>
    <details style="background:transparent;border:none;margin:0;">
        <summary style="padding:2px 0;font-size:0.75rem;color:var(--accent);">$polResCount violating resource$(if ($polResCount -ne 1) {'s'})</summary>
        <table style="margin-top:4px;"><thead><tr><th style="font-size:0.72rem;">Resource Name</th><th style="font-size:0.72rem;">Resource Group</th><th style="font-size:0.72rem;">Subscription</th></tr></thead><tbody>$polResRows</tbody></table>
        $polMoreIndicator
    </details>
</div>
"@
            }) -join "`n"

@"
<tr>
    <td><details style="background:transparent;border:none;margin:0;"><summary style="padding:4px 0;font-size:0.82rem;">$resType</summary>
        <div style="padding:8px 0 4px;">
            $policySections
        </div>
    </details></td>
    <td class="nc-bad">$uniqueCount</td>
    <td>$policyCount</td>
    <td>$severityBadge</td>
</tr>
"@
        }) -join "`n"
    }

    # ── CE bar charts ──
    $ceGroupSummary = ''
    if ($CEPExportData.Count -gt 0) {
        $ceGroups = $CEPExportData | Group-Object 'CE Control Group'
        $ceGroupSummary = ($ceGroups | ForEach-Object {
            $groupName = $_.Name; $total = $_.Count
            $compliant = ($_.Group | Where-Object { $_.'Status' -like '*Compliant*' -and $_.'Status' -notlike '*Non*' }).Count
            $nc = ($_.Group | Where-Object { $_.'Status' -like '*Non-Compliant*' }).Count
            $na = ($_.Group | Where-Object { $_.'Status' -eq 'Not Assigned' }).Count
            $pct = if ($total -gt 0) { [math]::Round(($compliant / $total) * 100) } else { 0 }
            $barClass = if ($pct -ge 80) { 'bar-green' } elseif ($pct -ge 50) { 'bar-amber' } else { 'bar-red' }
            @"
<div class="ce-group-card">
    <div class="ce-group-name">$groupName</div>
    <div class="ce-bar-container"><div class="ce-bar $barClass" style="width:${pct}%"></div></div>
    <div class="ce-stats">$compliant / $total compliant ($pct%) $(if ($nc -gt 0) { "| <span class='nc-bad'>$nc non-compliant</span>" }) $(if ($na -gt 0) { "| <span class='status-na-text'>$na not assigned</span>" })</div>
</div>
"@
        }) -join "`n"
    }

    # ── Coverage Gaps ──
    $missingControlScopeIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $AssessmentFindings | Where-Object Category -eq 'Missing Controls' | ForEach-Object {
        $_.ScopeIds | ForEach-Object { if ($_) { [void]$missingControlScopeIds.Add($_) } }
    }
    $scopesWithPolicies = $PolicyResults | Group-Object 'Scope Name' | ForEach-Object {
        $scopeEffectCounts = Get-EffectivePolicyEffectCounts -PolicyResults @($_.Group)
        $scopeId = if ($_.Group[0].Scope) { $_.Group[0].Scope } else { $_.Name }
        $hasDeny = -not $missingControlScopeIds.Contains($scopeId)
        $hasDINE = $scopeEffectCounts.Remediating -gt 0
        $hasAudit = $scopeEffectCounts.Audit -gt 0
        $ncRes = ($_.Group | ForEach-Object { if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 } } | Measure-Object -Sum).Sum
        [PSCustomObject]@{
            ScopeName = $_.Name; ScopeType = $_.Group[0].'Scope Type'; Count = $_.Count
            HasDeny = $hasDeny; HasDINE = $hasDINE; HasAudit = $hasAudit; NCResources = $ncRes
        }
    }
    $coverageRows = ($scopesWithPolicies | Sort-Object ScopeType, ScopeName | ForEach-Object {
        $denyBadge = if ($_.HasDeny) { "<span class='badge status-pass'>Yes</span>" } else { "<span class='badge status-fail'>No</span>" }
        $dineBadge = if ($_.HasDINE) { "<span class='badge status-pass'>Yes</span>" } else { "<span class='badge status-warn'>No</span>" }
        $auditBadge = if ($_.HasAudit) { "<span class='badge status-pass'>Yes</span>" } else { "<span class='badge status-warn'>No</span>" }
        $ncClass = if ($_.NCResources -gt 0) { 'nc-bad' } else { 'nc-ok' }
        "<tr><td>$($_.ScopeName)</td><td>$($_.ScopeType)</td><td>$($_.Count)</td><td>$denyBadge</td><td>$dineBadge</td><td>$auditBadge</td><td class=`"$ncClass`">$($_.NCResources)</td></tr>"
    }) -join "`n"

    $scopesNoDeny = @($scopesWithPolicies | Where-Object { -not $_.HasDeny })
    $scopesNoDINE = @($scopesWithPolicies | Where-Object { -not $_.HasDINE })

    # Enforcement gap items
    $enforcementGapAssignmentIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $criticalEnforcementAssignmentIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $AssessmentFindings | Where-Object Category -eq 'Enforcement Gap' | ForEach-Object {
        foreach ($assignmentId in $_.AssignmentIds) {
            [void]$enforcementGapAssignmentIds.Add($assignmentId)
            if ($_.Severity -eq 'Critical') { [void]$criticalEnforcementAssignmentIds.Add($assignmentId) }
        }
    }
    $enforcementGapItems = @($PolicyResults | Where-Object { $enforcementGapAssignmentIds.Contains($_.'Assignment ID') })
    $enforcementGapRows = ($enforcementGapItems | ForEach-Object {
        $impactClass = switch ($_.'Security Impact') { 'High' { 'nc-bad' }; 'Medium' { 'warn-text' }; default { '' } }
        "<tr><td>$($_.'Display Name')</td><td>$($_.'Scope Name')</td><td>$($_.'Effect Type')</td><td class=`"$impactClass`">$($_.'Security Impact')</td><td>$($_.'Risk Level')</td></tr>"
    }) -join "`n"

    # High-security enforcement issues
    $highSecEnforceIssues = @($PolicyResults | Where-Object { $criticalEnforcementAssignmentIds.Contains($_.'Assignment ID') })

    # ── Security posture rows ──
    $securityRows = ($PolicyResults | Sort-Object @{Expression={switch ($_.'Risk Level') { 'High' {0}; 'Medium' {1}; default {2} }}}, @{Expression={switch ($_.'Security Impact') { 'High' {0}; 'Medium' {1}; default {2} }}} | ForEach-Object {
        $riskClass = switch ($_.'Risk Level') { 'High' { 'risk-high' }; 'Medium' { 'risk-med' }; default { 'risk-low' } }
        $secClass = switch ($_.'Security Impact') { 'High' { 'nc-bad' }; 'Medium' { 'warn-text' }; default { '' } }
        $ncVal = if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 }; $ncClass = if ($ncVal -gt 0) { 'nc-bad' } else { 'nc-ok' }
        $catVal = if ($_.Category) { $_.Category } else { '-' }
        "<tr><td>$($_.'Display Name')</td><td><span class=`"badge $riskClass`">$($_.'Risk Level')</span></td><td class=`"$secClass`">$($_.'Security Impact')</td><td>$catVal</td><td>$($_.'Effect Type')</td><td>$($_.'Enforcement Mode')</td><td class=`"$ncClass`">$ncVal</td><td>$($_.'Scope Name')</td></tr>"
    }) -join "`n"

    # ── Cost exposure rows ──
    $costRows = ($PolicyResults | Where-Object { $_.'Cost Exposure' -ne 'None' -and $_.'Cost Exposure' -ne '' -and $_.'Cost Exposure' } | Sort-Object @{Expression={switch ($_.'Cost Exposure') { 'High' {0}; 'Medium' {1}; default {2} }}} | ForEach-Object {
        $costClass = switch ($_.'Cost Exposure') { 'High' { 'risk-high' }; 'Medium' { 'risk-med' }; default { 'risk-low' } }
        $opsClass = switch ($_.'Operational Overhead') { 'High' { 'risk-high' }; 'Medium' { 'risk-med' }; default { 'risk-low' } }
        $catVal = if ($_.Category) { $_.Category } else { '-' }
        "<tr><td>$($_.'Display Name')</td><td><span class=`"badge $costClass`">$($_.'Cost Exposure')</span></td><td><span class=`"badge $opsClass`">$($_.'Operational Overhead')</span></td><td>$catVal</td><td>$($_.'Effect Type')</td><td>$($_.'Enforcement Mode')</td><td>$($_.'Scope Name')</td></tr>"
    }) -join "`n"

    $validCostEvidence = @($CostEvidenceRecords | Where-Object { $null -ne $_ -and (Test-CostEvidenceRecord -Record $_) })
    $costEvidenceRows = ($validCostEvidence | ForEach-Object {
        $amount = ([decimal]$_.Amount).ToString('0.########', [System.Globalization.CultureInfo]::InvariantCulture)
        $description = [System.Net.WebUtility]::HtmlEncode([string]$_.Description)
        $unit = [System.Net.WebUtility]::HtmlEncode([string]$_.Unit)
        $region = [System.Net.WebUtility]::HtmlEncode([string]$_.Region)
        $currency = [System.Net.WebUtility]::HtmlEncode([string]$_.Currency)
        $source = [System.Net.WebUtility]::HtmlEncode([string]$_.Source)
        $sourceUri = [System.Net.WebUtility]::HtmlEncode([string]$_.SourceUri)
        $retrievedAt = [System.Net.WebUtility]::HtmlEncode([string]$_.RetrievedAt)
        $priceOrCostDate = [System.Net.WebUtility]::HtmlEncode([string]$_.PriceOrCostDate)
        "<tr><td>$description</td><td>$amount $currency</td><td>$unit</td><td>$region</td><td><a href=`"$sourceUri`" target=`"_blank`">$source</a></td><td>$priceOrCostDate</td><td>$retrievedAt</td></tr>"
    }) -join "`n"

    # ── Remediation Plan ──
    $remediationItems = @(ConvertTo-AssessmentActions -AssessmentFindings $AssessmentFindings | Select-Object -First 50)

    $remCritical = @($remediationItems | Where-Object { $_.Priority -eq 'Critical' }).Count
    $remHigh = @($remediationItems | Where-Object { $_.Priority -eq 'High' }).Count
    $remMedium = @($remediationItems | Where-Object { $_.Priority -eq 'Medium' }).Count
    # Roadmap phases
    $phase30 = @($remediationItems | Where-Object { $_.Phase -eq '30-day' })
    $phase60 = @($remediationItems | Where-Object { $_.Phase -eq '60-day' })
    $phase90 = @($remediationItems | Where-Object { $_.Phase -eq '90-day' })

    $roadmap30Html = if ($phase30.Count -gt 0) {
        ($phase30 | ForEach-Object { "<li><strong>$($_.Action)</strong><br><span class=`"text-dim`">Finding $(@($_.FindingIds) -join ', ') &middot; $($_.Impact) &middot; Effort: $($_.Effort)</span></li>" }) -join "`n"
    } else { "<li class=`"text-dim`">No critical items identified</li>" }

    $roadmap60Html = if ($phase60.Count -gt 0) {
        ($phase60 | ForEach-Object { "<li><strong>$($_.Action)</strong><br><span class=`"text-dim`">Finding $(@($_.FindingIds) -join ', ') &middot; $($_.Impact) &middot; Effort: $($_.Effort)</span></li>" }) -join "`n"
    } else { "<li class=`"text-dim`">No high-priority items identified</li>" }

    $roadmap90Html = if ($phase90.Count -gt 0) {
        ($phase90 | ForEach-Object { "<li><strong>$($_.Action)</strong><br><span class=`"text-dim`">Finding $(@($_.FindingIds) -join ', ') &middot; $($_.Impact) &middot; Effort: $($_.Effort)</span></li>" }) -join "`n"
    } else { "<li class=`"text-dim`">No medium-priority items identified</li>" }

    $remediationRows = ($remediationItems | ForEach-Object {
        $prioClass = switch ($_.Priority) { 'Critical' { 'status-fail' }; 'High' { 'status-nc' }; 'Medium' { 'status-warn' }; default { 'status-skip' } }
        $effortClass = switch ($_.Effort) { 'Low' { 'status-pass' }; 'Medium' { 'status-warn' }; 'High' { 'status-fail' }; default { '' } }
        "<tr><td><span class=`"badge $prioClass`">$($_.Priority)</span></td><td>$($_.Phase)</td><td>$($_.Action)<br><span class=`"text-dim`">Finding: $(@($_.FindingIds) -join ', ')</span></td><td><span class=`"badge $effortClass`">$($_.Effort)</span></td><td>$($_.Category)</td><td>$($_.Impact)</td><td>$($_.Scope)</td></tr>"
    }) -join "`n"

    $remediationEvidencePolicies = @($PolicyResults | Where-Object { $_.'Is Remediating' -and $_.'Remediation Evidence' })
    $remediationEvidenceRows = ($remediationEvidencePolicies | ForEach-Object {
        $evidence = $_.'Remediation Evidence'
        $stateClass = switch ($evidence.State) {
            'Succeeded' { 'status-pass' }
            'Failed' { 'status-fail' }
            'MissingPermissions' { 'status-fail' }
            'Pending' { 'status-warn' }
            'NotStarted' { 'status-warn' }
            default { 'status-skip' }
        }
        $displayName = [System.Net.WebUtility]::HtmlEncode([string]$_.'Display Name')
        $identity = [System.Net.WebUtility]::HtmlEncode("$($evidence.IdentityType) | $($evidence.PrincipalId)")
        $missingRoles = @($evidence.MissingRoles) -join ', '
        $roleText = "Required $(@($evidence.RequiredRoles).Count) | Available $(@($evidence.AvailableRoles).Count)"
        if ($missingRoles) { $roleText += " | Missing: $missingRoles" }
        $roleText = [System.Net.WebUtility]::HtmlEncode($roleText)
        $taskText = if ($evidence.SelectedTaskId) {
            "$($evidence.SelectedTaskState) | $($evidence.SelectedTaskId) | $(@($evidence.TaskRecords).Count) task record(s)"
        } else { "No task record | $(@($evidence.TaskRecords).Count) task record(s)" }
        $taskText += " | observed $($evidence.EvidenceTimestamp)"
        $taskText = [System.Net.WebUtility]::HtmlEncode($taskText)
        $applicable = if ($null -ne $evidence.ApplicableResourceCount) { [string]$evidence.ApplicableResourceCount } else { 'Not assessed' }
        $lastEvaluation = if ($evidence.LastEvaluation) { [System.Net.WebUtility]::HtmlEncode([string]$evidence.LastEvaluation) } else { 'Not available' }
        $scopeControls = "Exemptions $(@($evidence.Exemptions).Count) | notScopes $(@($evidence.NotScopes).Count) | selectors $(@($evidence.ResourceSelectors).Count) | overrides $(@($evidence.Overrides).Count)"
        $scopeControls = [System.Net.WebUtility]::HtmlEncode($scopeControls)
        $errorText = @($evidence.Error, $evidence.TaskQueryError, $evidence.RoleQueryError | Where-Object { $_ }) -join ' | '
        if (-not $errorText) { $errorText = 'None reported' }
        $errorText = [System.Net.WebUtility]::HtmlEncode($errorText)
        "<tr><td>$displayName</td><td><span class=`"badge $stateClass`">$($evidence.State)</span></td><td>$identity</td><td>$roleText</td><td>$taskText</td><td>$applicable</td><td>$lastEvaluation</td><td>$scopeControls</td><td>$errorText</td></tr>"
    }) -join "`n"

    # ── Key Findings (Executive Summary callouts) ──
    $findingsHtml = ''
    $findingsList = @()

    if ($assessmentState -eq 'NotEvaluated') {
        $queryRecords = if ($DataQuality) { $DataQuality.TotalRecords } else { 0 }
        $queryTimestamp = if ($DataQuality) { $DataQuality.Timestamp } else { 'unknown' }
        $findingsList += "<div class=`"callout callout-info`"><span class=`"callout-icon`">&#x2139;&#xFE0F;</span><div><strong>Not evaluated</strong><p>No policy state evaluations were returned. Compliance has not been established, so zero non-compliance is not reported as a positive finding.</p><p style=`"margin-top:4px;font-size:0.8rem;color:var(--text-dim);`">Data quality: query succeeded; $queryRecords records; timestamp $queryTimestamp; fallback: $(if ($DataQuality -and $DataQuality.FallbackUsed) { 'yes' } else { 'no' }).</p></div></div>"
    } elseif ($assessmentState -eq 'DataUnavailable') {
        $failedQueryNames = if ($DataQuality -and $DataQuality.FailedQueries) { @($DataQuality.FailedQueries.Name) -join ', ' } else { 'PolicyStates' }
        $queryTimestamp = if ($DataQuality) { $DataQuality.Timestamp } else { 'unknown' }
        $findingsList += "<div class=`"callout callout-warning`"><span class=`"callout-icon`">&#x26A0;&#xFE0F;</span><div><strong>Compliance data unavailable</strong><p>The compliance query failed or returned unusable data ($failedQueryNames). No positive compliance conclusion can be made.</p><p style=`"margin-top:4px;font-size:0.8rem;color:var(--text-dim);`">Data quality: query failed; timestamp $queryTimestamp; fallback: $(if ($DataQuality -and $DataQuality.FallbackUsed) { 'yes' } else { 'no' }).</p></div></div>"
    }

    # Precompute enrichment data for callouts
    $assignmentsWithoutObservedNC = $totalAssignments - $assignmentsWithNC
    $assignmentsWithoutObservedNCPct = if ($totalAssignments -gt 0) { [math]::Round(($assignmentsWithoutObservedNC / $totalAssignments) * 100, 1) } else { 100 }
    $topNCTypes = if ($NCExportData.Count -gt 0) {
        ($NCExportData | Select-Object 'Resource ID', 'Resource Type' -Unique | Group-Object 'Resource Type' | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
    } else { '' }
    $topNCPolicies = if ($NCExportData.Count -gt 0) {
        ($NCExportData | Group-Object 'Policy Name' | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object {
            $polName = if ($_.Name.Length -gt 50) { $_.Name.Substring(0, 47) + '...' } else { $_.Name }
            "$polName ($($_.Count))"
        }) -join ', '
    } else { '' }
    $AssessmentFindings | Group-Object Category | Sort-Object Name | ForEach-Object {
        $categoryFindings = @($_.Group)
        $highestSeverity = @('Critical', 'High', 'Medium', 'Low', 'Info') | Where-Object { $_ -in $categoryFindings.Severity } | Select-Object -First 1
        $calloutClass = if ($highestSeverity -eq 'Critical') { 'callout-critical' } elseif ($highestSeverity -in @('High', 'Medium')) { 'callout-warning' } else { 'callout-info' }
        $icon = if ($highestSeverity -eq 'Critical') { '&#x26D4;' } elseif ($highestSeverity -in @('High', 'Medium')) { '&#x26A0;&#xFE0F;' } else { '&#x2139;&#xFE0F;' }
        $findingIds = @($categoryFindings.Id) -join ', '
        $titles = @($categoryFindings | Select-Object -First 3 | ForEach-Object { $_.Title }) -join '; '
        $recommendations = @($categoryFindings.Recommendation | Select-Object -Unique -First 3) -join ' '
        $verification = @($categoryFindings.VerificationSteps | Where-Object { $_ } | Select-Object -Unique -First 3) -join ' '
        $sources = @($categoryFindings.Source | Select-Object -Unique) -join '; '
        $confidence = @($categoryFindings.Confidence | Select-Object -Unique) -join ', '
        $confidenceClass = if ($confidence -eq 'High') { 'status-pass' } elseif ($confidence -match 'Low') { 'status-fail' } else { 'status-warn' }
        $sourceQuality = if ($sources -match 'heuristic|comparison') { 'Derived' } else { 'Observed' }
        $sourceQualityClass = if ($sourceQuality -eq 'Observed') { 'status-pass' } else { 'status-warn' }
        $qualityBadges = if ($_.Name -like 'CEP *') {
            "<span class=`"badge $sourceQualityClass`">Evidence basis: $sourceQuality</span> <span class=`"badge $cepDataQualityClass`">Data quality: $cepDataQualityState</span>"
        } else {
            "<span class=`"badge $sourceQualityClass`">Data quality: $sourceQuality</span>"
        }
        $findingsList += "<div class=`"callout $calloutClass`"><span class=`"callout-icon`">$icon</span><div><strong>$($_.Name) ($($categoryFindings.Count))</strong><p><span class=`"badge $confidenceClass`">Confidence: $confidence</span> $qualityBadges</p><p><strong>Fact:</strong> $titles</p><p><strong>Interpretation:</strong> These observations indicate a potential $($_.Name.ToLowerInvariant()) condition; effective impact and applicability require validation.</p><p><strong>Verify:</strong> $verification</p><p><strong>Action:</strong> $recommendations</p><p style=`"margin-top:4px;font-size:0.8rem;color:var(--text-dim);`"><strong>Finding IDs:</strong> $findingIds &middot; <strong>Source:</strong> $sources</p></div></div>"
    }
    if ($tFail -gt 0 -or $tWarn -gt 0) {
        $scoreSummary = if ($CEPAssessment.ScoreState -eq 'Measured' -and $null -ne $ceScore) { "${ceScore}% passed" } else { 'score N/A' }
        $cepReviewRecommendation = if ($tFail -gt 0 -and $tWarn -gt 0) {
            'Review failed and warning evidence and complete all manual tests with an authorised certification body.'
        } elseif ($tFail -gt 0) {
            'Review failed check evidence and complete all manual tests with an authorised certification body.'
        } else {
            'Review warning evidence and complete all manual tests with an authorised certification body.'
        }
        $findingsList += "<div class=`"callout callout-warning`"><span class=`"callout-icon`">&#x1F4CB;</span><div><strong>CE+ Automated Checks Require Review: $scoreSummary</strong><p>$tFail checks failing and $tWarn warnings. The score excludes prerequisites, warnings, skipped checks, and manual checks.</p><p style=`"margin-top:4px;font-size:0.8rem;color:var(--text-dim);`"><em>Recommendation:</em> $cepReviewRecommendation</p></div></div>"
    }
    if ($hasEvaluatedCompliance -and $enforcedCount -gt 0 -and $auditOnlyCount -eq 0 -and $totalNC -eq 0) {
        $findingsList += "<div class=`"callout callout-success`"><span class=`"callout-icon`">&#x2705;</span><div><strong>Strong Policy Posture</strong><p>All $enforcedCount assignments are enforced with zero non-compliant resources. Your environment is fully compliant with all assigned policy rules.</p></div></div>"
    } elseif ($hasEvaluatedCompliance -and $enforcedCount -gt 0 -and $totalNC -eq 0) {
        $findingsList += "<div class=`"callout callout-success`"><span class=`"callout-icon`">&#x2705;</span><div><strong>Zero Non-Compliance</strong><p>No non-compliant resources detected across $totalAssignments assignments. $enforcedCount enforced, $auditOnlyCount in audit/DoNotEnforce mode.</p></div></div>"
    }
    if ($denyCount -gt 0 -and $scopesNoDeny.Count -eq 0) {
        $findingsList += "<div class=`"callout callout-success`"><span class=`"callout-icon`">&#x2705;</span><div><strong>Preventive Controls Active</strong><p>All $($scopesWithPolicies.Count) monitored scopes have at least one Deny policy. Non-compliant deployments will be blocked.</p></div></div>"
    }
    if ($CEPAssessment.ScoreState -eq 'Measured' -and $tAutomated -gt 0 -and $tFail -eq 0 -and $tWarn -eq 0) {
        $findingsList += "<div class=`"callout callout-success`"><span class=`"callout-icon`">&#x2705;</span><div><strong>CE+ Automated Checks: ${ceScore}% passed</strong><p>All $tAutomated automated checks passed. Manual testing and independent certification are still required.</p></div></div>"
    }
    $findingsHtml = $findingsList -join "`n"

    $policyByAssignmentId = @{}
    foreach ($policy in $PolicyResults) {
        foreach ($assignmentKey in @($policy.'Assignment ID', $policy.'Assignment Name')) {
            if ($assignmentKey) { $policyByAssignmentId[[string]$assignmentKey] = $policy }
        }
    }
    $actionByFindingId = @{}
    foreach ($action in $remediationItems) {
        foreach ($findingId in @($action.FindingIds)) {
            if ($findingId) { $actionByFindingId[[string]$findingId] = $action }
        }
    }
    $executiveRiskCandidates = @($AssessmentFindings | ForEach-Object {
        $finding = $_
        $matchingPolicies = @($finding.AssignmentIds | ForEach-Object {
            if ($policyByAssignmentId.ContainsKey([string]$_)) { $policyByAssignmentId[[string]$_] }
        })
        if ($finding.Category -eq 'Non-Compliance' -and $matchingPolicies.Count -gt 0) {
            $policy = $matchingPolicies[0]
            $displayName = [string]$policy.'Display Name'
            $summaryName = $displayName -replace '(?i)\s+\(subscription:\s*[0-9a-f-]+\)$', ''
            $subscriptionKey = if ($displayName -match '(?i)\(subscription:\s*([0-9a-f-]+)\)$') {
                $Matches[1]
            } elseif ([string]$policy.Scope -match '(?i)/subscriptions/([^/]+)') {
                $Matches[1]
            } elseif ($policy.'Scope Type' -eq 'Subscription') {
                [string]$policy.'Scope Name'
            } else {
                ''
            }
            [PSCustomObject]@{
                GroupKey = if ($subscriptionKey) { "Non-Compliance|$summaryName" } else { [string]$finding.Id }
                Kind = if ($subscriptionKey) { 'Non-Compliance' } else { 'Finding' }
                FindingId = [string]$finding.Id
                Name = $summaryName
                Severity = [string]$finding.Severity
                Title = [string]$finding.Title
                AffectedResources = if ($policy.'Non-Compliant Resources' -match '^\d+$') { [int]$policy.'Non-Compliant Resources' } else { 0 }
                SubscriptionKey = $subscriptionKey
            }
        } else {
            [PSCustomObject]@{
                GroupKey = [string]$finding.Id
                Kind = 'Finding'
                FindingId = [string]$finding.Id
                Name = ''
                Severity = [string]$finding.Severity
                Title = [string]$finding.Title
                AffectedResources = 0
                SubscriptionKey = ''
            }
        }
    })
    $executiveRiskSummaries = @($executiveRiskCandidates | Group-Object GroupKey | ForEach-Object {
        $items = @($_.Group)
        $severity = @($items | Sort-Object @{ Expression = { @('Critical', 'High', 'Medium', 'Low', 'Info').IndexOf([string]$_.Severity) } } | Select-Object -First 1).Severity
        $phase = switch ($severity) { 'Critical' { '30-day' }; 'High' { '60-day' }; default { '90-day' } }
        if ($items[0].Kind -eq 'Non-Compliance') {
            $subscriptionCount = @($items.SubscriptionKey | Where-Object { $_ } | Select-Object -Unique).Count
            $affectedResources = ($items.AffectedResources | Measure-Object -Sum).Sum
            $subscriptionLabel = if ($subscriptionCount -eq 1) { 'subscription' } else { 'subscriptions' }
            $title = "$($items[0].Name) &middot; $subscriptionCount $subscriptionLabel &middot; $affectedResources affected resources"
            $actionText = "Prioritise remediation for '$($items[0].Name)' across $subscriptionCount $subscriptionLabel ($affectedResources affected resources)."
            [PSCustomObject]@{ Severity = $severity; Phase = $phase; Title = $title; Action = $actionText }
        } else {
            $findingAction = $actionByFindingId[[string]$items[0].FindingId]
            $actionText = if ($findingAction) { [string]$findingAction.Action } else { "Review and assign ownership for '$($items[0].Title)'." }
            [PSCustomObject]@{ Severity = $severity; Phase = $phase; Title = $items[0].Title; Action = $actionText }
        }
    })
    $executiveRiskItems = @($executiveRiskSummaries |
        Sort-Object @{ Expression = { @('Critical', 'High', 'Medium', 'Low', 'Info').IndexOf([string]$_.Severity) } }, Title |
        Select-Object -First 5 | ForEach-Object {
            $severityClass = switch ($_.Severity) { 'Critical' { 'status-fail' }; 'High' { 'status-fail' }; 'Medium' { 'status-warn' }; default { 'status-skip' } }
            $safeTitle = [System.Net.WebUtility]::HtmlEncode([string]$_.Title) -replace '&amp;middot;', '&middot;'
            "<li><span class=`"badge $severityClass`">$($_.Severity)</span><span>$safeTitle</span></li>"
        })
    $executiveRisksHtml = if ($executiveRiskItems.Count -gt 0) { $executiveRiskItems -join "`n" } else { '<li class="text-dim">No material deterministic findings were identified.</li>' }

    $executiveActionItems = @($executiveRiskSummaries |
        Sort-Object @{ Expression = { @('Critical', 'High', 'Medium', 'Low', 'Info').IndexOf([string]$_.Severity) } }, Title |
        Select-Object -First 5 | ForEach-Object {
            $safeAction = [System.Net.WebUtility]::HtmlEncode([string]$_.Action)
            "<li><strong>$($_.Phase)</strong><span>$safeAction</span></li>"
        })
    $executiveActionsHtml = if ($executiveActionItems.Count -gt 0) { $executiveActionItems -join "`n" } else { '<li class="text-dim">No deterministic actions were generated.</li>' }
    $engineerActionItems = @($remediationItems | Select-Object -First 5 | ForEach-Object {
        $safeAction = [System.Net.WebUtility]::HtmlEncode([string]$_.Action)
        "<li><strong>$($_.Phase)</strong><span>$safeAction</span></li>"
    })
    $engineerActionsHtml = if ($engineerActionItems.Count -gt 0) { $engineerActionItems -join "`n" } else { '<li class="text-dim">No deterministic actions were generated.</li>' }

    $affectedSubscriptionCount = @($NCExportData | ForEach-Object { $_.'Subscription ID' } | Where-Object { $_ } | Select-Object -Unique).Count
    $affectedResourceTypeCount = @($NCExportData | ForEach-Object { $_.'Resource Type' } | Where-Object { $_ } | Select-Object -Unique).Count
    $missingRemediationIdentityCount = @($PolicyResults | Where-Object {
        $_.'Is Remediating' -and (-not $_.'Remediation Evidence' -or -not $_.'Remediation Evidence'.PrincipalId)
    }).Count
    $managementGroupCount = @($PolicyResults | Where-Object { $_.'Scope Type' -eq 'Management Group' } | ForEach-Object { $_.'Scope Name' } | Where-Object { $_ } | Select-Object -Unique).Count
    $subscriptionScopeCount = @($PolicyResults | Where-Object { $_.'Scope Type' -eq 'Subscription' } | ForEach-Object { $_.'Scope Name' } | Where-Object { $_ } | Select-Object -Unique).Count
    $highRiskInitiativeAssignmentCount = @($PolicyResults | Where-Object { $_.'Policy Type' -match 'Initiative' -and $_.'Risk Level' -eq 'High' }).Count
    $criticalFindingCount = @($AssessmentFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $executiveOutcome = if (-not $hasEvaluatedCompliance) {
        if ($assessmentState -eq 'NotEvaluated') { 'Assessment incomplete' } else { 'Decision blocked' }
    } elseif ($assessmentState -eq 'EvaluatedNonCompliant' -or $totalNC -gt 0 -or $criticalFindingCount -gt 0) {
        'Action required'
    } else {
        'No material issues observed'
    }
    $executiveOutcomeClass = if (-not $hasEvaluatedCompliance) {
        'card-amber'
    } elseif ($assessmentState -eq 'EvaluatedNonCompliant' -or $totalNC -gt 0 -or $criticalFindingCount -gt 0) {
        'card-red'
    } else {
        'card-green'
    }
    $evidenceStatus = if ($hasEvaluatedCompliance -and $failedQueryCount -eq 0) {
        'Evaluated'
    } elseif ($hasEvaluatedCompliance) {
        'Partial'
    } elseif ($assessmentState -eq 'NotEvaluated') {
        'Not evaluated'
    } else {
        'Unavailable'
    }
    $topInitiativesSummary = @($PolicyResults | Where-Object { $_.'Policy Type' -match 'Initiative' } |
        Sort-Object { if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 } } -Descending |
        Select-Object -First 3 | ForEach-Object { [System.Net.WebUtility]::HtmlEncode([string]$_.'Display Name') }) -join '; '
    $topCategoriesSummary = @($PolicyResults | Group-Object Category | Sort-Object Count -Descending | Select-Object -First 3 |
        ForEach-Object { "$([System.Net.WebUtility]::HtmlEncode([string]$_.Name)) ($($_.Count))" }) -join '; '
    $topResourceTypesSummary = if ($topNCTypes) { [System.Net.WebUtility]::HtmlEncode($topNCTypes) } else { 'No affected resource types returned' }
    $topFailingPoliciesSummary = if ($topNCPolicies) { [System.Net.WebUtility]::HtmlEncode($topNCPolicies) } else { 'No failing policies returned' }

    # ── Architecture insights ──
    $antiPatternItems = @()

    # AP-1: Disabled policies
    if ($disabledCount -gt 0) {
        $disabledPolicies = @($PolicyResults | Where-Object { $_.'Is Disabled' })
        $disabledNames = ($disabledPolicies | ForEach-Object { $_.'Display Name' }) -join '</li><li>'
        $antiPatternItems += @"
<div class="ap-item" style="margin-bottom:12px;border-left:3px solid var(--amber);padding:6px 12px;">
    <details>
        <summary style="cursor:pointer;font-weight:600;font-size:0.88rem;color:var(--amber);">&#x26D4; $disabledCount disabled $(if ($disabledCount -eq 1) {'policy'} else {'policies'})</summary>
        <div style="padding:8px 0;font-size:0.82rem;">
            <p><strong>What this means:</strong> These assignments exist in your environment but their effect is set to <code>Disabled</code>. Azure does not evaluate resources against them at all &mdash; they contribute nothing to compliance or security.</p>
            <p><strong>Why it matters:</strong> Disabled policies create management clutter, make audit reports confusing, and can give a false sense of coverage. They also consume assignment quota (max 500 per scope).</p>
            <p style="margin-top:6px;"><strong>Affected policies:</strong></p>
            <ul style="margin:4px 0 0 16px;font-size:0.8rem;"><li>$disabledNames</li></ul>
            <p style="margin-top:8px;"><strong>Recommended action:</strong> Review each and either re-enable with the intended effect, or delete the assignment if no longer needed.</p>
            <p style="margin-top:6px;font-size:0.75rem;color:var(--text-dim);">&#x1F4DA; <strong>Reference:</strong> <a href="https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects#disabled" target="_blank" style="color:var(--accent);">Azure Policy effects &mdash; Disabled</a> | <a href="https://learn.microsoft.com/en-us/azure/governance/policy/overview#maximum-count-of-azure-policy-objects" target="_blank" style="color:var(--accent);">Assignment limits</a></p>
        </div>
    </details>
</div>
"@
    }

    # AP-2: High-security policies with enforcement disabled
    if ($highSecEnforceIssues.Count -gt 0) {
        $hsNames = ($highSecEnforceIssues | ForEach-Object {
            $eff = $_.'Effect Type'
            "<li><strong>$($_.'Display Name')</strong> <span style='color:var(--text-dim);font-size:0.75rem;'>($eff @ $($_.'Scope Name'))</span></li>"
        }) -join ''
        $antiPatternItems += @"
<div class="ap-item" style="margin-bottom:12px;border-left:3px solid var(--red);padding:6px 12px;">
    <details>
        <summary style="cursor:pointer;font-weight:600;font-size:0.88rem;color:var(--red);">&#x1F6A8; $($highSecEnforceIssues.Count) high-security $(if ($highSecEnforceIssues.Count -eq 1) {'policy'} else {'policies'}) with enforcement disabled</summary>
        <div style="padding:8px 0;font-size:0.82rem;">
            <p><strong>Fact:</strong> These policy assignments have a high Security Impact score and their enforcement mode is <code>DoNotEnforce</code>; configured effects are not applied.</p>
            <p><strong>Interpretation:</strong> Preventive or remediation value may be absent, depending on each configured effect and effective scope.</p>
            <p style="margin-top:6px;"><strong>Affected policies:</strong></p>
            <ul style="margin:4px 0 0 16px;font-size:0.8rem;">$hsNames</ul>
            <p><strong>Verify:</strong> Confirm the intended effect, exclusions, inherited assignments, and workload impact in a controlled scope.</p>
            <p style="margin-top:8px;"><strong>Action:</strong> Where validation supports enforcement, change <code>enforcementMode</code> from <code>DoNotEnforce</code> to <code>Default</code> through a staged rollout.</p>
            <p style="margin-top:6px;font-size:0.75rem;color:var(--text-dim);">&#x1F4DA; <strong>Reference:</strong> <a href="https://learn.microsoft.com/en-us/azure/governance/policy/concepts/assignment-structure#enforcement-mode" target="_blank" style="color:var(--accent);">Azure Policy enforcement mode</a> | <a href="https://learn.microsoft.com/en-us/azure/governance/policy/how-to/policy-safe-deployment-practices" target="_blank" style="color:var(--accent);">Safe deployment practices for Azure Policy</a></p>
        </div>
    </details>
</div>
"@
    }

    # AP-3: Scopes lacking Deny policies
    if ($scopesNoDeny.Count -gt 0 -and $scopesWithPolicies.Count -gt 0) {
        $denyGapRatio = "$($scopesNoDeny.Count) of $($scopesWithPolicies.Count)"
        $noDenyList = ($scopesNoDeny | Sort-Object ScopeType, ScopeName | ForEach-Object {
            "<li><strong>$($_.ScopeName)</strong> <span style='color:var(--text-dim);font-size:0.75rem;'>($($_.ScopeType) &mdash; $($_.Count) assignments, NC: $($_.NCResources))</span></li>"
        }) -join ''
        $antiPatternItems += @"
<div class="ap-item" style="margin-bottom:12px;border-left:3px solid var(--amber);padding:6px 12px;">
    <details>
        <summary style="cursor:pointer;font-weight:600;font-size:0.88rem;color:var(--amber);">&#x1F6E1;&#xFE0F; $denyGapRatio scopes lack Deny policies</summary>
        <div style="padding:8px 0;font-size:0.82rem;">
            <p><strong>What this means:</strong> These scopes have policy assignments (Audit, DINE, etc.) but none with a <code>Deny</code> effect. Without Deny policies, non-compliant resources can be deployed freely at these scopes &mdash; they'll only be flagged after the fact.</p>
            <p><strong>Why it matters:</strong> Deny policies are the only policy effect that prevents non-compliant resources from being created or modified. Scopes without Deny rely entirely on detection and manual remediation, which is reactive and slower. This is especially critical for security-sensitive scopes (production subscriptions, shared services).</p>
            <p style="margin-top:6px;"><strong>Affected scopes:</strong></p>
            <ul style="margin:4px 0 0 16px;font-size:0.8rem;">$noDenyList</ul>
            <p style="margin-top:8px;"><strong>Recommended action:</strong> Assign Deny policies for your most critical guardrails at these scopes. Common candidates: allowed locations, allowed VM SKUs, require HTTPS for storage accounts, block public IP creation. Start with policies assigned at the Management Group level so they inherit downward.</p>
            <p style="margin-top:6px;font-size:0.75rem;color:var(--text-dim);">&#x1F4DA; <strong>Reference:</strong> <a href="https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects#deny" target="_blank" style="color:var(--accent);">Azure Policy effects &mdash; Deny</a> | <a href="https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/governance" target="_blank" style="color:var(--accent);">CAF: Governance design area</a></p>
        </div>
    </details>
</div>
"@
    }

    # AP-4: Scopes without assigned DINE/Modify effects
    if ($scopesNoDINE.Count -gt 0 -and $scopesWithPolicies.Count -gt 0) {
        $dineGapRatio = "$($scopesNoDINE.Count) of $($scopesWithPolicies.Count)"
        $noDINEList = ($scopesNoDINE | Sort-Object ScopeType, ScopeName | ForEach-Object {
            "<li><strong>$($_.ScopeName)</strong> <span style='color:var(--text-dim);font-size:0.75rem;'>($($_.ScopeType) &mdash; $($_.Count) assignments, NC: $($_.NCResources))</span></li>"
        }) -join ''
        $antiPatternItems += @"
<div class="ap-item" style="margin-bottom:12px;border-left:3px solid var(--amber);padding:6px 12px;">
    <details>
        <summary style="cursor:pointer;font-weight:600;font-size:0.88rem;color:var(--amber);">&#x1F527; $dineGapRatio scopes have no assigned DINE/Modify effect</summary>
        <div style="padding:8px 0;font-size:0.82rem;">
            <p><strong>What this means:</strong> These scopes have no <code>DeployIfNotExists</code> (DINE) or <code>Modify</code> policies. When configurations drift or are deployed without required components (e.g. missing diagnostic settings, missing backup), they must be fixed manually.</p>
            <p><strong>Why it matters:</strong> Without an assigned DINE/Modify effect, applicable gaps may require manual correction. Assignment presence alone does not establish remediation: task state, identity, roles, scope controls, and policy evaluation must also be verified.</p>
            <p style="margin-top:6px;"><strong>Affected scopes:</strong></p>
            <ul style="margin:4px 0 0 16px;font-size:0.8rem;">$noDINEList</ul>
            <p style="margin-top:8px;"><strong>Recommended action:</strong> Assign DINE/Modify policies for: diagnostic settings (send logs to Log Analytics), backup configuration, encryption at rest, network watcher, and tagging. Azure has many built-in DINE policies &mdash; start with <em>Configure diagnostic settings</em> and <em>Configure backup on VMs</em>.</p>
            <p style="margin-top:6px;font-size:0.75rem;color:var(--text-dim);">&#x1F4DA; <strong>Reference:</strong> <a href="https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects#deployifnotexists" target="_blank" style="color:var(--accent);">Azure Policy effects &mdash; DeployIfNotExists</a> | <a href="https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources" target="_blank" style="color:var(--accent);">Remediate non-compliant resources</a></p>
        </div>
    </details>
</div>
"@
    }

    # AP-5: Duplicate policy assignments at the same scope
    $duplicates = @($PolicyResults | Group-Object 'Policy Definition ID', 'Scope Name' | Where-Object { $_.Count -gt 1 })
    if ($duplicates.Count -gt 0) {
        $totalDupAssignments = ($duplicates | Measure-Object -Property Count -Sum).Sum
        $dupList = ($duplicates | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
            $policyName = ($_.Group[0]).'Display Name'
            $scopeName = ($_.Group[0]).'Scope Name'
            "<li><strong>$policyName</strong> at <em>$scopeName</em> <span style='color:var(--text-dim);font-size:0.75rem;'>($($_.Count) assignments)</span></li>"
        }) -join ''
        $antiPatternItems += @"
<div class="ap-item" style="margin-bottom:12px;border-left:3px solid var(--amber);padding:6px 12px;">
    <details>
        <summary style="cursor:pointer;font-weight:600;font-size:0.88rem;color:var(--amber);">&#x1F503; $($duplicates.Count) duplicate policy assignment$(if ($duplicates.Count -gt 1) {'s'}) ($totalDupAssignments total)</summary>
        <div style="padding:8px 0;font-size:0.82rem;">
            <p><strong>What this means:</strong> The same policy definition is assigned more than once at the same scope. Duplicate assignments don't provide additional protection &mdash; they just consume assignment quota and create confusion.</p>
            <p><strong>Why it matters:</strong> Duplicates make it harder to understand which assignment controls what, complicate compliance reporting, and can cause conflicting parameters if the assignments have different settings.</p>
            <p style="margin-top:6px;"><strong>Top duplicates:</strong></p>
            <ul style="margin:4px 0 0 16px;font-size:0.8rem;">$dupList</ul>
            <p style="margin-top:8px;"><strong>Recommended action:</strong> Review and remove redundant assignments. Keep the one with the correct parameters and enforcement mode.</p>
            <p style="margin-top:6px;font-size:0.75rem;color:var(--text-dim);">&#x1F4DA; <strong>Reference:</strong> <a href="https://learn.microsoft.com/en-us/azure/governance/policy/overview#maximum-count-of-azure-policy-objects" target="_blank" style="color:var(--accent);">Azure Policy limits</a></p>
        </div>
    </details>
</div>
"@
    }

    $antiPatternsHtml = if ($antiPatternItems.Count -gt 0) {
        "<p style='font-size:0.8rem;color:var(--text-dim);margin-bottom:10px;'>$($antiPatternItems.Count) issue$(if ($antiPatternItems.Count -gt 1) {'s'}) detected. Click each to expand details, affected resources, and references.</p>" + ($antiPatternItems -join "`n")
    } else {
        "<p class='text-dim'>&#x2705; No anti-patterns detected. Policy architecture appears well-designed.</p>"
    }

    # Hierarchy verdict
    $hierarchyVerdict = if ($mgAssignments -ge $subAssignments -and $mgAssignments -ge $rgAssignments) {
        "<span class='badge status-pass'>Centralised</span> Policy assignments are primarily at the Management Group level, indicating a mature centralised governance model with good inheritance."
    } elseif ($subAssignments -gt $mgAssignments) {
        "<span class='badge status-warn'>Subscription-level</span> Most policies are assigned at the Subscription level. Consider consolidating to Management Group level for consistent governance."
    } else {
        "<span class='badge status-fail'>Fragmented</span> Significant Resource Group-level assignments suggest ad-hoc policy management. Consider elevating to higher scopes."
    }

    # Preventive / Detective / Remediation ratio
    $controlTotal = [math]::Max(($denyCount + $auditEffectCount + $dineModifyCount), 1)
    $preventivePct = [math]::Round(($denyCount / $controlTotal) * 100)
    $detectivePct = [math]::Round(($auditEffectCount / $controlTotal) * 100)
    $remediativePct = [math]::Round(($dineModifyCount / $controlTotal) * 100)

    # Control balance health assessment (suggested: Preventive 35-45%, Detective 30-40%, Remediation 15-25%)
    $prevHealth = if ($preventivePct -ge 35 -and $preventivePct -le 45) { 'green' } elseif ($preventivePct -ge 25) { 'amber' } else { 'red' }
    $detHealth  = if ($detectivePct -ge 30 -and $detectivePct -le 40) { 'green' } elseif ($detectivePct -le 55) { 'amber' } else { 'red' }
    $remHealth  = if ($remediativePct -ge 15 -and $remediativePct -le 25) { 'green' } elseif ($remediativePct -ge 10) { 'amber' } else { 'red' }
    $controlBalanceTakeaways = [System.Collections.Generic.List[string]]::new()
    if ($detectivePct -gt 55) {
        $controlBalanceTakeaways.Add('<li><strong>Detection-heavy</strong> (Audit &gt;55%) &mdash; The measured effect distribution relies heavily on detective controls. Verify applicability before changing critical Audit effects to Deny.</li>')
    }
    if ($preventivePct -lt 25) {
        $controlBalanceTakeaways.Add('<li><strong>Low prevention</strong> (&lt;25%) &mdash; The measured distribution contains few preventive effects. Verify inherited controls and applicability before adding Deny effects.</li>')
    }
    if ($remediativePct -lt 15) {
        $controlBalanceTakeaways.Add('<li><strong>Low remediation</strong> (&lt;15%) &mdash; The measured distribution contains few DINE/Modify effects. Verify which configurations are suitable for automated remediation.</li>')
    }
    if ($disabledCount -gt 0) {
        $controlBalanceTakeaways.Add('<li><strong>Disabled policies present</strong> &mdash; Entirely disabled assignments are not evaluated and require an ownership review.</li>')
    }
    $controlBalanceTakeawaysHtml = if ($controlBalanceTakeaways.Count -gt 0) {
        "<p><strong>Threshold findings:</strong></p><ul style='margin:4px 0 0 16px;padding:0;'>$($controlBalanceTakeaways -join '')</ul>"
    } else {
        '<p class="text-dim">No control-balance threshold findings were triggered.</p>'
    }
    $overallBalance = if ($prevHealth -eq 'green' -and $detHealth -eq 'green' -and $remHealth -eq 'green') { 'Well Balanced' 
    } elseif ($prevHealth -eq 'red' -or $detHealth -eq 'red' -or $remHealth -eq 'red') { 'Imbalanced' 
    } else { 'Moderate' }
    $balanceBadgeClass = switch ($overallBalance) { 'Well Balanced' { 'status-pass' }; 'Imbalanced' { 'status-fail' }; default { 'status-warn' } }

    # ── Framework mapping ──
    $frameworkRows = ''
    if ($CEPAssessment.Requested) {
        $ceStatus = switch ($CEPAssessment.State) {
            'PrerequisiteUnavailable' { "<span class='badge status-ne'>Prerequisite unavailable</span>" }
            'EvaluationFailed' { "<span class='badge status-fail'>Evaluation failed</span>" }
            'PartiallyEvaluated' { "<span class='badge status-warn'>Partially evaluated</span>" }
            default {
                if ($tFail -gt 0) { "<span class='badge status-fail'>Checks failed</span>" }
                elseif ($tWarn -gt 0) { "<span class='badge status-warn'>Review required</span>" }
                else { "<span class='badge status-pass'>Automated checks passed</span>" }
            }
        }
        $ceScoreText = if ($CEPAssessment.ScoreState -eq 'Measured' -and $null -ne $ceScore) { "${ceScore}%" } else { 'N/A' }
        $frameworkRows += "<tr><td><strong>&#x1F6E1;&#xFE0F; Cyber Essentials Plus</strong> <span class='experimental-tag'>Experimental</span><br><span class='text-dim' style='font-size:0.75rem;'>UK NCSC certification for cyber security hygiene. This mapping is experimental and not an official certification assessment.</span></td><td>$ceStatus</td><td><strong>$ceScoreText</strong><br><span class='text-dim'>$($CEPAssessment.ScoreState)</span></td><td>$tPass passed, $tFail failed, $tWarn warnings, $tManual manual checks. Assessment state: $($CEPAssessment.State). Independent assessment by an authorised certification body remains required.</td></tr>`n"
    }
    $regPolicies = @($PolicyResults | Where-Object { $_.'Policy Type' -eq 'Initiative (Regulatory)' })
    # Track assigned regulatory initiative names to avoid duplicating them as "Inferred"
    # Also include non-regulatory initiatives whose names match known frameworks (e.g. "Microsoft Cloud Security Benchmark" is an Initiative, not Initiative (Regulatory))
    $assignedRegNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $allInitiatives = @($PolicyResults | Where-Object { $_.'Policy Type' -in @('Initiative', 'Initiative (Regulatory)') })
    foreach ($init in $allInitiatives) {
        [void]$assignedRegNames.Add($init.'Display Name')
    }
    if ($regPolicies.Count -gt 0) {
        # One row per regulatory initiative (not grouped)
        $regPolicies | Select-Object -Property 'Display Name','Non-Compliant Resources','Total Resources','Scope Name','Enforcement Mode','Effect Type' -Unique | ForEach-Object {
            $regDispName = $_.'Display Name'
            $regNC = if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 }
            $regTotal = if ($_.'Total Resources' -match '^\d+$') { [int]$_.'Total Resources' } else { 0 }
            $regScope = $_.'Scope Name'
            $regEnforce = $_.'Enforcement Mode'
            $regStatusBadge = if ($regTotal -le 0) { "<span class='badge status-warn'>Not evaluated</span>" } elseif ($regNC -gt 0) { "<span class='badge status-fail'>Non-Compliant</span>" } else { "<span class='badge status-pass'>Compliant</span>" }
            $regNCText = if ($regTotal -le 0) { '<span class="text-dim">No policy state evaluations available</span>' } elseif ($regNC -gt 0) { "<span class='nc-bad'>$regNC non-compliant</span> resources" } else { '<span style="color:var(--green)">All evaluated resources compliant</span>' }
            # Calculate compliance score from total/NC resources
            $regScoreText = 'N/A'
            if ($regTotal -gt 0) {
                $regCompliant = $regTotal - $regNC
                $regScorePct = [math]::Round(($regCompliant / $regTotal) * 100, 1)
                $regScoreColor = if ($regScorePct -ge 90) { 'var(--green)' } elseif ($regScorePct -ge 70) { 'var(--amber)' } else { 'var(--red)' }
                $regScoreText = "<span style='color:$regScoreColor;font-weight:600;'>${regScorePct}%</span>"
            }
            $frameworkRows += "<tr><td><strong>&#x1F4DC; $([System.Web.HttpUtility]::HtmlEncode($regDispName))</strong><br><span class='text-dim' style='font-size:0.75rem;'>Regulatory compliance initiative &mdash; Scope: $([System.Web.HttpUtility]::HtmlEncode($regScope))</span></td><td>$regStatusBadge</td><td>$regScoreText</td><td>$regNCText$(if ($regTotal -gt 0) { " out of <strong>$regTotal</strong> evaluated" }). Enforcement: <strong>$regEnforce</strong>.</td></tr>`n"
            # Track this name so we don't duplicate it as "Inferred" below
            [void]$assignedRegNames.Add($regDispName)
        }
    }
    # Framework availability is discovered from official Azure built-in initiative metadata.
    # Helper: check if any assigned regulatory initiative name matches a pattern
    function Test-FrameworkAssigned {
        param([string]$Pattern)
        if ($assignedRegNames.Count -eq 0) { return $false }
        foreach ($name in $assignedRegNames) {
            if ($name -match $Pattern) { return $true }
        }
        return $false
    }

    function Get-AvailableFrameworkInitiatives {
        param([string]$Pattern)
        if (-not $initDefMetadata) { return @() }
        return @($initDefMetadata.Values |
            Where-Object { $_.DisplayName -match $Pattern } |
            Sort-Object DisplayName -Unique |
            ForEach-Object {
                if ($_.Version) { "$($_.DisplayName) (definition v$($_.Version))" } else { $_.DisplayName }
            })
    }

    function Add-UnmeasuredFrameworkRow {
        param([string]$Icon, [string]$Name, [string]$Description, [string]$Pattern)
        $available = @(Get-AvailableFrameworkInitiatives -Pattern $Pattern)
        $sourceText = if ($available.Count -gt 0) {
            "Official Azure built-in initiative(s) available: <em>$([System.Web.HttpUtility]::HtmlEncode(($available | Select-Object -First 3) -join '; '))</em>. Assign the appropriate initiative to obtain Azure Policy control-level results."
        } else {
            'No matching built-in initiative was returned by Azure Resource Graph for the current tenant and permissions. Check the official Azure Policy built-in initiatives catalog.'
        }
        return "<tr><td>$Icon $Name<br><span class='text-dim' style='font-size:0.75rem;'>$Description</span></td><td><span class='badge status-ne'>Not measured</span></td><td>N/A</td><td><strong>No corresponding initiative assignment detected.</strong> $sourceText</td></tr>`n"
    }

    if (-not (Test-FrameworkAssigned 'security benchmark|cloud security benchmark|azure security benchmark')) {
        $frameworkRows += Add-UnmeasuredFrameworkRow -Icon '&#x1F50D;' -Name 'Microsoft Cloud Security Benchmark' -Description "Microsoft's recommended security baseline for Azure" -Pattern 'Microsoft.*cloud security benchmark|Azure Security Benchmark'
    }
    if (-not (Test-FrameworkAssigned 'CIS.*Azure|CIS.*Foundations|CIS.*Benchmark')) {
        $frameworkRows += Add-UnmeasuredFrameworkRow -Icon '&#x1F3DB;&#xFE0F;' -Name 'CIS Azure Foundations' -Description 'Center for Internet Security benchmark for Azure' -Pattern 'CIS.*Azure|CIS.*Foundations|CIS.*Benchmark'
    }
    if (-not (Test-FrameworkAssigned 'NIST|800-53')) {
        $frameworkRows += Add-UnmeasuredFrameworkRow -Icon '&#x1F3E2;' -Name 'NIST SP 800-53' -Description 'US federal standard for information security controls' -Pattern 'NIST.*800-53|800-53.*NIST'
    }
    if (-not (Test-FrameworkAssigned 'ISO.?27001|ISO.?27002')) {
        $frameworkRows += Add-UnmeasuredFrameworkRow -Icon '&#x1F30D;' -Name 'ISO/IEC 27001' -Description 'International standard for information security management' -Pattern 'ISO.?IEC.*27001|ISO.?27001'
    }

    $executiveComplianceResults = [System.Collections.Generic.List[object]]::new()
    if ($ALZData -and [int]$ALZData.TotalRecommended -gt 0) {
        $alzExecutiveClass = if ([decimal]$ALZData.CoveragePercent -ge 75) { 'status-pass' } elseif ([decimal]$ALZData.CoveragePercent -ge 50) { 'status-warn' } else { 'status-fail' }
        $executiveComplianceResults.Add([PSCustomObject]@{
            Name = 'Azure Landing Zone'
            Status = 'Coverage measured'
            StatusClass = $alzExecutiveClass
            Result = "$($ALZData.CoveragePercent)% detected"
            Detail = "$($ALZData.EnforcedCoveragePercent)% enforced; $($ALZData.TotalMissing) applicable gaps across $($ALZData.TotalRecommended) assessed assets. Inventory coverage, not a compliance score."
            Order = 0
        })
    }
    if ($CEPAssessment.ScoreState -eq 'Measured' -and $null -ne $ceScore) {
        $cepExecutiveStatus = if ($tFail -gt 0) { 'Checks failed' } elseif ($tWarn -gt 0) { 'Review required' } else { 'Automated checks passed' }
        $cepExecutiveClass = if ($tFail -gt 0) { 'status-fail' } elseif ($tWarn -gt 0) { 'status-warn' } else { 'status-pass' }
        $executiveComplianceResults.Add([PSCustomObject]@{
            Name = 'Cyber Essentials Plus'
            Status = $cepExecutiveStatus
            StatusClass = $cepExecutiveClass
            Result = "${ceScore}% tool indicator"
            Detail = "$tPass passed, $tFail failed, $tWarn warnings, and $tManual manual checks. Independent certification remains required."
            Order = 1
        })
    }

    $measuredFrameworkAssignments = @($allInitiatives | Where-Object {
        $_.'Policy Type' -eq 'Initiative (Regulatory)' -or
        $_.'Display Name' -match 'Microsoft.*Cloud Security Benchmark|Azure Security Benchmark|CIS.*Azure|CIS.*Foundations|NIST.*800-53|800-53.*NIST|ISO.?IEC.*27001|ISO.?27001'
    })
    @($measuredFrameworkAssignments | Group-Object 'Display Name' | Sort-Object Name) | ForEach-Object {
        $evaluatedAssignments = @($_.Group | Where-Object { ($_.'Total Resources' -match '^\d+$') -and [int]$_.'Total Resources' -gt 0 })
        if ($evaluatedAssignments.Count -eq 0) { return }

        $initiativeTotal = ($evaluatedAssignments | ForEach-Object { [int]$_.'Total Resources' } | Measure-Object -Sum).Sum
        $initiativeNC = ($evaluatedAssignments | ForEach-Object { if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 } } | Measure-Object -Sum).Sum
        $initiativeScore = [math]::Round((($initiativeTotal - $initiativeNC) / $initiativeTotal) * 100, 1)
        $initiativeStatus = if ($initiativeNC -gt 0) { 'Action required' } else { 'Compliant' }
        $initiativeClass = if ($initiativeNC -gt 0) { 'status-fail' } else { 'status-pass' }
        $executiveComplianceResults.Add([PSCustomObject]@{
            Name = [string]$_.Name
            Status = $initiativeStatus
            StatusClass = $initiativeClass
            Result = "${initiativeScore}%"
            Detail = "$initiativeNC non-compliant out of $initiativeTotal policy evaluation records across $($evaluatedAssignments.Count) assignment(s)."
            Order = 2
        })
    }

    $executiveComplianceItemsHtml = if ($executiveComplianceResults.Count -gt 0) {
        @($executiveComplianceResults | Sort-Object Order, Name | ForEach-Object {
            $safeFrameworkName = [System.Web.HttpUtility]::HtmlEncode([string]$_.Name)
            $safeFrameworkStatus = [System.Web.HttpUtility]::HtmlEncode([string]$_.Status)
            $safeFrameworkResult = [System.Web.HttpUtility]::HtmlEncode([string]$_.Result)
            $safeFrameworkDetail = [System.Web.HttpUtility]::HtmlEncode([string]$_.Detail)
            "<div class=`"executive-compliance-item`"><div class=`"executive-compliance-heading`"><strong>$safeFrameworkName</strong><span class=`"badge $($_.StatusClass)`">$safeFrameworkStatus</span></div><div class=`"executive-compliance-result`">$safeFrameworkResult</div><p>$safeFrameworkDetail</p></div>"
        }) -join "`n"
    } else {
        '<p class="executive-compliance-empty">No assigned standards or Landing Zone assets produced a measured result in this assessment.</p>'
    }

    # ── Overall Posture Rating ──
    $overallRating = if ($highRiskCount -eq 0 -and $totalNC -eq 0 -and $enforcedCount -gt 0 -and $auditOnlyCount -eq 0) { 'Excellent' }
                     elseif ($highRiskCount -le 2 -and $totalNC -le 10 -and $highSecEnforceIssues.Count -eq 0) { 'Good' }
                     elseif ($highRiskCount -le 5 -and $totalNC -le 50) { 'Needs Improvement' }
                     else { 'At Risk' }
    $ratingClass = switch ($overallRating) { 'Excellent' { 'rating-excellent' }; 'Good' { 'rating-good' }; 'Needs Improvement' { 'rating-warn' }; default { 'rating-risk' } }
    $ratingIcon = switch ($overallRating) { 'Excellent' { '&#x2705;' }; 'Good' { '&#x1F7E2;' }; 'Needs Improvement' { '&#x1F7E0;' }; default { '&#x1F534;' } }
    $highRiskAssignmentNoun = if ($highRiskCount -eq 1) { 'assignment' } else { 'assignments' }
    $affectedResourceNoun = if ($totalNC -eq 1) { 'resource' } else { 'resources' }
    $overallRatingBasis = "$highRiskCount high-risk $highRiskAssignmentNoun and $totalNC unique affected $affectedResourceNoun"

    # ═══════════════════════════════════════════════════════════════
    #  BUILD HTML DOCUMENT
    # ═══════════════════════════════════════════════════════════════

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure Policy Assessment Report</title>
<style>
/* ── Reset & Theme ── */
:root {
    --bg: #0d1117; --surface: #161b22; --surface-2: #1c2230; --border: #30363d;
    --text: #e6edf3; --text-dim: #8b949e; --accent: #58a6ff; --accent-subtle: rgba(88,166,255,0.1);
    --green: #3fb950; --red: #f85149; --amber: #d29922; --purple: #bc8cff; --magenta: #f778ba;
    --green-bg: rgba(63,185,80,0.12); --red-bg: rgba(248,81,73,0.12); --amber-bg: rgba(210,153,34,0.12);
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
html, body { max-width: 100%; overflow-x: hidden; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; font-size: 14px; }

/* ── Layout ── */
.container { max-width: 1440px; margin: 0 auto; padding: 24px; }
section { margin-bottom: 36px; scroll-margin-top: 70px; }

/* ── Header ── */
header { background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%); border-bottom: 2px solid var(--accent); padding: 14px 20px; margin-bottom: 0; border-radius: 8px 8px 0 0; }
.header-main { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 14px; }
.header-copy { min-width: 0; }
.header-title-row { display: flex; align-items: baseline; gap: 12px; min-width: 0; }
header h1 { font-size: 1.3rem; line-height: 1.25; color: var(--accent); }
header .subtitle { font-size: 0.82rem; line-height: 1.3; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
header .meta { color: var(--text-dim); font-size: 0.72rem; line-height: 1.3; display: flex; gap: 0; flex-wrap: nowrap; white-space: nowrap; overflow-x: auto; scrollbar-width: none; margin-top: 4px; }
header .meta::-webkit-scrollbar { display: none; }
header .meta span { flex: 0 0 auto; }
header .meta span + span::before { content: '\00B7'; padding: 0 8px; color: var(--border); }
.rating-badge { display: inline-flex; align-items: center; gap: 6px; padding: 5px 11px; border-radius: 20px; font-weight: 600; font-size: 0.78rem; white-space: nowrap; }
.rating-excellent { background: var(--green-bg); color: var(--green); }
.rating-good { background: var(--green-bg); color: var(--green); }
.rating-warn { background: var(--amber-bg); color: var(--amber); }
.rating-risk { background: var(--red-bg); color: var(--red); }

/* ── Navigation ── */
nav { position: sticky; top: 0; z-index: 100; background: var(--surface); border: 1px solid var(--border); border-top: none; display: flex; gap: 0; overflow-x: auto; padding: 0; }
nav { scrollbar-width: none; }
nav::-webkit-scrollbar { display: none; }
nav a { padding: 12px 20px; color: var(--text-dim); text-decoration: none; font-size: 0.82rem; white-space: nowrap; border-bottom: 2px solid transparent; transition: all 0.2s; font-weight: 500; }
nav a:hover { color: var(--text); background: var(--accent-subtle); }
nav a.active { color: var(--accent); border-bottom-color: var(--accent); }
.report-page { display: none; margin: 20px 0 0; }
.report-page.active { display: block; animation: page-enter 0.18s ease-out; }
.page-lead { min-height: 0; }
@keyframes page-enter { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }
.page-heading { display: flex; align-items: end; justify-content: space-between; gap: 20px; margin-bottom: 14px; }
.page-heading h2 { color: var(--accent); font-size: 1.35rem; }
.page-heading p { color: var(--text-dim); max-width: 720px; font-size: 0.85rem; }
.page-status { color: var(--text-dim); font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }
.page-summary { min-height: 0; }
.page-summary .summary-cards { margin-bottom: 14px; }
.page-summary .card { padding: 10px 14px; min-width: 105px; }
.page-summary .card-num { font-size: 1.45rem; }
.page-summary .executive-kpis { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px; }
.page-summary .executive-kpis .card { min-width: 0; min-height: 86px; display: flex; flex-direction: column; justify-content: center; }
.page-summary .executive-kpis .executive-outcome { font-size: 1.05rem; line-height: 1.25; }
.page-summary .executive-kpis .executive-evidence { font-size: 1.15rem; }
.decision-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.decision-grid.three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.compact-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; min-width: 0; }
.compact-panel h3 { color: var(--accent); font-size: 0.9rem; margin-bottom: 7px; }
.compact-panel p { color: var(--text-dim); font-size: 0.8rem; }
.consequence-negative { border-left: 3px solid var(--red); }
.consequence-positive { border-left: 3px solid var(--green); }
.executive-compliance { margin-bottom: 14px; }
.executive-compliance > summary { color: var(--accent); }
.executive-compliance > .details-content > p { margin-bottom: 10px; }
.executive-compliance-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0 18px; }
.executive-compliance-item { min-width: 0; padding: 10px 0; border-top: 1px solid var(--border); }
.executive-compliance-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; }
.executive-compliance-heading strong { color: var(--text); font-size: 0.82rem; line-height: 1.3; }
.executive-compliance-heading .badge { flex: 0 0 auto; }
.executive-compliance-result { margin-top: 5px; color: var(--accent); font-size: 1rem; font-weight: 700; }
.executive-compliance-item p, .executive-compliance-empty { margin-top: 3px; color: var(--text-dim); font-size: 0.72rem; line-height: 1.35; }
.executive-decisions { margin-top: 14px; }
.executive-decision-list { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
.compact-list { list-style: none; display: grid; gap: 6px; }
.compact-list li { display: flex; align-items: flex-start; gap: 8px; color: var(--text-dim); font-size: 0.79rem; line-height: 1.35; }
.compact-list li strong { color: var(--text); min-width: 48px; }
.report-page > .section-header, .report-page > details.section-disclosure > summary .section-num { display: none; }

/* ── Section Headers ── */
.section-header { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
.section-header h2 { font-size: 1.2rem; color: var(--accent); }
.section-header .section-num { color: var(--text-dim); font-size: 0.85rem; font-weight: 400; }
h3.sub-title { color: var(--text); font-size: 1rem; margin: 20px 0 10px; }

/* ── Cards ── */
.summary-cards { display: flex; gap: 14px; margin-bottom: 20px; flex-wrap: wrap; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 20px; min-width: 120px; text-align: center; }
.card-num { font-size: 1.8rem; font-weight: 700; }
.card-label { font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }
.card-green .card-num { color: var(--green); }
.card-red .card-num { color: var(--red); }
.card-amber .card-num { color: var(--amber); }
.card-blue .card-num { color: var(--accent); }
.card-purple .card-num { color: var(--purple); }
.card-magenta .card-num { color: var(--magenta); }
.card-gray .card-num { color: var(--text-dim); }

/* ── Callout boxes ── */
.callout { display: flex; gap: 12px; padding: 14px 18px; border-radius: 8px; margin-bottom: 12px; border-left: 4px solid; align-items: flex-start; }
.callout-icon { font-size: 1.2rem; flex-shrink: 0; margin-top: 2px; }
.callout p { font-size: 0.85rem; color: var(--text-dim); margin-top: 4px; }
.callout-critical { background: var(--red-bg); border-color: var(--red); }
.callout-warning { background: var(--amber-bg); border-color: var(--amber); }
.callout-success { background: var(--green-bg); border-color: var(--green); }
.callout-info { background: var(--accent-subtle); border-color: var(--accent); }

/* ── Tables ── */
.table-wrap { overflow-x: auto; margin-top: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
th { background: var(--surface-2); color: var(--accent); text-align: left; padding: 10px 12px; position: sticky; top: 0; cursor: pointer; white-space: nowrap; border-bottom: 2px solid var(--border); user-select: none; }
th:hover { background: #243044; }
th.sortable::after { content: ' \2195'; font-size: 0.7rem; color: var(--text-dim); }
td { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:hover { background: var(--accent-subtle); }
.mono { font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.78rem; }

/* ── Badges ── */
.badge { padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; display: inline-block; }
.type-policy .badge, .badge.type-policy { background: rgba(230,237,243,0.1); color: var(--text); }
.type-initiative .badge, .badge.type-initiative { background: rgba(210,153,34,0.15); color: var(--amber); }
.type-regulatory .badge, .badge.type-regulatory { background: rgba(247,120,186,0.15); color: var(--magenta); }
.risk-high { background: var(--red-bg); color: var(--red); }
.risk-med { background: var(--amber-bg); color: var(--amber); }
.risk-low { background: var(--green-bg); color: var(--green); }
.nc-bad { color: var(--red); font-weight: 600; }
.nc-ok { color: var(--green); }
.warn-text { color: var(--amber); }
.badge.status-pass { background: var(--green-bg); color: var(--green); }
.badge.status-fail { background: var(--red-bg); color: var(--red); }
.badge.status-warn { background: var(--amber-bg); color: var(--amber); }
.badge.status-skip { background: rgba(139,148,158,0.15); color: var(--text-dim); }
.badge.status-manual { background: rgba(188,140,255,0.15); color: var(--purple); }
.badge.status-ok { background: var(--green-bg); color: var(--green); }
.badge.status-nc { background: var(--red-bg); color: var(--red); }
.badge.status-na { background: rgba(139,148,158,0.15); color: var(--text-dim); }
.badge.status-ne { background: var(--amber-bg); color: var(--amber); }
.status-na-text { color: var(--text-dim); }

/* ── CE bar charts ── */
.ce-group-card { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px 16px; margin-bottom: 10px; }
.ce-group-name { font-weight: 600; margin-bottom: 6px; font-size: 0.9rem; }
.ce-bar-container { background: rgba(255,255,255,0.05); border-radius: 4px; height: 8px; overflow: hidden; margin-bottom: 6px; }
.ce-bar { height: 100%; border-radius: 4px; transition: width 0.6s ease; }
.bar-green { background: var(--green); } .bar-amber { background: var(--amber); } .bar-red { background: var(--red); }
.ce-stats { font-size: 0.8rem; color: var(--text-dim); }

/* ── Grids ── */
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
.grid-2 > *, .grid-3 > *, .roadmap > * { min-width: 0; }
.insight-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.insight-box h4 { color: var(--accent); font-size: 0.9rem; margin-bottom: 8px; }
.insight-box p, .insight-box ul { font-size: 0.85rem; color: var(--text-dim); }
.insight-box .big-num { font-size: 2rem; font-weight: 700; }

/* ── Collapsible details ── */
details { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 16px; }
details > summary { padding: 14px 18px; cursor: pointer; font-weight: 600; font-size: 0.9rem; color: var(--text); user-select: none; list-style: none; display: flex; align-items: center; gap: 8px; }
details > summary::before { content: '\25B6'; font-size: 0.7rem; color: var(--text-dim); transition: transform 0.2s; }
details[open] > summary::before { transform: rotate(90deg); }
details > summary:hover { background: var(--accent-subtle); }
details > .details-content { padding: 0 18px 18px; }
.report-disclosure > summary { min-height: 52px; }
.report-disclosure > summary .disclosure-meta { margin-left: auto; color: var(--text-dim); font-size: 0.75rem; font-weight: 400; text-align: right; }
.report-disclosure[open] > summary { border-bottom: 1px solid var(--border); margin-bottom: 14px; }
.report-disclosure.depth-3 { background: var(--bg); border-style: dashed; }
.report-disclosure.depth-3 > summary { color: var(--text-dim); }
.section-disclosure { background: transparent; border: 0; border-radius: 0; margin: 0; }
.section-disclosure > summary { padding: 0 0 10px; border-bottom: 1px solid var(--border); font-size: 1.2rem; color: var(--accent); }
.section-disclosure > summary::before { margin-right: 4px; }
.section-disclosure > summary:hover { background: transparent; color: var(--text); }
.section-disclosure > summary .section-num { color: var(--text-dim); font-size: 0.85rem; font-weight: 400; }
.section-disclosure > summary .disclosure-hint { margin-left: auto; color: var(--text-dim); font-size: 0.75rem; font-weight: 400; }
.section-disclosure[open] > summary { margin-bottom: 16px; }
.section-content { padding-top: 0; }

/* ── Filters ── */
.filter-bar { display: flex; gap: 12px; margin-bottom: 12px; align-items: center; flex-wrap: wrap; }
.filter-bar input { background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 8px 14px; border-radius: 6px; font-size: 0.85rem; min-width: 280px; }
.filter-bar input:focus { outline: none; border-color: var(--accent); }
.filter-bar .count { color: var(--text-dim); font-size: 0.82rem; }
.copy-btn { background: var(--surface-2); border: 1px solid var(--border); color: var(--text-dim); padding: 5px 12px; border-radius: 6px; font-size: 0.78rem; cursor: pointer; transition: all 0.2s; display: inline-flex; align-items: center; gap: 4px; }
.copy-btn:hover { background: var(--accent-subtle); color: var(--accent); border-color: var(--accent); }
.copy-btn.copied { background: var(--green-bg); color: var(--green); border-color: var(--green); }

/* ── Roadmap ── */
.roadmap { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin-bottom: 24px; }
.roadmap-phase { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 18px; position: relative; border-top: 3px solid var(--border); }
.roadmap-phase.phase-30 { border-top-color: var(--red); }
.roadmap-phase.phase-60 { border-top-color: var(--amber); }
.roadmap-phase.phase-90 { border-top-color: var(--green); }
.roadmap-phase h4 { font-size: 0.95rem; margin-bottom: 4px; }
.roadmap-phase .phase-label { font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px; }
.roadmap-phase ul { padding-left: 18px; }
.roadmap-phase li { margin-bottom: 10px; font-size: 0.85rem; }

/* ── Finding list ── */
.finding-list { padding-left: 20px; }
.finding-list li { margin-bottom: 10px; font-size: 0.85rem; color: var(--text-dim); }
.finding-list li strong { color: var(--text); }

/* ── Progress bar ── */
.progress-bar { background: rgba(255,255,255,0.05); border-radius: 4px; height: 24px; overflow: hidden; position: relative; }
.progress-fill { height: 100%; border-radius: 4px; transition: width 0.6s ease; display: flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: 600; }
.progress-fill.fill-green { background: var(--green); color: #0d1117; }
.progress-fill.fill-amber { background: var(--amber); color: #0d1117; }
.progress-fill.fill-red { background: var(--red); color: #0d1117; }

/* ── Legend & Note Boxes ── */
.legend { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; }
.legend h4 { color: var(--accent); font-size: 0.9rem; margin-bottom: 10px; display: flex; align-items: center; gap: 6px; }
.legend-grid { display: flex; flex-wrap: wrap; gap: 14px 28px; }
.legend-item { display: flex; align-items: center; gap: 6px; font-size: 0.8rem; color: var(--text-dim); }
.legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.legend-dot.dot-red { background: var(--red); }
.legend-dot.dot-amber { background: var(--amber); }
.legend-dot.dot-green { background: var(--green); }
.legend-dot.dot-blue { background: var(--accent); }
.legend-dot.dot-purple { background: var(--purple); }
.legend-dot.dot-gray { background: var(--text-dim); }
.legend-dot.dot-magenta { background: var(--magenta); }

.note-box { background: var(--accent-subtle); border: 1px solid rgba(88,166,255,0.2); border-radius: 6px; padding: 10px 14px; margin-bottom: 14px; font-size: 0.82rem; color: var(--text-dim); display: flex; align-items: flex-start; gap: 8px; }
.note-box .note-icon { flex-shrink: 0; font-size: 1rem; }

/* ── Column Info Tips ── */
.col-info { display: inline-flex; align-items: center; justify-content: center; width: 15px; height: 15px; border-radius: 50%; background: rgba(88,166,255,0.15); color: var(--accent); font-size: 0.6rem; font-weight: 700; font-style: normal; cursor: help; margin-left: 4px; vertical-align: middle; border: 1px solid rgba(88,166,255,0.3); }
.col-info:hover { background: rgba(88,166,255,0.3); }
.info-tooltip { position: fixed; z-index: 9999; background: #1c2230; color: #e6edf3; padding: 10px 14px; border-radius: 8px; font-size: 0.8rem; font-weight: 400; line-height: 1.5; max-width: 300px; border: 1px solid #30363d; box-shadow: 0 8px 24px rgba(0,0,0,0.5); pointer-events: none; opacity: 0; transition: opacity 0.15s ease; }
.info-tooltip.visible { opacity: 1; }
.table-footnote { font-size: 0.78rem; color: var(--text-dim); margin-top: 6px; padding: 6px 0; font-style: italic; }
.rec-cell { max-width: 280px; white-space: normal; font-size: 0.82rem; line-height: 1.35; }

.section-intro { background: var(--surface); border-left: 3px solid var(--accent); border-radius: 0 6px 6px 0; padding: 12px 16px; margin-bottom: 20px; }
.section-intro p { font-size: 0.85rem; color: var(--text-dim); margin-bottom: 4px; }
.section-intro p:last-child { margin-bottom: 0; }
.section-intro strong { color: var(--text); }

.guide-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 0 0 8px 8px; margin-bottom: 24px; }
.guide-panel > summary { padding: 12px 20px; cursor: pointer; font-weight: 600; font-size: 0.88rem; color: var(--accent); user-select: none; list-style: none; display: flex; align-items: center; gap: 8px; }
.guide-panel > summary::before { content: '\25B6'; font-size: 0.65rem; color: var(--text-dim); transition: transform 0.2s; }
.guide-panel[open] > summary::before { transform: rotate(90deg); }
.guide-panel > summary:hover { background: var(--accent-subtle); }
.guide-content { padding: 0 20px 18px; }
.guide-content h4 { color: var(--text); font-size: 0.88rem; margin: 14px 0 6px; }
.guide-content h4:first-child { margin-top: 0; }
.guide-content p, .guide-content li { font-size: 0.82rem; color: var(--text-dim); }
.guide-content ul { padding-left: 18px; margin-bottom: 8px; }
.guide-content li { margin-bottom: 4px; }
.guide-columns { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }


.glossary { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px 24px; margin-bottom: 24px; }
.glossary h3 { color: var(--accent); font-size: 1rem; margin-bottom: 14px; }
.glossary-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 32px; }
.glossary-item { display: flex; gap: 8px; font-size: 0.82rem; padding: 4px 0; }
.glossary-term { font-weight: 600; color: var(--text); min-width: 140px; flex-shrink: 0; }
.glossary-def { color: var(--text-dim); }

/* ── Disclaimer Banner ── */
.disclaimer-banner { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 1px solid rgba(88,166,255,0.25); border-radius: 8px; padding: 14px 20px; margin-bottom: 20px; display: flex; align-items: flex-start; gap: 10px; font-size: 0.8rem; color: var(--text-dim); line-height: 1.5; }
.disclaimer-banner .disclaimer-icon { flex-shrink: 0; font-size: 1.1rem; }
.disclaimer-banner strong { color: var(--accent); }
.disclaimer-banner a { color: var(--accent); text-decoration: underline; }
.experimental-tag { display: inline-block; background: rgba(255,166,0,0.15); color: #ffa600; border: 1px solid rgba(255,166,0,0.3); border-radius: 4px; padding: 1px 7px; font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; vertical-align: middle; margin-left: 4px; }

/* ── Misc ── */
.text-dim { color: var(--text-dim); font-size: 0.85rem; }
.empty { text-align: center; padding: 48px 24px; color: var(--text-dim); }
.empty h3 { margin-bottom: 8px; color: var(--text); }
.stat-row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 0.85rem; }
.stat-row:last-child { border-bottom: none; }
.divider { border: none; border-top: 1px solid var(--border); margin: 24px 0; }

/* ── Print styles ── */
@media print {
    body { background: #fff; color: #1a1a1a; font-size: 11px; }
    :root { --bg: #fff; --surface: #f6f8fa; --surface-2: #eaeef2; --border: #d0d7de; --text: #1a1a1a; --text-dim: #57606a; --accent: #0969da; }
    nav { display: none; }
    .container { max-width: 100%; padding: 0; }
    section { break-inside: avoid; margin-bottom: 20px; }
    details[open] { break-inside: avoid; }
    .summary-cards { flex-wrap: wrap; }
    .card { border: 1px solid #d0d7de; }
    .callout { break-inside: avoid; }
    .filter-bar { display: none; }
    .report-page { display: block !important; min-height: 0; break-before: page; }
    .report-page:first-of-type { break-before: auto; }
    .page-detail { display: block; }
    details > * { display: block !important; }
}

@media (max-width: 1024px) { .grid-2, .grid-3, .roadmap { grid-template-columns: 1fr; } }
@media (max-width: 768px) {
    .container { padding: 8px; }
    header { padding: 9px 10px; }
    .header-main { gap: 8px; }
    .header-title-row { display: block; }
    header h1 { font-size: 1.05rem; }
    header .subtitle { display: none; }
    header .meta { display: flex; font-size: 0.62rem; margin-top: 3px; }
    header .meta span + span::before { padding: 0 5px; }
    .rating-badge { padding: 4px 9px; font-size: 0.72rem; }
    .summary-cards { flex-direction: column; }
    .card { min-width: auto; }
    .filter-bar input { min-width: 100%; }
    nav { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); overflow: hidden; }
    nav a { padding: 7px 2px; font-size: 0.62rem; line-height: 1.15; white-space: normal; text-align: center; }
    .page-summary .summary-cards { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 6px; }
    .page-summary .executive-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .page-summary .executive-kpis .card:first-child { grid-column: 1 / -1; }
    .page-summary .card { padding: 7px 5px; min-width: 0; }
    .page-summary .card-num { font-size: 1.05rem; }
    .page-summary .card-label { font-size: 0.62rem; line-height: 1.2; }
    .decision-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px; }
    .page-summary .decision-grid { grid-template-columns: 1fr; }
    .decision-grid.three { grid-template-columns: 1fr; }
    .executive-compliance-grid { grid-template-columns: 1fr; }
    .executive-decision-list { grid-template-columns: 1fr; }
    .compact-panel { padding: 8px; }
    .compact-panel h3 { font-size: 0.76rem; }
    .compact-panel p, .compact-list li { font-size: 0.7rem; }
    .compact-list { gap: 4px; }
    .report-page { margin-top: 10px; }
    .page-heading { align-items: center; margin-bottom: 8px; }
    .page-heading h2 { font-size: 1rem; }
    .page-heading p, .page-status { display: none; }
    .section-disclosure > summary { flex-wrap: wrap; }
    .section-disclosure > summary .disclosure-hint { width: 100%; margin-left: 20px; text-align: left; }
}
</style>
</head>
<body>
<div class="container">

<!-- ══════════════════════════════════════════════════════ -->
<!--  HEADER                                               -->
<!-- ══════════════════════════════════════════════════════ -->
<header>
    <div class="header-main">
        <div class="header-copy">
            <div class="header-title-row">
                <h1>&#x1F6E1;&#xFE0F; Azure Policy Assessment Report</h1>
                <p class="subtitle">Comprehensive Policy, Security &amp; Compliance Analysis</p>
            </div>
            <div class="meta" aria-label="Report metadata">
                <span>Generated: $reportDate</span>
                $(if ($TenantName) { "<span>Tenant: $TenantName</span>" })
                $(if ($FilterLabel) { "<span>&#x1F50D; Filter: $FilterLabel</span>" } else { "<span>Scope: All (tenant-wide)</span>" })
                <span>Script v$ScriptVersion</span>
                <span>$totalAssignments assignments analysed</span>
            </div>
        </div>
        <div class="rating-badge $ratingClass" title="Tool risk indicator based on $overallRatingBasis; not an official compliance or certification rating">$ratingIcon $overallRating</div>
    </div>
</header>

<!-- ══════════════════════════════════════════════════════ -->
<!--  NAVIGATION                                           -->
<!-- ══════════════════════════════════════════════════════ -->
<nav id="main-nav">
    <a href="#page-summary" class="active" data-page="page-summary">Summary</a>
    <a href="#page-csa" data-page="page-csa">CSA / Architect</a>
    <a href="#page-engineer" data-page="page-engineer">Engineer</a>
    <a href="#page-evidence" data-page="page-evidence">Evidence</a>
    <a href="#page-methodology" data-page="page-methodology">Methodology</a>
</nav>

<main id="report-pages">
<section id="page-summary" class="report-page page-lead active" data-report-page data-page-group="page-summary">
    <div class="page-heading"><div><h2>Executive Summary</h2><p>What is happening, why it matters, the expected effect of action or inaction, and the decisions leadership must make.</p></div><span class="page-status">Start here</span></div>
    <div class="page-summary">
        <div class="summary-cards executive-kpis">
            <div class="card $executiveOutcomeClass"><div class="card-num executive-outcome">$executiveOutcome</div><div class="card-label">Assessment Outcome</div></div>
            <div class="card $(if ($totalNC -gt 0) { 'card-red' } else { 'card-green' })"><div class="card-num">$(if ($hasEvaluatedCompliance) { $totalNC } else { 'N/A' })</div><div class="card-label">Affected Resources</div></div>
            <div class="card $(if ($affectedSubscriptionCount -gt 0) { 'card-amber' } else { 'card-green' })"><div class="card-num">$(if ($hasEvaluatedCompliance) { $affectedSubscriptionCount } else { 'N/A' })</div><div class="card-label">Affected Subscriptions</div></div>
            <div class="card $(if ($criticalFindingCount -gt 0) { 'card-red' } else { 'card-green' })"><div class="card-num">$criticalFindingCount</div><div class="card-label">Critical Findings</div></div>
            <div class="card $(if ($failedQueryCount -eq 0 -and $hasEvaluatedCompliance) { 'card-green' } else { 'card-amber' })"><div class="card-num executive-evidence">$evidenceStatus</div><div class="card-label">Evidence Status</div></div>
        </div>
        <details class="report-disclosure depth-2 executive-compliance" id="details-executive-compliance">
            <summary>Compliance &amp; Landing Zone Results <span class="disclosure-meta">$($executiveComplianceResults.Count) measured result$(if ($executiveComplianceResults.Count -ne 1) { 's' })</span></summary>
            <div class="details-content">
                <p>Only assigned standards and Landing Zone assets with measured evidence are included. Percentages use each result's stated evidence base and do not establish certification.</p>
                <div class="executive-compliance-grid">$executiveComplianceItemsHtml</div>
            </div>
        </details>
        <div class="decision-grid">
            <div class="compact-panel"><h3>Priority Risks</h3><ul class="compact-list">$executiveRisksHtml</ul></div>
            <div class="compact-panel"><h3>Priority Actions</h3><ul class="compact-list">$executiveActionsHtml</ul></div>
        </div>
        <div class="decision-grid three">
            <div class="compact-panel"><h3>What Is Happening</h3>$(if ($hasEvaluatedCompliance) { "<p><strong>$totalNC</strong> resources are affected across <strong>$affectedSubscriptionCount</strong> subscriptions. The assessment produced <strong>$criticalFindingCount</strong> critical findings; <strong>$auditOnlyCount</strong> assignments do not apply their configured effects and <strong>$missingRemediationIdentityCount</strong> identity blockers can prevent automated correction.</p>" } else { '<p><strong>No reliable resource posture conclusion is available.</strong> Restore usable policy-state evidence before making a compliance decision.</p>' })</div>
            <div class="compact-panel consequence-negative"><h3>If No Action Is Taken</h3>$(if ($hasEvaluatedCompliance) { '<p>Observed violations remain unresolved, controls that only detect continue to allow exposure, and identity blockers continue to delay automated correction. Regulatory and operational risk persists until findings are remediated or explicitly accepted.</p>' } else { '<p>No resource posture conclusion is available. Leadership remains unable to quantify exposure or prioritise remediation reliably until evidence collection is restored and the environment is evaluated.</p>' })</div>
            <div class="compact-panel consequence-positive"><h3>If Action Is Taken</h3>$(if ($hasEvaluatedCompliance) { "<p>The prioritised plan targets the <strong>$totalNC</strong> observed affected resources, <strong>$auditOnlyCount</strong> enforcement gaps, and <strong>$missingRemediationIdentityCount</strong> identity blockers. A subsequent Azure Policy evaluation must confirm the actual reduction; action does not by itself establish compliance or certification.</p>" } else { '<p>Restore evidence collection and rerun the assessment first. The resulting baseline can then support prioritised remediation and measurable follow-up; no posture improvement is claimed before evaluation.</p>' })</div>
        </div>
        <div class="compact-panel executive-decisions"><h3>Leadership Decisions Required</h3><ul class="compact-list executive-decision-list"><li><strong>Own</strong><span>Assign accountable owners for $remCritical critical remediation actions.</span></li><li><strong>Fund</strong><span>Approve capacity and change windows for the 30/60/90-day plan.</span></li><li><strong>Accept</strong><span>Record explicit risk acceptance for deferred findings and exceptions.</span></li></ul></div>
    </div>
</section>

<section id="page-csa" class="report-page page-lead" data-report-page data-page-group="page-csa">
    <div class="page-heading"><div><h2>CSA / Architect</h2><p>Governance coverage, risk concentration, control architecture, and structural gaps.</p></div><span class="page-status">Architecture view</span></div>
    <div class="page-summary">
        <div class="summary-cards">
            <div class="card card-blue"><div class="card-num">$managementGroupCount</div><div class="card-label">Management Groups</div></div>
            <div class="card card-blue"><div class="card-num">$subscriptionScopeCount</div><div class="card-label">Subscription Scopes</div></div>
            <div class="card $(if ($highRiskInitiativeAssignmentCount -gt 0) { 'card-red' } else { 'card-green' })"><div class="card-num">$highRiskInitiativeAssignmentCount</div><div class="card-label">High-Risk Initiative Assignments</div></div>
            <div class="card $(if ($scopesNoDeny.Count -gt 0) { 'card-amber' } else { 'card-green' })"><div class="card-num">$($scopesNoDeny.Count)</div><div class="card-label">Scopes Without Preventive Controls</div></div>
        </div>
        <div class="decision-grid three">
            <div class="compact-panel"><h3>Risk Concentration</h3><p><strong>Initiatives:</strong> $(if ($topInitiativesSummary) { $topInitiativesSummary } else { 'None returned' })</p><p><strong>Categories:</strong> $(if ($topCategoriesSummary) { $topCategoriesSummary } else { 'None returned' })</p><p><strong>Resource types:</strong> $topResourceTypesSummary</p></div>
            <div class="compact-panel"><h3>Governance Gaps</h3><ul class="compact-list"><li><strong>$($scopesNoDeny.Count)</strong><span>scopes without preventive controls</span></li><li><strong>$auditOnlyCount</strong><span>assignments without enforcement</span></li><li><strong>$missingRemediationIdentityCount</strong><span>remediating assignments missing identity evidence</span></li></ul></div>
            <div class="compact-panel"><h3>Control Architecture</h3><ul class="compact-list"><li><strong>$denyCount</strong><span>preventive controls</span></li><li><strong>$auditEffectCount</strong><span>detective controls</span></li><li><strong>$dineModifyCount</strong><span>remediating effects</span></li></ul><p>Behavior depends on effect: Deny blocks, Audit reports, and DINE/Modify can remediate.</p></div>
        </div>
    </div>
</section>

<section id="page-engineer" class="report-page page-lead" data-report-page data-page-group="page-engineer">
    <div class="page-heading"><div><h2>Engineer</h2><p>Policy assignments, affected resources, prioritised remediation, blockers, permissions, and operational evidence.</p></div><span class="page-status">Action view</span></div>
    <div class="page-summary">
        <div class="summary-cards">
            <div class="card card-blue"><div class="card-num">$ncPolicyCount</div><div class="card-label">Failing Policies</div></div>
            <div class="card card-blue"><div class="card-num">$affectedResourceTypeCount</div><div class="card-label">Affected Resource Types</div></div>
            <div class="card $(if ($missingRemediationIdentityCount -gt 0) { 'card-red' } else { 'card-green' })"><div class="card-num">$missingRemediationIdentityCount</div><div class="card-label">Identity Blockers</div></div>
            <div class="card $(if ($highSecEnforceIssues.Count -gt 0) { 'card-red' } else { 'card-green' })"><div class="card-num">$($highSecEnforceIssues.Count)</div><div class="card-label">High-Security Enforcement Gaps</div></div>
        </div>
        <div class="decision-grid three">
            <div class="compact-panel"><h3>Remediation Queue</h3><ul class="compact-list">$engineerActionsHtml</ul></div>
            <div class="compact-panel"><h3>Affected Resource Types</h3><p>$topResourceTypesSummary</p><p><strong>$totalNC</strong> unique affected resources across <strong>$affectedSubscriptionCount</strong> subscriptions.</p></div>
            <div class="compact-panel"><h3>Operational Findings</h3><p><strong>Top failing policies:</strong> $topFailingPoliciesSummary</p><p><strong>$($highSecEnforceIssues.Count)</strong> high-security enforcement gaps require review.</p></div>
        </div>
    </div>
</section>

<section id="page-evidence" class="report-page page-lead" data-report-page data-page-group="page-evidence">
    <div class="page-heading"><div><h2>Evidence</h2><p>Assessment provenance and snapshot changes supporting the conclusions shown in the audience views.</p></div><span class="page-status">Evidence catalogue</span></div>
    <div class="page-summary">
        <div class="summary-cards">
            <div class="card card-blue"><div class="card-num">$($AssessmentFindings.Count)</div><div class="card-label">Findings</div></div>
            <div class="card card-blue"><div class="card-num">$dataQualityRecords</div><div class="card-label">Evidence Records</div></div>
            <div class="card $(if ($successfulQueryCount -gt 0) { 'card-green' } else { 'card-gray' })"><div class="card-num">$successfulQueryCount</div><div class="card-label">Successful Sources</div></div>
            <div class="card $(if ($failedQueryCount -gt 0) { 'card-red' } else { 'card-green' })"><div class="card-num">$failedQueryCount</div><div class="card-label">Failed Sources</div></div>
        </div>
        <div class="decision-grid">
            <div class="compact-panel"><h3>Current-State Provenance</h3><p>Counts summarize the Azure records collected for this assessment. Assignment, resource, policy, and exemption details are available directly in Engineer.</p></div>
            <div class="compact-panel"><h3>Change Evidence</h3><p>Snapshot delta appears only when a comparison YAML was supplied and remains isolated from the current-state operational inventory.</p></div>
        </div>
    </div>
</section>

<section id="page-methodology" class="report-page page-lead" data-report-page data-page-group="page-methodology">
    <div class="page-heading"><div><h2>Methodology</h2><p>Confidence, sources, collection boundaries, limitations, and interpretation guidance.</p></div><span class="page-status">Reference view</span></div>
    <div class="page-summary">
        <div class="decision-grid three">
            <div class="compact-panel"><h3>Confidence</h3><p>Deterministic findings retain source and confidence metadata. Current data quality: <strong>$dataQualityLabel</strong>.</p></div>
            <div class="compact-panel"><h3>Data Sources</h3><p>Azure Resource Graph, Azure Policy metadata and states, remediation tasks, role assignments, exemptions, and explicitly enabled cost sources.</p></div>
            <div class="compact-panel"><h3>Collection Method</h3><p>Point-in-time, read-only evidence collection at $dataQualityTimestamp. Fallback used: $(if ($dataQualityFallback) { 'yes' } else { 'no' }).</p></div>
        </div>
        <details class="report-disclosure depth-3 disclaimer-disclosure">
            <summary>Methodology and limitations <span class="disclosure-meta">Best-effort tool, not an official Microsoft product</span></summary>
            <div class="details-content disclaimer-banner">
                <span class="disclaimer-icon">&#x2139;&#xFE0F;</span>
                <span><strong>Not an Official Microsoft Product.</strong> This project is made and maintained by Riccardo Pomato. It is a best-effort open-source tool designed to help Azure architects and engineers assess their policy posture. It is not affiliated with, endorsed by, or supported by Microsoft. The data and recommendations herein are provided &ldquo;as-is&rdquo; without warranty. Always validate findings against the <a href="https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Compliance" target="_blank">Azure Policy compliance dashboard</a> and official Microsoft documentation.</span>
            </div>
        </details>
    </div>
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!--  HOW TO READ THIS REPORT                              -->
<!-- ══════════════════════════════════════════════════════ -->
<details class="guide-panel report-page" data-report-page data-page-group="page-methodology">
    <summary>&#x1F4D6; How to Read This Report</summary>
    <div class="guide-content">
        <p>This report analyses your Azure Policy assignments across all scopes and provides actionable insights organised into $totalSections sections: 7 core sections$(if ($hasALZSection -or $hasDeltaSection) { ' plus the optional sections listed below' }). Use the navigation bar above to jump between sections.</p>

        <div class="guide-columns">
            <div>
                <h4>Report Sections</h4>
                <ul>
                    <li><strong>Summary</strong> &mdash; Executive conclusions only: high-level KPIs, aggregated priority risks and actions, business impact, and leadership decisions.</li>
                    <li><strong>Engineering Report</strong> &mdash; Actionable inventory: prioritised findings, all policy assignments, non-compliant resources, exemptions, remediation evidence, and verification details.</li>
                    <li><strong>Architecture Insights</strong> &mdash; Design analysis: scope placement and inheritance, control type balance, coverage gaps, policy structure, and architectural anti-patterns.</li>
                    <li><strong>Governance &amp; Compliance</strong> &mdash; Framework mapping (CE+, CIS, NIST), Cyber Essentials test results <span class="experimental-tag">Experimental</span>, and regulatory compliance.</li>
                    <li><strong>Security Action Inventory</strong> &mdash; Risk-prioritised assignments, enforcement-gap records, and affected resource types for implementation and verification.</li>
$(if ($hasALZSection) { '                    <li><strong>Landing Zone</strong> &mdash; Deterministic comparison with the selected Azure Landing Zones Library inventory.</li>' })
                    <li><strong>Cost Insights</strong> &mdash; Resource cost and operational overhead associated with policy assignments.</li>
                    <li><strong>Recommendations</strong> &mdash; Prioritised action plan with a 30-60-90 day roadmap.</li>
$(if ($YAMLDeltaData) { '                    <li><strong>Delta Assessment</strong> &mdash; Changes detected against the supplied prior YAML assessment.</li>' })
                </ul>
            </div>
            <div>
                <h4>Colour Legend</h4>
                <div class="legend-grid" style="margin-bottom:12px;">
                    <div class="legend-item"><span class="legend-dot dot-red"></span> Critical / High risk / Failed</div>
                    <div class="legend-item"><span class="legend-dot dot-amber"></span> Warning / Medium risk / Needs review</div>
                    <div class="legend-item"><span class="legend-dot dot-green"></span> Healthy / Low risk / Passed</div>
                    <div class="legend-item"><span class="legend-dot dot-blue"></span> Informational / Count</div>
                    <div class="legend-item"><span class="legend-dot dot-purple"></span> Manual review required</div>
                    <div class="legend-item"><span class="legend-dot dot-gray"></span> Skipped / Not applicable</div>
                    <div class="legend-item"><span class="legend-dot dot-magenta"></span> Regulatory compliance</div>
                </div>

                <h4>Key Terms</h4>
                <ul>
                    <li><strong>NC</strong> = Non-Compliant (unique resources that violate a policy rule)</li>
                    <li><strong>Enforced (Default)</strong> = Assignment is actively enforced by Azure &mdash; the policy effect (Deny, Audit, DINE, etc.) is applied</li>
                    <li><strong>DoNotEnforce</strong> = Enforcement mode disabled &mdash; Azure evaluates compliance but does not apply configured effects automatically; separate manual remediation tasks may still exist</li>
                    <li><strong>Deny</strong> = Preventive control &mdash; blocks non-compliant deployments before they happen</li>
                    <li><strong>Audit / AuditIfNotExists</strong> = Detective control &mdash; flags non-compliance but allows the action to proceed</li>
                    <li><strong>DINE / Modify</strong> = Remediation control &mdash; auto-deploys or corrects configurations (DeployIfNotExists / Modify)</li>
                    <li><strong>Parameterised</strong> = Effect defined via parameter (e.g. <code>[parameters('effect')]</code>) &mdash; actual effect depends on assignment</li>
                    <li><strong>Control Type Balance</strong> = Ratio of Preventive / Detective / Remediation effects. Suggested ranges are opinionated tool guidance, not official targets</li>
                    <li><strong>Anti-Pattern</strong> = A detected governance misconfiguration (expand each for details, affected items, and Microsoft docs references)</li>
                    <li><strong>Exemption</strong> = Excludes a scope from policy evaluation. Types: Waiver (accepted risk) or Mitigated (alternative control)</li>
                    <li><strong>CE+</strong> = Cyber Essentials Plus (UK NCSC certification) <span class="experimental-tag">Experimental</span></li>
                </ul>

                <h4>Interactive Features</h4>
                <ul>
                    <li>Click <strong>column headers</strong> to sort tables ascending/descending</li>
                    <li>Use the <strong>search box</strong> above tables to filter rows in real-time</li>
                    <li>Click <strong>&#x25B6; collapsible sections</strong> to expand/collapse detailed data</li>
                </ul>
            </div>
        </div>
    </div>
</details>

<!-- ══════════════════════════════════════════════════════ -->
<!--  1. PRIORITISED FINDINGS                              -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="sec-findings" class="report-page" data-report-page data-page-group="page-engineer">
    <div class="section-header">
        <h2>Prioritised Findings</h2>
        <span class="section-num">Section 1 of $totalSections</span>
    </div>

    <div class="section-intro">
        <p><strong>Purpose:</strong> Actionable deterministic findings and assignment-level evidence supporting the aggregated risks in Summary. Use this section to investigate why an item was raised, identify affected records, and verify the recommended action.</p>
    </div>

    <details class="report-disclosure depth-2" id="details-key-findings">
        <summary>Key Findings &amp; Risks <span class="disclosure-meta">Deterministic findings and recommended actions</span></summary>
        <div class="details-content">
            <div class="note-box"><span class="note-icon">&#x1F4AC;</span><span>Findings are automatically generated based on your policy data. <strong style="color:var(--red)">Red callouts</strong> = critical issues requiring immediate action (e.g. high-security policies not enforced). <strong style="color:var(--amber)">Amber callouts</strong> = warnings to investigate (e.g. non-compliant resources, missing Deny policies). <strong style="color:var(--accent)">Blue callouts</strong> = informational notes (e.g. disabled policies, housekeeping). <strong style="color:var(--green)">Green callouts</strong> = healthy areas confirmed. Hover over &#x24D8; icons for additional context.</span></div>
            $findingsHtml
            $(if (-not $findingsHtml -and $hasEvaluatedCompliance) { "<p class='text-dim'>No significant findings to report from the evaluated data.</p>" })
        </div>
    </details>

    $(if ($topNCRows) {
    @"
    <details class="report-disclosure depth-2" id="details-findings-nc" style="margin-top:24px;">
        <summary>Top 10 Non-Compliant Assignments <span class="disclosure-meta">Policy-level drill-down</span></summary>
        <div class="details-content">
            <p class="text-dim" style="margin-bottom:8px;">Policy perspective: NC counts are per-assignment. The same resource may be counted under multiple assignments.</p>
            <button class="copy-btn" onclick="copyTable('exec-top-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            <div class="table-wrap">
            <table id="exec-top-table">
            <thead><tr><th class="sortable" onclick="sortTable('exec-top-table',0)">Display Name <span class="col-info" data-tip="The friendly name of the policy or initiative assignment" title="Assignment display name">&#9432;</span></th><th>Type <span class="col-info" data-tip="Initiative (regulatory or standard) or single Policy" title="Assignment type">&#9432;</span></th><th class="sortable" onclick="sortTable('exec-top-table',2)">NC Resources <span class="col-info" data-tip="Number of resources currently non-compliant with this assignment" title="Non-compliant resource count">&#9432;</span></th><th>Scope <span class="col-info" data-tip="The Azure hierarchy level and name where this assignment is applied" title="Assignment scope">&#9432;</span></th><th>Enforcement <span class="col-info" data-tip="Default = actively enforced; DoNotEnforce = audit-only mode" title="Enforcement mode">&#9432;</span></th></tr></thead>
            <tbody>$topNCRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
    })
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!--  2. ENGINEERING REPORT                                -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="sec-engineering" class="report-page" data-report-page data-page-group="page-engineer">
<details class="section-disclosure">
    <summary>
        <span>Engineering Report</span>
        <span class="section-num">Section 2 of $totalSections</span>
        <span class="disclosure-hint">$totalAssignments assignments · $totalNC affected resources · $ncPolicyCount failing policies</span>
    </summary>
    <div class="section-content">

    <div class="section-intro">
        <p><strong>Purpose:</strong> Actionable technical inventory of every policy assignment and non-compliant resource. Use this section to identify affected records, investigate violations, and export implementation data.</p>
        <p>Scope placement, effect balance, category distribution, and coverage design are analysed in CSA / Architect. Expand the panels below for searchable assignment and resource records.</p>
    </div>

    <div class="note-box"><span class="note-icon">&#x1F4AC;</span><span><strong>Scope Type</strong> indicates where the policy is assigned: Management Group (inherited by all child resources), Subscription, or Resource Group (most specific). <strong>NC Resources</strong> = count of resources violating the policy rule.</span></div>

    <details>
        <summary>&#x1F4C4; All Policy Assignments ($totalAssignments)</summary>
        <div class="details-content">
            <div class="filter-bar">
                <input type="text" id="filter-policies" placeholder="Search assignments..." oninput="filterTable('policies-table','filter-policies')">
                <span class="count" id="count-policies">$totalAssignments assignments</span>
                <button class="copy-btn" onclick="copyTable('policies-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            </div>
            <div class="table-wrap">
            <table id="policies-table">
            <thead><tr><th class="sortable" onclick="sortTable('policies-table',0)">Display Name <span class="col-info" data-tip="The friendly name of the policy or initiative assignment" title="The friendly name of the policy or initiative assignment">&#9432;</span></th><th class="sortable" onclick="sortTable('policies-table',1)">Type <span class="col-info" data-tip="Initiative (regulatory or standard) or single Policy" title="Initiative (regulatory or standard) or single Policy">&#9432;</span></th><th class="sortable" onclick="sortTable('policies-table',2)">Category <span class="col-info" data-tip="Azure Policy category (e.g. Security, Monitoring, Compute)" title="Azure Policy category">&#9432;</span></th><th class="sortable" onclick="sortTable('policies-table',3)">Effect <span class="col-info" data-tip="The enforced effect: Audit, Deny, DeployIfNotExists, Modify, etc." title="The enforced effect type">&#9432;</span></th><th class="sortable" onclick="sortTable('policies-table',4)">Enforcement <span class="col-info" data-tip="Default = actively enforced; DoNotEnforce = audit-only mode" title="Default = enforced; DoNotEnforce = audit-only">&#9432;</span></th><th class="sortable" onclick="sortTable('policies-table',5)">NC Resources <span class="col-info" data-tip="Number of resources currently non-compliant with this policy" title="Non-compliant resource count">&#9432;</span></th><th class="sortable" onclick="sortTable('policies-table',6)">Scope Type <span class="col-info" data-tip="Assignment scope level: Management Group, Subscription, or Resource Group" title="Scope level">&#9432;</span></th><th class="sortable" onclick="sortTable('policies-table',7)">Scope Name <span class="col-info" data-tip="Name of the management group, subscription, or resource group" title="Scope name">&#9432;</span></th><th class="sortable" onclick="sortTable('policies-table',8)">Risk Level <span class="col-info" data-tip="Computed risk: High (disabled/deny), Medium (audit-only), Low (enforced)" title="Computed risk level">&#9432;</span></th><th class="sortable" onclick="sortTable('policies-table',9)">Security Impact <span class="col-info" data-tip="How strongly this policy protects your environment (High/Medium/Low)" title="Security impact rating">&#9432;</span></th><th class="sortable" onclick="sortTable('policies-table',10)">Compliance Impact <span class="col-info" data-tip="Regulatory/compliance importance: High = required by frameworks, Medium = recommended, Low = optional" title="Compliance impact rating">&#9432;</span></th><th class="sortable" onclick="sortTable('policies-table',11)">Recommendation <span class="col-info" data-tip="Actionable guidance to improve this assignment's posture" title="Actionable recommendation">&#9432;</span></th></tr></thead>
            <tbody>$policyRows</tbody>
            </table>
            </div>
        </div>
    </details>

    $(if ($NCExportData.Count -gt 0) {
    @"
    <details id="details-nc-resources">
        <summary>&#x1F4E6; Non-Compliant Resources &mdash; Resource Perspective ($totalNC unique resources)</summary>
        <div class="details-content">
            <p class="text-dim" style="margin-bottom:12px;">Each row is a <strong>unique non-compliant resource</strong>. The Policies column shows all policies that flag it. Fix the resource once to resolve all related violations.</p>
            <div class="filter-bar">
                <input type="text" id="filter-nc" placeholder="Search resources..." oninput="filterTable('nc-table','filter-nc')">
                <span class="count" id="count-nc">$totalNC resources</span>
                <button class="copy-btn" onclick="copyTable('nc-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            </div>
            <div class="table-wrap">
            <table id="nc-table">
            <thead><tr><th class="sortable" onclick="sortTable('nc-table',0)">Resource Name <span class="col-info" data-tip="The name of the Azure resource that is non-compliant" title="Resource name">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-table',1)">Resource Type <span class="col-info" data-tip="The Azure resource type (e.g. Microsoft.Compute/virtualMachines)" title="Resource type">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-table',2)">Resource Group <span class="col-info" data-tip="The resource group containing this resource" title="Resource group">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-table',3)">Policies <span class="col-info" data-tip="All policy definitions that flag this resource as non-compliant" title="Policies flagging this resource">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-table',4)">Initiatives <span class="col-info" data-tip="Initiative(s) containing the policies that flag this resource" title="Parent initiatives">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-table',5)">Subscription <span class="col-info" data-tip="The Azure subscription where this resource resides" title="Subscription">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-table',6)">Hits <span class="col-info" data-tip="Number of separate policy evaluations that flag this resource as non-compliant" title="Evaluation hit count">&#9432;</span></th></tr></thead>
            <tbody>$ncResRows</tbody>
            </table>
            </div>
        </div>
    </details>

    <details id="details-nc-policies">
        <summary>&#x1F4DC; Non-Compliant Policies ($ncPolicyCount policies with violations)</summary>
        <div class="details-content">
            <p class="text-dim" style="margin-bottom:12px;">Each row is a <strong>policy with non-compliant resources</strong>. The same resource may appear under multiple policies. Use this view to prioritise which policies to remediate first.</p>
            <div class="filter-bar">
                <input type="text" id="filter-nc-pol" placeholder="Search policies..." oninput="filterTable('nc-pol-table','filter-nc-pol')">
                <span class="count" id="count-nc-pol">$ncPolicyCount policies</span>
                <button class="copy-btn" onclick="copyTable('nc-pol-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            </div>
            <div class="table-wrap">
            <table id="nc-pol-table">
            <thead><tr><th class="sortable" onclick="sortTable('nc-pol-table',0)">Policy Name <span class="col-info" data-tip="The policy definition name that has non-compliant resources" title="Policy name">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-pol-table',1)">Unique Resources <span class="col-info" data-tip="Count of distinct resources flagged by this policy" title="Unique NC resources">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-pol-table',2)">Total Evaluations <span class="col-info" data-tip="Total policy evaluation hits (a resource may be evaluated multiple times across scopes)" title="Total evaluations">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-pol-table',3)">Resource Types <span class="col-info" data-tip="The Azure resource types affected by this policy" title="Affected resource types">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-pol-table',4)">Initiatives <span class="col-info" data-tip="Initiative(s) that contain this policy definition" title="Parent initiatives">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-pol-table',5)">Subscriptions <span class="col-info" data-tip="Subscription(s) where non-compliant resources for this policy were found" title="Affected subscriptions">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-pol-table',6)">Severity <span class="col-info" data-tip="Impact severity based on the number of affected resources: Critical (&ge;50), High (&ge;20), Medium (&ge;5), Low (<5)" title="Severity level">&#9432;</span></th></tr></thead>
            <tbody>$ncPolicyRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
    })

    $(if ($costRows) {
    @"
    <details id="details-cost-policies">
        <summary>&#x1F4CA; Policies with Cost/Operational Impact</summary>
        <div class="details-content">
            <p class="text-dim" style="margin-bottom:12px;">Assignment-level inventory supporting the aggregate cost exposure analysis in CSA / Architect. Validate heuristic exposure against official pricing and actual usage before implementation decisions.</p>
            <div class="filter-bar">
                <input type="text" id="filter-cost" placeholder="Search policies..." oninput="filterTable('cost-table','filter-cost')">
                <span class="count" id="count-cost"></span>
                <button class="copy-btn" onclick="copyTable('cost-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            </div>
            <div class="table-wrap">
            <table id="cost-table">
            <thead><tr><th>Policy</th><th>Cost Exposure</th><th>Operational Overhead</th><th>Category</th><th>Effect</th><th>Enforcement</th><th>Scope</th></tr></thead>
            <tbody>$costRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
    })

$exemptionSubHtml
    </div>
</details>
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!--  3. ARCHITECTURE INSIGHTS                             -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="sec-architecture" class="report-page" data-report-page data-page-group="page-csa">
<details class="section-disclosure">
    <summary>
        <span>Architecture Insights</span>
        <span class="section-num">Section 3 of $totalSections</span>
        <span class="disclosure-hint">$($scopesWithPolicies.Count) scopes · $($scopesNoDeny.Count) without Deny · $auditOnlyCount without enforcement</span>
    </summary>
    <div class="section-content">

    <div class="section-intro">
        <p><strong>Purpose:</strong> Evaluate how well your policy architecture is designed. This section analyses scope hierarchy, the balance between preventive/detective/remediation controls, and identifies anti-patterns.</p>
        <p>Management Group assignments can provide centralised governance, while subscription or resource-group assignments can also be intentional. Assess scope placement against ownership, inheritance, exclusions, and organisational requirements rather than a universal target.</p>
    </div>

    <div class="legend">
        <h4>&#x1F3F7;&#xFE0F; Architecture Legend</h4>
        <div class="legend-grid" style="margin-bottom:10px;">
            <div class="legend-item"><span class="badge status-pass">Centralised</span> Policies at Management Group level (best practice)</div>
            <div class="legend-item"><span class="badge status-warn">Subscription-level</span> Mostly subscription assignments (consider consolidating)</div>
            <div class="legend-item"><span class="badge status-fail">Fragmented</span> Ad-hoc Resource Group assignments (needs restructuring)</div>
        </div>
        <div class="legend-grid">
            <div class="legend-item"><span class="legend-dot dot-red"></span> &#x1F6D1; Preventive (Deny) &mdash; blocks non-compliant actions</div>
            <div class="legend-item"><span class="legend-dot dot-amber"></span> &#x1F50D; Detective (Audit) &mdash; reports violations only</div>
            <div class="legend-item"><span class="legend-dot dot-green"></span> &#x1F527; Remediation (DINE/Modify) &mdash; remediating effect assigned; outcome requires evidence</div>
            $(if ($disabledCount -gt 0) { "<div class='legend-item'><span class='legend-dot dot-gray'></span> &#x26D4; Disabled &mdash; policy exists but is not evaluated</div>" })
        </div>
    </div>

    <div class="grid-2" style="margin-bottom:20px;">
        <div class="insight-box">
            <h4>&#x1F3D7;&#xFE0F; Scope Hierarchy Model <span class="col-info" data-tip="Shows how your assignments are distributed across Azure hierarchy levels. Management Group assignments inherit to all child subscriptions and resource groups." title="Scope hierarchy">&#9432;</span></h4>
            <p>$hierarchyVerdict</p>
            <div style="margin-top:12px;">
                <div class="stat-row"><span>&#x1F3E2; Management Group <span class="col-info" data-tip="Policies assigned at this level are inherited by all child subscriptions and resource groups. This is the best practice for centralised governance." title="Inherited by all child scopes (best practice)">i</span></span><strong style="color:$(if ($mgAssignments -ge $subAssignments) { 'var(--green)' } else { 'var(--text)' })">$mgAssignments</strong></div>
                <div class="stat-row"><span>&#x1F4C1; Subscription <span class="col-info" data-tip="Policies assigned at subscription level apply to all resource groups within. Consider consolidating to Management Group level if many subscriptions share the same policies." title="Applies to all RGs within the subscription">i</span></span><strong style="color:$(if ($subAssignments -gt $mgAssignments) { 'var(--amber)' } else { 'var(--text)' })">$subAssignments</strong></div>
                <div class="stat-row"><span>&#x1F4E6; Resource Group <span class="col-info" data-tip="Most specific scope. Policies here only apply to resources in that RG. High counts may indicate fragmented governance — consider moving policies higher in the hierarchy." title="Only applies to resources in that RG">i</span></span><strong style="color:$(if ($rgAssignments -gt 10) { 'var(--red)' } elseif ($rgAssignments -gt 0) { 'var(--amber)' } else { 'var(--text)' })">$rgAssignments</strong></div>
            </div>
            <div class="progress-bar" style="margin-top:12px;">
                $(if ($mgAssignments -gt 0) { $mgPct = [math]::Round(($mgAssignments / [math]::Max($totalAssignments,1)) * 100); "<div class='progress-fill fill-green' style='width:${mgPct}%' title='Management Group: $mgAssignments'>MG ${mgPct}%</div>" })$(if ($subAssignments -gt 0) { $subPct = [math]::Round(($subAssignments / [math]::Max($totalAssignments,1)) * 100); "<div class='progress-fill fill-amber' style='width:${subPct}%' title='Subscription: $subAssignments'>Sub ${subPct}%</div>" })$(if ($rgAssignments -gt 0) { $rgPct = [math]::Round(($rgAssignments / [math]::Max($totalAssignments,1)) * 100); "<div class='progress-fill fill-red' style='width:${rgPct}%' title='Resource Group: $rgAssignments'>RG ${rgPct}%</div>" })
            </div>
        </div>
        <div class="insight-box">
            <h4>&#x2696;&#xFE0F; Control Type Balance <span class="badge $balanceBadgeClass">$overallBalance</span> <span class="col-info" data-tip="Distribution of policy effects across control types. A balanced mix provides defence in depth. The suggested ranges are opinionated guidance from this tool — not official Azure or WAF targets." title="Control type distribution">&#9432;</span></h4>

            <!-- Three individual bars with ideal range markers -->
            <div style="margin-top:12px;">
                <!-- Preventive -->
                <div style="margin-bottom:14px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <span style="font-size:0.85rem;"><span class="legend-dot dot-red" style="display:inline-block;"></span> &#x1F6D1; Preventive (Deny)</span>
                        <strong style="color:var(--$prevHealth);">$denyCount ($preventivePct%)</strong>
                    </div>
                    <div style="position:relative;height:22px;background:var(--bg-secondary);border-radius:6px;overflow:visible;">
                        <div style="position:absolute;left:35%;width:10%;height:100%;background:rgba(76,175,80,0.15);border-left:2px dashed var(--green);border-right:2px dashed var(--green);z-index:1;" title="Suggested range: 35-45%"></div>
                        <div style="position:absolute;left:0;width:${preventivePct}%;height:100%;background:var(--$prevHealth);border-radius:6px;z-index:2;display:flex;align-items:center;justify-content:center;font-size:0.72rem;font-weight:600;color:#fff;min-width:$(if ($preventivePct -gt 5) { '0' } else { '28px' });">$(if ($preventivePct -ge 8) { "${preventivePct}%" })</div>
                    </div>
                    <div style="display:flex;justify-content:space-between;font-size:0.68rem;color:var(--text-dim);margin-top:2px;"><span>0%</span><span style="margin-left:33%;">suggested 35-45%</span><span>100%</span></div>
                </div>

                <!-- Detective -->
                <div style="margin-bottom:14px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <span style="font-size:0.85rem;"><span class="legend-dot dot-amber" style="display:inline-block;"></span> &#x1F50D; Detective (Audit)</span>
                        <strong style="color:var(--$detHealth);">$auditEffectCount ($detectivePct%)</strong>
                    </div>
                    <div style="position:relative;height:22px;background:var(--bg-secondary);border-radius:6px;overflow:visible;">
                        <div style="position:absolute;left:30%;width:10%;height:100%;background:rgba(76,175,80,0.15);border-left:2px dashed var(--green);border-right:2px dashed var(--green);z-index:1;" title="Suggested range: 30-40%"></div>
                        <div style="position:absolute;left:0;width:${detectivePct}%;height:100%;background:var(--$detHealth);border-radius:6px;z-index:2;display:flex;align-items:center;justify-content:center;font-size:0.72rem;font-weight:600;color:#fff;min-width:$(if ($detectivePct -gt 5) { '0' } else { '28px' });">$(if ($detectivePct -ge 8) { "${detectivePct}%" })</div>
                    </div>
                    <div style="display:flex;justify-content:space-between;font-size:0.68rem;color:var(--text-dim);margin-top:2px;"><span>0%</span><span style="margin-left:28%;">suggested 30-40%</span><span>100%</span></div>
                </div>

                <!-- Remediation -->
                <div style="margin-bottom:8px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <span style="font-size:0.85rem;"><span class="legend-dot dot-green" style="display:inline-block;"></span> &#x1F527; Remediation (DINE/Modify)</span>
                        <strong style="color:var(--$remHealth);">$dineModifyCount ($remediativePct%)</strong>
                    </div>
                    <div style="position:relative;height:22px;background:var(--bg-secondary);border-radius:6px;overflow:visible;">
                        <div style="position:absolute;left:15%;width:10%;height:100%;background:rgba(76,175,80,0.15);border-left:2px dashed var(--green);border-right:2px dashed var(--green);z-index:1;" title="Suggested range: 15-25%"></div>
                        <div style="position:absolute;left:0;width:${remediativePct}%;height:100%;background:var(--$remHealth);border-radius:6px;z-index:2;display:flex;align-items:center;justify-content:center;font-size:0.72rem;font-weight:600;color:#fff;min-width:$(if ($remediativePct -gt 5) { '0' } else { '28px' });">$(if ($remediativePct -ge 8) { "${remediativePct}%" })</div>
                    </div>
                    <div style="display:flex;justify-content:space-between;font-size:0.68rem;color:var(--text-dim);margin-top:2px;"><span>0%</span><span style="margin-left:13%;">suggested 15-25%</span><span>100%</span></div>
                </div>

                $(if ($disabledCount -gt 0) { "<div style='margin-top:6px;'><span style='font-size:0.85rem;'><span class='legend-dot dot-gray' style='display:inline-block;'></span> &#x26D4; Disabled</span> <strong class='nc-bad'>$disabledCount</strong> <span style='font-size:0.75rem;color:var(--text-dim);'>(excluded from balance calculation)</span></div>" })
            </div>

            <!-- Combined distribution bar -->
            <div style="margin-top:14px;">
                <div style="font-size:0.78rem;color:var(--text-dim);margin-bottom:4px;">Combined Distribution</div>
                <div class="progress-bar">
                    $(if ($preventivePct -gt 0) { "<div class='progress-fill' style='width:${preventivePct}%;background:var(--red);' title='Preventive (Deny): ${preventivePct}%'>$( if ($preventivePct -ge 10) { "Deny ${preventivePct}%" } )</div>" })$(if ($detectivePct -gt 0) { "<div class='progress-fill' style='width:${detectivePct}%;background:var(--amber);' title='Detective (Audit): ${detectivePct}%'>$( if ($detectivePct -ge 10) { "Audit ${detectivePct}%" } )</div>" })$(if ($remediativePct -gt 0) { "<div class='progress-fill' style='width:${remediativePct}%;background:var(--green);' title='Remediation (DINE/Modify): ${remediativePct}%'>$( if ($remediativePct -ge 10) { "DINE ${remediativePct}%" } )</div>" })
                </div>
            </div>

            <!-- Explanation panel -->
            <details style="margin-top:14px;">
                <summary style="cursor:pointer;font-weight:600;font-size:0.85rem;">&#x1F4D6; How to read this &amp; control balance guidance</summary>
                <div class="details-content" style="padding:10px 14px;font-size:0.82rem;">
                    <p style="margin-top:0;color:var(--amber);font-size:0.8rem;">&#x26A0;&#xFE0F; The suggested percentage ranges below are <strong>opinionated guidance from this tool</strong>. They are not prescribed by the Azure Well-Architected Framework or any official Microsoft documentation. The <a href="https://learn.microsoft.com/en-us/azure/well-architected/security/" target="_blank" style="color:var(--accent);">WAF Security pillar</a> recommends defence in depth with layered controls but does not specify exact ratios.</p>
                    <p style="margin-top:8px;"><strong>Defence in depth</strong> recommends using all three control types together. The dashed green bands on the bars above show the suggested range for each.</p>
                    <table style="width:100%;font-size:0.8rem;border-collapse:collapse;margin:10px 0;">
                        <thead><tr style="border-bottom:1px solid var(--border);"><th style="text-align:left;padding:4px 8px;">Control Type</th><th style="padding:4px 8px;">Suggested Range</th><th style="padding:4px 8px;">Your %</th><th style="text-align:left;padding:4px 8px;">What it means</th></tr></thead>
                        <tbody>
                            <tr style="border-bottom:1px solid var(--border);"><td style="padding:4px 8px;">&#x1F6D1; <strong>Preventive</strong> (Deny)</td><td style="text-align:center;padding:4px 8px;">35&ndash;45%</td><td style="text-align:center;padding:4px 8px;color:var(--$prevHealth);font-weight:600;">${preventivePct}%</td><td style="padding:4px 8px;">Blocks non-compliant deployments <em>before</em> they happen. Too low = violations are created and need manual cleanup.</td></tr>
                            <tr style="border-bottom:1px solid var(--border);"><td style="padding:4px 8px;">&#x1F50D; <strong>Detective</strong> (Audit)</td><td style="text-align:center;padding:4px 8px;">30&ndash;40%</td><td style="text-align:center;padding:4px 8px;color:var(--$detHealth);font-weight:600;">${detectivePct}%</td><td style="padding:4px 8px;">Flags violations for review but allows them. Essential for visibility, but over-reliance means issues are discovered late.</td></tr>
                            <tr><td style="padding:4px 8px;">&#x1F527; <strong>Remediation</strong> (DINE/Modify)</td><td style="text-align:center;padding:4px 8px;">15&ndash;25%</td><td style="text-align:center;padding:4px 8px;color:var(--$remHealth);font-weight:600;">${remediativePct}%</td><td style="padding:4px 8px;">Auto-deploys or corrects configurations. Reduces manual toil and ensures baseline compliance continuously.</td></tr>
                        </tbody>
                    </table>
                    $controlBalanceTakeawaysHtml
                </div>
            </details>
        </div>
    </div>

    <div class="grid-2" style="margin-bottom:20px;">
        <div class="insight-box">
            <h4>&#x1F4CA; Policy Type Distribution <span class="col-info" data-tip="Breakdown of assignments by type: single policies, initiatives, and regulatory compliance initiatives" title="Policy type breakdown">&#9432;</span></h4>
            <div class="table-wrap">
            <table><thead><tr><th>Policy Type <span class="col-info" data-tip="Classification: single Policy, Initiative (policy set), or Initiative (Regulatory)" title="Policy type">&#9432;</span></th><th>Count <span class="col-info" data-tip="Number of assignments of this type" title="Assignment count">&#9432;</span></th><th>Share <span class="col-info" data-tip="Percentage of total assignments" title="Percentage share">&#9432;</span></th></tr></thead>
            <tbody>$policyTypeDist</tbody></table>
            </div>
        </div>
        <div class="insight-box">
            <h4>&#x26A0;&#xFE0F; Anti-Patterns &amp; Issues <span class="col-info" data-tip="Common misconfigurations or governance anti-patterns detected in your policy assignments" title="Anti-patterns detected">&#9432;</span></h4>
            $antiPatternsHtml
        </div>
    </div>

    $(if ($categoryRows) {
    @"
    <details>
        <summary>&#x1F4C2; Policy Category Distribution ($($categoryBreakdown.Count) categories)</summary>
        <div class="details-content">
            <p class="text-dim" style="margin-bottom:12px;">Design view of policy concentration by Azure definition category. Use it to identify over-represented domains and potential control gaps.</p>
            <div class="table-wrap">
            <table><thead><tr><th>Category <span class="col-info" data-tip="The Azure Policy definition category from Microsoft metadata" title="Policy category">&#9432;</span></th><th>Assignments <span class="col-info" data-tip="Number of policy assignments in this category" title="Assignment count">&#9432;</span></th><th>NC Resources <span class="col-info" data-tip="Total non-compliant resources across all assignments in this category" title="Non-compliant count">&#9432;</span></th><th>Share <span class="col-info" data-tip="Percentage of total assignments represented by this category" title="Category share">&#9432;</span></th></tr></thead>
            <tbody>$categoryRows</tbody></table>
            </div>
            <p class="text-dim" style="margin-top:8px;">Categories are sourced from Azure Policy definition metadata, not inferred from names.</p>
        </div>
    </details>
"@
    })

    <details id="details-coverage">
        <summary>&#x1F50D; Scope Coverage Analysis ($($scopesWithPolicies.Count) scopes)</summary>
        <div class="details-content">
            <p class="text-dim" style="margin-bottom:12px;">Shows whether each scope has preventive (Deny), remediating (DINE/Modify), and monitoring (Audit) effects assigned. It does not establish task outcome.</p>
            <div class="filter-bar">
                <input type="text" id="filter-coverage" placeholder="Search scopes..." oninput="filterTable('coverage-table','filter-coverage')">
                <span class="count" id="count-coverage">$($scopesWithPolicies.Count) scopes</span>
                <button class="copy-btn" onclick="copyTable('coverage-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            </div>
            <div class="table-wrap">
            <table id="coverage-table">
            <thead><tr><th class="sortable" onclick="sortTable('coverage-table',0)">Scope Name <span class="col-info" data-tip="The name of the management group, subscription, or resource group" title="Scope name">&#9432;</span></th><th class="sortable" onclick="sortTable('coverage-table',1)">Scope Type <span class="col-info" data-tip="Management Group, Subscription, or Resource Group" title="Scope type">&#9432;</span></th><th class="sortable" onclick="sortTable('coverage-table',2)">Assignments <span class="col-info" data-tip="Total number of policy assignments at this scope" title="Assignment count">&#9432;</span></th><th>Has Deny <span class="col-info" data-tip="Whether this scope has at least one Deny policy to block non-compliant deployments" title="Deny policy presence">&#9432;</span></th><th>Has DINE/Modify <span class="col-info" data-tip="Whether this scope has assigned DeployIfNotExists or Modify effects; task outcome requires evidence" title="Remediating effect presence">&#9432;</span></th><th>Has Audit <span class="col-info" data-tip="Whether this scope has Audit or AuditIfNotExists policies for monitoring" title="Audit policy presence">&#9432;</span></th><th class="sortable" onclick="sortTable('coverage-table',6)">NC Resources <span class="col-info" data-tip="Number of non-compliant resources at this scope" title="Non-compliant count">&#9432;</span></th></tr></thead>
            <tbody>$coverageRows</tbody>
            </table>
            </div>
        </div>
    </details>

    </div>
</details>
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!--  4. GOVERNANCE & COMPLIANCE                           -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="sec-governance" class="report-page" data-report-page data-page-group="page-csa">
<details class="section-disclosure">
    <summary>
        <span>Governance &amp; Compliance</span>
        <span class="section-num">Section 4 of $totalSections</span>
        <span class="disclosure-hint">$RegulatoryCount regulatory assignments · CE+ $($CEPAssessment.State) · data $dataQualityLabel</span>
    </summary>
    <div class="section-content">

    <div class="section-intro">
        <p><strong>Purpose:</strong> Shows how your Azure policies map to recognised security frameworks and certifications. Use this to assess <strong>audit readiness</strong> and identify <strong>compliance gaps</strong> before an assessment.</p>
        <p>The framework table distinguishes initiatives <strong style="color:var(--green)">assigned and evaluated by Azure Policy</strong> from frameworks that are <strong style="color:var(--amber)">not measured</strong>. No framework coverage is inferred from generic policy counts.</p>
    </div>

    <div class="legend">
        <h4>&#x1F3F7;&#xFE0F; Framework Status Legend</h4>
        <div class="legend-grid" style="margin-bottom:8px;">
            <div class="legend-item"><span class="badge status-pass">Passed</span> No failures or warnings in the automated checks</div>
            <div class="legend-item"><span class="badge status-warn">Partial</span> Score 50-79% &mdash; gaps exist, remediation needed</div>
            <div class="legend-item"><span class="badge status-fail">Weak</span> Score &lt; 50% &mdash; significant remediation required</div>
        </div>
        <div class="legend-grid">
            <div class="legend-item"><span class="badge status-pass">Assigned</span> Regulatory initiative is deployed in Azure &mdash; real compliance data from Azure Policy</div>
            <div class="legend-item"><span class="badge status-ne">Not measured</span> No matching initiative assignment was detected; no score is calculated</div>
        </div>
    </div>

    <div class="note-box"><span class="note-icon">&#x2139;&#xFE0F;</span><span><strong>Official framework evidence:</strong> The report uses initiative definitions discovered from Azure Resource Graph and compliance states for assigned initiatives. When no corresponding assignment is found, the framework is shown as <strong>Not measured</strong>. Assign the appropriate current built-in initiative in Azure Policy to obtain control-level results; Azure Policy mappings may still cover only a subset of a certification standard.</span></div>

    <h3 class="sub-title">Framework Coverage</h3>
    <div class="table-wrap" style="margin-bottom:24px;">
    <table>
    <thead><tr><th>Framework <span class="col-info" data-tip="The security framework or standard being assessed" title="Security framework or standard being assessed">i</span></th><th>Status <span class="col-info" data-tip="Assigned = evaluated by Azure Policy; Not measured = no corresponding assignment detected" title="Assessment status">i</span></th><th>Score <span class="col-info" data-tip="Calculated only from compliance data for an assigned initiative" title="Compliance score">i</span></th><th>Details <span class="col-info" data-tip="Official initiative source and observed compliance evidence" title="Detailed findings">i</span></th></tr></thead>
    <tbody>$frameworkRows</tbody>
    </table>
    </div>

$cepEvidenceHtml

$(if ($CEPTestResults.Count -gt 0) {
@"
    <h3 class="sub-title">Cyber Essentials Plus &mdash; Test Results <span class="experimental-tag">Experimental</span></h3>
    <div class="note-box"><span class="note-icon">&#x26A0;&#xFE0F;</span><span><strong>Experimental Feature:</strong> CE / CE+ assessment is a community-developed, experimental feature. It is <strong>not an official Cyber Essentials certification test</strong> and should not be used as a substitute for professional CE/CE+ assessment. Results are indicative only.</span></div>
    <div class="note-box"><span class="note-icon">&#x1F4DA;</span><span><strong>Evidence sources:</strong> Azure Policy mapping uses the <strong>UK NCSC Cyber Essentials v3.1 initiative</strong> when available. Independent technical checks use the <strong>NCSC CE+ v3.2 Test Specification</strong>. The versions differ because they are separate evidence sources for separate assessment phases.</span></div>
    $ceMultiAssignmentBanner
$(if (-not $isMultiAssignment) {
@"
    <div class="note-box"><span class="note-icon">&#x1F4AC;</span><span><strong>Test Statuses:</strong> <span class="badge status-pass">AUTOMATED PASS</span> = automated configuration checks passed, but listed manual verification may remain. <span class="badge status-fail">FAIL</span> = requirement not met, action needed. <span class="badge status-warn">WARN</span> = partial compliance, review recommended. <span class="badge status-skip">SKIP</span> = test could not run (data unavailable). <span class="badge status-manual">MANUAL</span> = requires human verification (cannot be automated).</span></div>
    $testSummaryCards
"@
})
$(if (-not $isMultiAssignment) {
@"
    <details>
        <summary>&#x1F9EA; CE+ Test Results Detail ($($CEPTestResults.Count) tests)</summary>
        <div class="details-content">
            <div class="table-wrap">
            <table id="tests-table">
            <thead><tr><th class="sortable" onclick="sortTable('tests-table',0)">Test # <span class="col-info" data-tip="Sequential test identifier within the CE+ assessment" title="Test number">&#9432;</span></th><th class="sortable" onclick="sortTable('tests-table',1)">Control Group <span class="col-info" data-tip="The Cyber Essentials control group this test belongs to (e.g. Firewalls, Secure Configuration)" title="CE control group">&#9432;</span></th><th class="sortable" onclick="sortTable('tests-table',2)">Test Name <span class="col-info" data-tip="Description of what this specific test validates" title="Test description">&#9432;</span></th><th class="sortable" onclick="sortTable('tests-table',3)">Status <span class="col-info" data-tip="PASS = met, FAIL = not met, WARN = partial, SKIP = unavailable, MANUAL = human check needed" title="Test result">&#9432;</span></th><th>Details <span class="col-info" data-tip="Additional context about the test result and whether evidence is resource-based, configuration-based, or manual" title="Result details">&#9432;</span></th><th class="sortable" onclick="sortTable('tests-table',5)">NC <span class="col-info" data-tip="Non-compliant resource count; N/A means the check does not measure resources" title="Non-compliant count">&#9432;</span></th><th class="sortable" onclick="sortTable('tests-table',6)">Compliant <span class="col-info" data-tip="Compliant resource count; N/A means the check does not measure resources" title="Compliant count">&#9432;</span></th><th class="sortable" onclick="sortTable('tests-table',7)">Total <span class="col-info" data-tip="Total evaluated resources; N/A means the check uses configuration or manual evidence" title="Total evaluated">&#9432;</span></th></tr></thead>
            <tbody>$testRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
})
"@
} else {
    if ($CEPAssessment.State -eq 'NotRequested') {
        '<div class="callout callout-info"><span class="callout-icon">&#x2139;&#xFE0F;</span><div><strong>CE+ Tests Not Run</strong><p>Run with <code>-CEP Test</code> or <code>-CEP Full</code> to populate Cyber Essentials Plus test results.</p></div></div>'
    } elseif ($CEPAssessment.State -eq 'EvaluationFailed') {
        '<div class="callout callout-warning"><span class="callout-icon">&#x26A0;&#xFE0F;</span><div><strong>Evaluation failed</strong><p>A query or runtime failure prevented CEP test evaluation. Review data quality and runtime diagnostics.</p></div></div>'
    } elseif ($CEPAssessment.State -eq 'PrerequisiteUnavailable') {
        "<div class='callout callout-info'><span class='callout-icon'>&#x2139;&#xFE0F;</span><div><strong>Assessment prerequisite unavailable</strong><p>$($CEPAssessment.PrerequisiteReason). Score: N/A.</p></div></div>"
    } else {
        '<div class="callout callout-info"><span class="callout-icon">&#x2139;&#xFE0F;</span><div><strong>Assessment partially evaluated</strong><p>No automated test result was available; no score was calculated.</p></div></div>'
    }
})

$(if ($CEPExportData.Count -gt 0 -and -not $isMultiAssignment) {
@"
    <h3 class="sub-title">CE+ Control Group Compliance <span class="experimental-tag">Experimental</span></h3>
    <div class="legend">
        <h4>&#x1F3F7;&#xFE0F; Compliance Status Legend</h4>
        <div class="legend-grid" style="margin-bottom:8px;">
            <div class="legend-item"><span class="legend-dot dot-green"></span> <strong>Compliant</strong> &mdash; policy requirement met, resources are in desired state</div>
            <div class="legend-item"><span class="legend-dot dot-red"></span> <strong>Non-Compliant</strong> &mdash; resources violate the policy, remediation needed</div>
            <div class="legend-item"><span class="legend-dot dot-gray"></span> <strong>Not Evaluated</strong> &mdash; compliance data not yet available from Azure</div>
            <div class="legend-item"><span class="legend-dot dot-amber"></span> <strong>Not Assigned</strong> &mdash; policy is not assigned to any scope</div>
        </div>
        <div class="legend-grid">
            <div class="legend-item"><span class="legend-dot dot-green"></span> Automated pass-rate indicator only &mdash; not a certification threshold</div>
            <div class="legend-item"><span class="legend-dot dot-amber"></span> Bar 50-79% &mdash; partial compliance, gaps exist</div>
            <div class="legend-item"><span class="legend-dot dot-red"></span> Bar &lt; 50% &mdash; weak compliance, significant remediation required</div>
        </div>
    </div>
    $ceGroupSummary
    <details>
        <summary>&#x1F4CB; CE+ Policy Compliance Detail ($($CEPExportData.Count) policies)</summary>
        <div class="details-content">
            <div class="filter-bar">
                <input type="text" id="filter-ce" placeholder="Search CE policies..." oninput="filterTable('ce-table','filter-ce')">
                <span class="count" id="count-ce">$($CEPExportData.Count) policies</span>
                <button class="copy-btn" onclick="copyTable('ce-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            </div>
            <div class="table-wrap">
            <table id="ce-table">
            <thead><tr><th class="sortable" onclick="sortTable('ce-table',0)">Control Group <span class="col-info" data-tip="The Cyber Essentials control group (e.g. Firewalls, Secure Configuration, Access Control)" title="CE control group">&#9432;</span></th><th class="sortable" onclick="sortTable('ce-table',1)">Policy <span class="col-info" data-tip="The Azure Policy definition mapped to this CE control" title="Policy name">&#9432;</span></th><th class="sortable" onclick="sortTable('ce-table',2)">Status <span class="col-info" data-tip="Compliance status: Compliant, Non-Compliant, or Not Evaluated" title="Compliance status">&#9432;</span></th><th class="sortable" onclick="sortTable('ce-table',3)">NC Resources <span class="col-info" data-tip="Number of resources non-compliant with this CE control policy" title="Non-compliant count">&#9432;</span></th><th class="sortable" onclick="sortTable('ce-table',4)">Compliant <span class="col-info" data-tip="Number of resources compliant with this CE control policy" title="Compliant count">&#9432;</span></th><th class="sortable" onclick="sortTable('ce-table',5)">Total <span class="col-info" data-tip="Total resources evaluated against this CE control policy" title="Total evaluated">&#9432;</span></th><th>Recommendation <span class="col-info" data-tip="Suggested action to improve compliance with this CE control" title="Recommended action">&#9432;</span></th></tr></thead>
            <tbody>$ceRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
} elseif ($CEPExportData.Count -eq 0) {
    if ($CEPAssessment.State -eq 'NotRequested') {
        '<div class="callout callout-info"><span class="callout-icon">&#x2139;&#xFE0F;</span><div><strong>CE+ Compliance Not Run</strong><p>Run with <code>-CEP Show</code> or <code>-CEP Full</code> to populate Cyber Essentials policy mapping.</p></div></div>'
    } elseif ($CEPAssessment.State -eq 'EvaluationFailed' -or $CEPAssessment.MappingState -eq 'Failed') {
        '<div class="callout callout-warning"><span class="callout-icon">&#x26A0;&#xFE0F;</span><div><strong>Evaluation failed</strong><p>The mapping query or runtime operation failed; no mapping conclusion was produced.</p></div></div>'
    } elseif ($CEPAssessment.MappingState -eq 'Unavailable') {
        "<div class='callout callout-info'><span class='callout-icon'>&#x2139;&#xFE0F;</span><div><strong>Mapping unavailable</strong><p>$($CEPAssessment.PrerequisiteReason). An empty mapping is not a 0% result.</p></div></div>"
    } else {
        '<div class="callout callout-info"><span class="callout-icon">&#x2139;&#xFE0F;</span><div><strong>Mapping has no evaluated data</strong><p>No mapping score was calculated.</p></div></div>'
    }
})
    </div>
</details>
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!--  5. SECURITY ACTION INVENTORY                         -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="sec-security" class="report-page" data-report-page data-page-group="page-engineer">
<details class="section-disclosure">
    <summary>
        <span>Security Action Inventory</span>
        <span class="section-num">Section 5 of $totalSections</span>
        <span class="disclosure-hint">$highRiskCount high risk · $totalNC affected resources · $($highSecEnforceIssues.Count) high-security gaps</span>
    </summary>
    <div class="section-content">

    <div class="section-intro">
        <p><strong>Purpose:</strong> Actionable, assignment-level inventory ordered by risk and security impact. Use it to identify which policies, scopes, and affected resource types require implementation work.</p>
        <p>Control effectiveness, scope coverage, and preventive/detective/remediation balance are analysed in CSA / Architect. Here, focus on <strong style="color:var(--red)">High Risk</strong> records and assignments in <code>DoNotEnforce</code> mode.</p>
    </div>

    <div class="legend">
        <h4>&#x1F3F7;&#xFE0F; Risk &amp; Security Legend</h4>
        <div class="legend-grid">
            <div class="legend-item"><span class="badge risk-high">High</span> Immediate attention required &mdash; significant security exposure</div>
            <div class="legend-item"><span class="badge risk-med">Medium</span> Should be addressed in planned work cycles</div>
            <div class="legend-item"><span class="badge risk-low">Low</span> Acceptable risk &mdash; monitor periodically</div>
            <div class="legend-item"><strong style="font-size:0.8rem;">Security Impact:</strong><span style="font-size:0.8rem;"> multi-signal score (effect type + category + name keywords + enforcement mode) measuring security value</span></div>
            <div class="legend-item"><strong style="font-size:0.8rem;">Risk Level:</strong><span style="font-size:0.8rem;"> composite score combining security impact, enforcement gaps, and active controls</span></div>
            <div class="legend-item"><strong style="font-size:0.8rem;">Priority Enforcement Gap:</strong><span style="font-size:0.8rem;"> High/Medium security-impact assignment in DoNotEnforce mode &mdash; configured effects are not applied</span></div>
        </div>
        <div style="margin-top:10px;font-size:0.82rem;color:var(--dim);">
            <strong>Parameterised Initiatives:</strong> When member policy effects are parameter-driven (e.g. <code>[parameters(&apos;effect&apos;)]</code>), the security score is inferred from the <strong>category</strong> (Security Center / Defender for Cloud &rarr; +15, Network / Identity &rarr; +10) and <strong>name keywords</strong> (e.g. &ldquo;defender&rdquo;, &ldquo;encrypt&rdquo;, &ldquo;mfa&rdquo; &rarr; +10). Initiatives like ASC Default and Defender for SQL that deploy agents are scored as <strong>High</strong> security impact.
        </div>
    </div>

    <details style="margin-bottom:18px;">
        <summary style="cursor:pointer;font-weight:600;font-size:0.95rem;">&#x1F9EE; How are Security Impact &amp; Risk Level calculated?</summary>
        <div class="details-content" style="padding:12px 16px;">
            <p style="margin-top:0;">Scores use a <strong>multi-signal point system</strong> (0&ndash;100 scale) instead of simple if/else rules. Multiple independent signals are summed, then mapped to High&nbsp;/&nbsp;Medium&nbsp;/&nbsp;Low&nbsp;/&nbsp;None via fixed thresholds.</p>
            <table class="report-table" style="font-size:0.82rem;">
                <thead><tr><th>Signal</th><th>Weight</th><th>Examples</th></tr></thead>
                <tbody>
                    <tr><td><strong>Effect Type</strong> (strongest)</td><td>&pm;35 pts</td><td>Deny&nbsp;+30, DINE&nbsp;+25, Modify&nbsp;+20, Audit&nbsp;+0, Disabled&nbsp;&minus;35</td></tr>
                    <tr><td><strong>Parameterised &times; Category</strong></td><td>+5 to +15 pts</td><td>Parameterised + Security Center&nbsp;+15, + Network/Identity&nbsp;+10, other&nbsp;+5</td></tr>
                    <tr><td><strong>Policy Category</strong></td><td>&pm;15 pts</td><td>Security Center / Key Vault / Encryption&nbsp;+15, Network / Identity&nbsp;+10, Tags / General&nbsp;&minus;15</td></tr>
                    <tr><td><strong>Name Keywords</strong></td><td>+10 pts</td><td>Policies with &ldquo;encrypt&rdquo;, &ldquo;firewall&rdquo;, &ldquo;MFA&rdquo;, &ldquo;defender&rdquo;, &ldquo;asc default&rdquo;, &ldquo;sentinel&rdquo; in their name get boosted</td></tr>
                    <tr><td><strong>Enforcement Mode</strong></td><td>&times;0.65 multiplier</td><td>DoNotEnforce reduces score by 35% (policy still <em>reports</em> violations, so impact is NOT zero)</td></tr>
                </tbody>
            </table>
            <p><strong>Thresholds:</strong> &ge;75 pts = High, &ge;40 pts = Medium, &ge;15 pts = Low, &lt;15 pts = None</p>
            <p><strong>Risk Level</strong> is a separate composite: it adds <em>Security Impact</em> contribution (+40/+20/+5), an enforcement-gap penalty (+15 for DoNotEnforce on High/Medium security), an active-enforcement bonus (&minus;10 for enforced Deny/DINE/Modify), and a disabled penalty (+10). Thresholds: &ge;40 = High, &ge;20 = Medium, &lt;20 = Low.</p>
        </div>
    </details>

    $(if ($enforcementGapRows) {
    @"
    <details>
        <summary>&#x1F513; Priority Enforcement Gaps ($($enforcementGapItems.Count) High/Medium security-impact assignments)</summary>
        <div class="details-content">
            <p class="text-dim" style="margin-bottom:12px;">Action queue containing the risk-prioritised subset of $auditOnlyCount total DoNotEnforce assignments. Their configured effects are not applied.</p>
            <div class="table-wrap">
            <table id="enforcement-gap-table">
            <thead><tr><th class="sortable" onclick="sortTable('enforcement-gap-table',0)">Policy Name <span class="col-info" data-tip="The name of the policy assignment in DoNotEnforce mode" title="Policy name">&#9432;</span></th><th>Scope <span class="col-info" data-tip="Where this policy is assigned (scope name)" title="Assignment scope">&#9432;</span></th><th>Effect Type <span class="col-info" data-tip="The configured policy effect that is not being applied" title="Effect type">&#9432;</span></th><th class="sortable" onclick="sortTable('enforcement-gap-table',3)">Security Impact <span class="col-info" data-tip="How significantly security is affected by this policy not being enforced" title="Security impact">&#9432;</span></th><th>Risk Level <span class="col-info" data-tip="Combined risk assessment while enforcement is disabled" title="Risk level">&#9432;</span></th></tr></thead>
            <tbody>$enforcementGapRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
    })

    <details>
        <summary>&#x1F4CA; Risk-Rated Policy Table ($totalAssignments policies)</summary>
        <div class="details-content">
            <div class="filter-bar">
                <input type="text" id="filter-security" placeholder="Search policies..." oninput="filterTable('security-table','filter-security')">
                <span class="count" id="count-security">$totalAssignments policies</span>
                <button class="copy-btn" onclick="copyTable('security-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            </div>
            <div class="table-wrap">
            <table id="security-table">
            <thead><tr><th class="sortable" onclick="sortTable('security-table',0)">Policy <span class="col-info" data-tip="The policy assignment name" title="Policy name">&#9432;</span></th><th class="sortable" onclick="sortTable('security-table',1)">Risk Level <span class="col-info" data-tip="Combined risk: High = disabled/deny, Medium = audit-only, Low = enforced" title="Risk level">&#9432;</span></th><th class="sortable" onclick="sortTable('security-table',2)">Security Impact <span class="col-info" data-tip="How significantly security is affected if this policy is absent" title="Security impact">&#9432;</span></th><th>Category <span class="col-info" data-tip="Azure Policy definition category" title="Category">&#9432;</span></th><th>Effect <span class="col-info" data-tip="The policy effect: Audit, Deny, DINE, Modify, etc." title="Effect type">&#9432;</span></th><th>Enforcement <span class="col-info" data-tip="Default = enforced; DoNotEnforce = audit-only" title="Enforcement mode">&#9432;</span></th><th class="sortable" onclick="sortTable('security-table',6)">NC Resources <span class="col-info" data-tip="Number of non-compliant resources for this policy" title="NC count">&#9432;</span></th><th>Scope <span class="col-info" data-tip="Where this policy is assigned" title="Scope">&#9432;</span></th></tr></thead>
            <tbody>$securityRows</tbody>
            </table>
            </div>
        </div>
    </details>

    $(if ($NCExportData.Count -gt 0) {
    @"
    <h3 class="sub-title" style="margin-top:20px;">Non-Compliant Resources by Type (Top 15)</h3>
    <div class="section-intro" style="margin-bottom:14px;">
        <p><strong>Purpose:</strong> Shows which Azure resource types have the most non-compliant resources. Click any resource type to <strong>expand</strong> and see the specific policies flagging it, their risk level, and the individual resources affected.</p>
        <p>Use this to <strong>prioritise remediation</strong> &mdash; focus on resource types with <strong>High</strong> risk and the highest non-compliant counts first.</p>
    </div>
    <div class="legend">
        <h4>&#x1F3F7;&#xFE0F; Risk Level Legend</h4>
        <div class="legend-grid">
            <div class="legend-item"><span class="badge status-fail">High</span> Critical risk &mdash; immediate remediation recommended</div>
            <div class="legend-item"><span class="badge status-warn">Medium</span> Moderate risk &mdash; review and plan remediation</div>
            <div class="legend-item"><span class="badge status-pass">Low</span> Lower risk &mdash; monitor and address in normal cycle</div>
        </div>
    </div>
    <div class="table-wrap">
    <table id="nc-type-table"><thead><tr><th class="sortable" onclick="sortTable('nc-type-table',0)">Resource Type <span class="col-info" data-tip="The Azure resource type (e.g. Microsoft.Storage/storageAccounts). Click to expand and see affected policies and individual resources." title="Resource type">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-type-table',1)">Non-Compliant <span class="col-info" data-tip="Number of unique resources of this type that are non-compliant with one or more policies" title="NC count">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-type-table',2)">Policies <span class="col-info" data-tip="Number of distinct policies flagging resources of this type as non-compliant" title="Policy count">&#9432;</span></th><th class="sortable" onclick="sortTable('nc-type-table',3)">Highest Risk <span class="col-info" data-tip="The highest risk level among all policies affecting this resource type (High > Medium > Low)" title="Max risk level">&#9432;</span></th></tr></thead>
    <tbody>$ncByTypeRows</tbody></table>
    </div>
"@
    })
    </div>
</details>
</section>

$alzSectionHtml

<!-- ══════════════════════════════════════════════════════ -->
<!--  7. COST GOVERNANCE                                   -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="sec-cost" class="report-page" data-report-page data-page-group="page-csa">
<details class="section-disclosure">
    <summary>
        <span>Cost Governance</span>
        <span class="section-num">Section $costSectionNumber of $totalSections</span>
        <span class="disclosure-hint">$costHigh high exposure · $opsHigh high overhead · $($validCostEvidence.Count) official records</span>
    </summary>
    <div class="section-content">

    <div class="section-intro">
        <p><strong>Purpose:</strong> Identify qualitative cost exposure and separate it from official price or actual-cost evidence.</p>
        <p><strong>Cost exposure</strong> is a Low/Medium/High heuristic based on effect, category, and policy-name signals. It is not measured spend and does not prove that resources are deployed. <strong>Operational Overhead</strong> estimates management effort.</p>
    </div>

    <div class="legend">
        <h4>&#x1F3F7;&#xFE0F; Cost &amp; Overhead Legend</h4>
        <div class="legend-grid">
            <div class="legend-item"><span class="badge risk-high">Cost exposure: High</span> Heuristic signal requiring validation against official pricing and actual usage.</div>
            <div class="legend-item"><span class="badge risk-med">Cost exposure: Medium</span> Heuristic signal that billable services or operational changes may be involved.</div>
            <div class="legend-item"><span class="badge risk-low">Cost exposure: Low</span> Lower heuristic exposure; this does not establish the absence of charges.</div>
            <div class="legend-item"><span class="badge risk-high">High Overhead</span> Frequent alerts, agent health monitoring, complex exceptions, regular maintenance</div>
            <div class="legend-item"><span class="badge risk-med">Medium Overhead</span> Periodic attention &mdash; compliance reviews, exception management</div>
            <div class="legend-item"><span class="badge risk-low">Low Overhead</span> Set-and-forget &mdash; minimal ongoing effort</div>
        </div>
        <div style="margin-top:10px;font-size:0.82rem;color:var(--dim);">
            <strong>Parameterised Initiatives:</strong> When an initiative&rsquo;s member policies use <code>[parameters(&apos;effect&apos;)]</code>, the actual effect depends on the assigned parameter value. Cost and overhead are inferred from the <strong>category</strong> (e.g. Security Center / Monitoring &rarr; High) and <strong>policy name keywords</strong> (e.g. &ldquo;defender&rdquo;, &ldquo;sentinel&rdquo;, &ldquo;backup&rdquo;).
        </div>
    </div>

    <details style="margin-bottom:18px;">
        <summary style="cursor:pointer;font-weight:600;font-size:0.95rem;">How are Cost Exposure &amp; Operational Overhead classified?</summary>
        <div class="details-content" style="padding:12px 16px;">
            <p style="margin-top:0;"><strong>Cost exposure</strong> combines effect type, policy category, parameterisation, and policy-name signals, then emits only Low, Medium, or High. Internal weighting is not a price estimate.</p>
            <p>DINE/Modify assignments associated with monitoring, backup, security plans, infrastructure, or data ingestion generally increase exposure. Audit, Deny, disabled assignments, and governance metadata generally lower exposure, but none of these signals proves a monetary amount.</p>
            <p><strong>Operational Overhead</strong> considers both effect type <em>and</em> category: DINE/Modify on infrastructure = High, Modify on Tags = Low, Deny = Medium (exception management), Audit = Low. For <strong>Parameterised</strong> initiatives, overhead is inferred from category: Security Center/Monitoring/Backup = High, Network/Compute/SQL = Medium, others = Low.</p>
        </div>
    </details>

    <div class="summary-cards">
        <div class="card card-red"><div class="card-num">$costHigh</div><div class="card-label">Cost exposure: High</div></div>
        <div class="card card-amber"><div class="card-num">$costMedium</div><div class="card-label">Cost exposure: Medium</div></div>
        <div class="card card-green"><div class="card-num">$costLow</div><div class="card-label">Cost exposure: Low</div></div>
    </div>

    <div class="grid-3" style="margin-bottom:20px;">
        <div class="insight-box">
            <h4>Cost Exposure Summary</h4>
            <div class="stat-row"><span>Cost exposure: High</span><strong class="nc-bad">$costHigh</strong></div>
            <div class="stat-row"><span>Cost exposure: Medium</span><strong class="warn-text">$costMedium</strong></div>
            <div class="stat-row"><span>Cost exposure: Low</span><strong>$costLow</strong></div>
        </div>
        <div class="insight-box">
            <h4>&#x2699;&#xFE0F; Operational Overhead <span class="col-info" data-tip="Breakdown of policies by ongoing operational management effort required" title="Operational overhead breakdown">&#9432;</span></h4>
            <div class="stat-row"><span>High overhead</span><strong class="nc-bad">$opsHigh</strong></div>
            <div class="stat-row"><span>Medium overhead</span><strong class="warn-text">$opsMedium</strong></div>
            <div class="stat-row"><span>Low overhead</span><strong>$opsLow</strong></div>
        </div>
        <div class="insight-box">
            <h4>&#x1F4A1; Optimisation Opportunities <span class="col-info" data-tip="Actionable suggestions to reduce cost and complexity of your policy estate" title="Optimisation suggestions">&#9432;</span></h4>
            <ul style="padding-left:18px;">
                $(if ($auditOnlyCount -gt 0) { "<li>$auditOnlyCount assignments use DoNotEnforce. Review business intent, configured effect, exemptions, and impact before changing enforcement mode; zero policy-state records do not establish safe enablement.</li>" })
                $(if ($disabledCount -gt 0) { "<li>$disabledCount disabled policies &mdash; remove to eliminate unnecessary policy evaluation cycles.</li>" })
                $(if ($auditOnlyCount -eq 0 -and $disabledCount -eq 0) { "<li class='text-dim'>No immediate optimisation opportunities identified.</li>" })
            </ul>
        </div>
    </div>

    $(if (-not $costRows) {
        "<div class='callout callout-info'><span class='callout-icon'>&#x2139;&#xFE0F;</span><div><strong>No elevated cost exposure</strong><p>No policies have been classified with elevated heuristic exposure or operational overhead.</p></div></div>"
    })

    <h3 class="sub-title">Official Monetary Evidence</h3>
    $(if ($costEvidenceRows) {
    @"
    <div class="callout callout-info"><div><strong>Official evidence only</strong><p>Retail prices are unit-price records, not workload estimates. Cost Management records are actual costs for the stated period. Every amount includes source, region, currency, price or cost date, and retrieval timestamp.</p></div></div>
    <div class="table-wrap"><table id="cost-evidence-table">
    <thead><tr><th>Description</th><th>Amount</th><th>Unit / Period</th><th>Region</th><th>Official Source</th><th>Price / Cost Date</th><th>Retrieved At</th></tr></thead>
    <tbody>$costEvidenceRows</tbody></table></div>
"@
    } else {
        '<div class="callout callout-info"><div><strong>No official monetary evidence collected</strong><p>No amounts are shown. Enable Retail Prices API or Cost Management evidence explicitly to include sourced monetary data.</p></div></div>'
    })
    </div>
</details>
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!--  8. RECOMMENDATIONS & ROADMAP                         -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="sec-recommendations" class="report-page" data-report-page data-page-group="page-engineer">
<details class="section-disclosure">
    <summary>
        <span>Recommendations &amp; Roadmap</span>
        <span class="section-num">Section $recommendationsSectionNumber of $totalSections</span>
        <span class="disclosure-hint">$remCritical critical · $remHigh high · $remMedium medium · $($remediationItems.Count) total actions</span>
    </summary>
    <div class="section-content">

    <div class="section-intro">
        <p><strong>Purpose:</strong> A consolidated, prioritised action plan generated from all findings in this report. Items are categorised by urgency and mapped to a 30-60-90 day implementation timeline.</p>
        <p>Start with <strong style="color:var(--red)">Critical</strong> items (30-day phase) for immediate security improvements, then address <strong style="color:var(--amber)">High</strong> priority items (60-day), and finally <strong>Medium</strong> items (90-day) for long-term posture improvement.</p>
    </div>

    <div class="legend">
        <h4>&#x1F3F7;&#xFE0F; Priority &amp; Effort Legend</h4>
        <div class="legend-grid">
            <div class="legend-item"><span class="badge status-fail">Critical</span> Must fix immediately &mdash; active security exposure</div>
            <div class="legend-item"><span class="badge status-pass">Low Effort</span> Quick win &mdash; can be done in hours</div>
            <div class="legend-item"><span class="badge status-nc">High</span> Fix within 60 days &mdash; compliance/security gap</div>
            <div class="legend-item"><span class="badge status-warn">Medium Effort</span> Requires planning &mdash; days to weeks</div>
            <div class="legend-item"><span class="badge status-warn">Medium</span> Address within 90 days &mdash; improvement opportunity</div>
            <div class="legend-item"><span class="badge status-fail">High Effort</span> Significant project &mdash; weeks to months</div>
        </div>
    </div>

    <div class="note-box"><span class="note-icon">&#x1F4AC;</span><span><strong>How the roadmap works:</strong> Items are automatically categorised into 30/60/90-day phases based on priority and effort. The <strong style="color:var(--red)">30-day</strong> column contains critical, low-effort wins. The <strong style="color:var(--amber)">60-day</strong> column covers high-priority compliance work. The <strong style="color:var(--green)">90-day</strong> column addresses coverage gaps and housekeeping.</span></div>

    <details class="report-disclosure depth-3">
    <summary>Remediation Operational Evidence <span class="disclosure-meta">Task, identity, role, and scope records</span></summary>
    <div class="details-content">
    <div class="section-intro"><p>States below come from remediation task, policy-state, managed identity, role assignment, and scope-control evidence. <strong>Succeeded</strong> means a task explicitly reported success; it does not by itself prove current resource compliance. <strong>NotAssessed</strong> means evidence collection was insufficient and is not a healthy or failed conclusion.</p></div>
$(if ($remediationEvidenceRows) {
@"
    <div class="table-wrap"><table id="remediation-evidence-table">
    <thead><tr><th>Assignment</th><th>Evidence State</th><th>Managed Identity</th><th>Roles</th><th>Remediation Task</th><th>Applicable Resources</th><th>Last Evaluation</th><th>Exemptions / Scope Controls</th><th>Errors</th></tr></thead>
    <tbody>$remediationEvidenceRows</tbody></table></div>
"@
} else {
    '<div class="callout callout-info"><div><strong>No remediation evidence records</strong><p>No DINE/Modify assignment evidence was available. No working or failed remediation conclusion is reported.</p></div></div>'
})
    </div>
    </details>

    <div class="summary-cards">
        <div class="card card-red" title="Items requiring immediate action — active security exposure"><div class="card-num">$remCritical</div><div class="card-label">Critical <span class="col-info" data-tip="Must fix immediately — these represent active security exposure or critical compliance gaps" title="Critical items">&#9432;</span></div></div>
        <div class="card card-amber" title="Items to address within 60 days"><div class="card-num">$remHigh</div><div class="card-label">High <span class="col-info" data-tip="Fix within 60 days — compliance or security gaps that need planned attention" title="High priority items">&#9432;</span></div></div>
        <div class="card card-gray" title="Items to address within 90 days for posture improvement"><div class="card-num">$remMedium</div><div class="card-label">Medium <span class="col-info" data-tip="Address within 90 days — improvement opportunities and coverage optimisation" title="Medium priority items">&#9432;</span></div></div>
        <div class="card card-blue" title="Total number of remediation actions identified"><div class="card-num">$($remediationItems.Count)</div><div class="card-label">Total Actions <span class="col-info" data-tip="Total remediation items across all priority levels" title="Total actions">&#9432;</span></div></div>
    </div>

    <h3 class="sub-title">30-60-90 Day Roadmap</h3>
    <div class="roadmap">
        <div class="roadmap-phase phase-30">
            <h4>&#x1F534; 30 Days &mdash; Critical</h4>
            <div class="phase-label">Immediate security wins &middot; $($phase30.Count) items</div>
            <ul>$roadmap30Html</ul>
        </div>
        <div class="roadmap-phase phase-60">
            <h4>&#x1F7E0; 60 Days &mdash; High Priority</h4>
            <div class="phase-label">Compliance &amp; remediation &middot; $($phase60.Count) items</div>
            <ul>$roadmap60Html</ul>
        </div>
        <div class="roadmap-phase phase-90">
            <h4>&#x1F7E2; 90 Days &mdash; Medium Priority</h4>
            <div class="phase-label">Coverage &amp; optimisation &middot; $($phase90.Count) items</div>
            <ul>$roadmap90Html</ul>
        </div>
    </div>

$(if ($remediationItems.Count -gt 0) {
@"
    <details>
        <summary>&#x1F4CB; Full Remediation Action Plan ($($remediationItems.Count) items)</summary>
        <div class="details-content">
            <div class="filter-bar">
                <input type="text" id="filter-remediation" placeholder="Search actions..." oninput="filterTable('remediation-table','filter-remediation')">
                <span class="count" id="count-remediation">$($remediationItems.Count) actions</span>
                <button class="copy-btn" onclick="copyTable('remediation-table',this)" title="Copy table to clipboard">&#x1F4CB; Copy</button>
            </div>
            <div class="table-wrap">
            <table id="remediation-table">
            <thead><tr><th class="sortable" onclick="sortTable('remediation-table',0)">Priority <span class="col-info" data-tip="Urgency level: Critical (fix now), High (within 60 days), Medium (within 90 days)" title="Priority level">&#9432;</span></th><th class="sortable" onclick="sortTable('remediation-table',1)">Phase <span class="col-info" data-tip="Implementation timeline: 30-day (quick wins), 60-day (compliance), 90-day (optimisation)" title="Roadmap phase">&#9432;</span></th><th class="sortable" onclick="sortTable('remediation-table',2)">Action <span class="col-info" data-tip="The specific remediation action to take" title="Action item">&#9432;</span></th><th class="sortable" onclick="sortTable('remediation-table',3)">Effort <span class="col-info" data-tip="Estimated effort: Low (hours), Medium (days-weeks), High (weeks-months)" title="Effort estimate">&#9432;</span></th><th class="sortable" onclick="sortTable('remediation-table',4)">Category <span class="col-info" data-tip="The remediation category (e.g. Security, Compliance, Cost)" title="Category">&#9432;</span></th><th>Impact <span class="col-info" data-tip="Expected improvement from completing this action" title="Expected impact">&#9432;</span></th><th>Scope <span class="col-info" data-tip="Which scope(s) this action applies to" title="Scope">&#9432;</span></th></tr></thead>
            <tbody>$remediationRows</tbody>
            </table>
            </div>
        </div>
    </details>
"@
} elseif ($hasEvaluatedCompliance) {
    '<div class="callout callout-success"><span class="callout-icon">&#x2705;</span><div><strong>No Remediation Items</strong><p>No action items were identified from the available evaluated data.</p></div></div>'
} else {
    '<div class="callout callout-info"><span class="callout-icon">&#x2139;&#xFE0F;</span><div><strong>Remediation assessment unavailable</strong><p>Compliance data must be evaluated before remediation needs can be assessed.</p></div></div>'
})
    </div>
</details>
</section>

$yamlDeltaSectionHtml

<!-- ── Glossary ── -->
<details class="report-disclosure depth-3 glossary report-page" data-report-page data-page-group="page-methodology">
    <summary>Glossary of Terms <span class="disclosure-meta">Reference</span></summary>
    <div class="details-content">
    <div class="glossary-grid">
        <div class="glossary-item"><span class="glossary-term">Assignment</span><span class="glossary-def">A policy or initiative linked to a specific scope (MG, subscription, or resource group). See <a href="https://learn.microsoft.com/en-us/azure/governance/policy/concepts/assignment-structure" target="_blank" style="color:var(--accent);">docs</a></span></div>
        <div class="glossary-item"><span class="glossary-term">Policy</span><span class="glossary-def">A single rule that evaluates resources for compliance (e.g. &ldquo;Storage accounts must use HTTPS&rdquo;)</span></div>
        <div class="glossary-item"><span class="glossary-term">Initiative</span><span class="glossary-def">A collection of related policies grouped together for easier management (also called a Policy Set Definition)</span></div>
        <div class="glossary-item"><span class="glossary-term">Regulatory</span><span class="glossary-def">A built-in initiative mapped to a compliance standard (e.g. CIS, NIST, PCI DSS, ISO 27001)</span></div>
        <div class="glossary-item"><span class="glossary-term">Non-Compliant (NC)</span><span class="glossary-def">A resource that violates one or more policy rules and needs remediation</span></div>
        <div class="glossary-item"><span class="glossary-term">Enforced (Default)</span><span class="glossary-def">Assignment enforcement mode is <code>Default</code> &mdash; Azure applies the policy effect (Deny blocks, Audit flags, DINE/Modify remediates)</span></div>
        <div class="glossary-item"><span class="glossary-term">Enforcement disabled (DoNotEnforce)</span><span class="glossary-def">Assignment enforcement mode is <code>DoNotEnforce</code> &mdash; Azure evaluates compliance but does NOT apply any effect. See <a href="https://learn.microsoft.com/en-us/azure/governance/policy/concepts/assignment-structure#enforcement-mode" target="_blank" style="color:var(--accent);">docs</a></span></div>
        <div class="glossary-item"><span class="glossary-term">Management Group</span><span class="glossary-def">Top-level scope &mdash; policies here are inherited by all child subscriptions and resource groups</span></div>
        <div class="glossary-item"><span class="glossary-term">Deny</span><span class="glossary-def">Preventive effect &mdash; blocks the action entirely before it happens. See <a href="https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects#deny" target="_blank" style="color:var(--accent);">docs</a></span></div>
        <div class="glossary-item"><span class="glossary-term">Audit / AuditIfNotExists</span><span class="glossary-def">Detective effect &mdash; flags non-compliant resources but allows the action to proceed</span></div>
        <div class="glossary-item"><span class="glossary-term">DeployIfNotExists (DINE)</span><span class="glossary-def">Remediating effect that can deploy missing configurations when enforcement, identity, roles, scope, and evaluation prerequisites are satisfied. See <a href="https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects#deployifnotexists" target="_blank" style="color:var(--accent);">docs</a></span></div>
        <div class="glossary-item"><span class="glossary-term">Modify</span><span class="glossary-def">Remediating effect that can correct resource properties when its prerequisites and applicable operations are satisfied</span></div>
        <div class="glossary-item"><span class="glossary-term">Parameterised</span><span class="glossary-def">Policy effect is defined via a parameter (e.g. <code>[parameters('effect')]</code>). The actual effect depends on the value assigned &mdash; most Azure built-in policies default to Audit</span></div>
        <div class="glossary-item"><span class="glossary-term">Disabled</span><span class="glossary-def">Policy effect is disabled &mdash; Azure does not evaluate resources against it. Counts as a governance gap. See <a href="https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects#disabled" target="_blank" style="color:var(--accent);">docs</a></span></div>
        <div class="glossary-item"><span class="glossary-term">Control Type Balance</span><span class="glossary-def">Distribution of Preventive (Deny), Detective (Audit), and Remediation (DINE/Modify) effects. Defence in depth requires all three. Suggested ranges in this tool are opinionated guidance, not official targets</span></div>
        <div class="glossary-item"><span class="glossary-term">Anti-Pattern</span><span class="glossary-def">A detected governance misconfiguration (e.g. disabled policies, enforcement gaps, missing guardrails, duplicate assignments). Expand each item for details, affected resources, and Microsoft docs references</span></div>
        <div class="glossary-item"><span class="glossary-term">Exemption</span><span class="glossary-def">Allows a specific scope to be excluded from policy evaluation. Types: <strong>Waiver</strong> (accepted risk, time-limited) or <strong>Mitigated</strong> (alternative control in place). Can be full or partial (specific policies within an initiative). See <a href="https://learn.microsoft.com/en-us/azure/governance/policy/concepts/exemption-structure" target="_blank" style="color:var(--accent);">docs</a></span></div>
        <div class="glossary-item"><span class="glossary-term">CE / CE+ <span class="experimental-tag">Exp.</span></span><span class="glossary-def">Cyber Essentials / Cyber Essentials Plus &mdash; UK NCSC security certification scheme. CE/CE+ features in this tool are <strong>experimental</strong> and community-maintained; they are not official certification assessments</span></div>
        <div class="glossary-item"><span class="glossary-term">Risk Level</span><span class="glossary-def">Combined multi-signal assessment (0&ndash;100 point scale): adds Security Impact contribution, enforcement-gap penalty, active-enforcement bonus, and disabled penalty. Thresholds: &ge;40 High, &ge;20 Medium, &lt;20 Low</span></div>
        <div class="glossary-item"><span class="glossary-term">Security Impact</span><span class="glossary-def">Multi-signal score (0&ndash;100): effect type (&pm;35), category (&pm;15), name keywords (+10), enforcement multiplier (&times;0.65 if DoNotEnforce). Thresholds: &ge;75 High, &ge;40 Medium, &ge;15 Low, &lt;15 None</span></div>
        <div class="glossary-item"><span class="glossary-term">Cost Exposure</span><span class="glossary-def">Qualitative Low/Medium/High heuristic based on effect, category, parameterisation, and policy-name signals. It is not a price estimate or measured spend.</span></div>
        <div class="glossary-item"><span class="glossary-term">Operational Overhead</span><span class="glossary-def">Management effort derived from effect type &times; category: DINE/Modify on infra = High, Deny = Medium (exception handling), Audit = Low. Parameterised initiatives use category inference: Security Center/Monitoring = High, Network/Compute = Medium, others = Low</span></div>
        <div class="glossary-item"><span class="glossary-term">Category</span><span class="glossary-def">The policy definition category from Azure metadata (e.g. Security Center, Network, Monitoring, Tags)</span></div>
        <div class="glossary-item"><span class="glossary-term">Scope</span><span class="glossary-def">The Azure hierarchy level where a policy is assigned: Management Group (inherited) &gt; Subscription &gt; Resource Group (most specific)</span></div>
        <div class="glossary-item"><span class="glossary-term">Delta Assessment</span><span class="glossary-def">Comparison between the current run and a previous YAML snapshot. Shows new, removed, and changed assignments, compliance drift, and exemption changes. Generate with <code>-Output YAML</code> and compare with <code>-DeltaYAML &lt;path&gt;</code></span></div>
    </div>
    </div>
</details>
</main>

<!-- ── Footer ── -->
<hr class="divider">
<p class="text-dim" style="text-align:center;padding:16px 0;">
    Azure Policy Assessment Report &middot; Generated $reportDate
    $(if ($TenantName) { "&middot; Tenant: $TenantName" })
    $(if ($FilterLabel) { "&middot; Filter: $FilterLabel" } else { "&middot; Scope: All (tenant-wide)" })
    &middot; Script v$ScriptVersion
</p>

</div><!-- /container -->

<script>
function showPage(pageId, updateHash = true) {
    const targetGroup = document.querySelector('[data-page-group="' + pageId + '"]') ? pageId : 'page-summary';
    document.querySelectorAll('[data-report-page]').forEach(block => block.classList.toggle('active', block.dataset.pageGroup === targetGroup));
    let activeLink = null;
    document.querySelectorAll('#main-nav a[data-page]').forEach(link => {
        const isActive = link.dataset.page === targetGroup;
        link.classList.toggle('active', isActive);
        if (isActive) activeLink = link;
    });
    if (activeLink) activeLink.scrollIntoView({ behavior: 'auto', block: 'nearest', inline: 'center' });
    if (updateHash) history.replaceState(null, '', '#' + targetGroup);
    window.scrollTo({ top: 0, behavior: 'auto' });
}

function showPageForElement(element, updateHash = false) {
    const block = element && element.closest('[data-report-page]');
    if (block) showPage(block.dataset.pageGroup, updateHash);
    return block;
}

document.querySelectorAll('#main-nav a[data-page]').forEach(link => {
    link.addEventListener('click', event => {
        event.preventDefault();
        showPage(link.dataset.page);
    });
});

function routeHash() {
    const target = document.querySelector(window.location.hash || '#page-summary');
    if (!target) return showPage('page-summary', false);
    const block = target.matches('[data-report-page]') ? target : target.closest('[data-report-page]');
    if (block) showPage(block.dataset.pageGroup, false);
    if (target !== block) {
        let parentDetail = target.closest('details');
        while (parentDetail) {
            parentDetail.open = true;
            parentDetail = parentDetail.parentElement && parentDetail.parentElement.closest('details');
        }
        target.scrollIntoView({ block: 'start' });
    }
}

window.addEventListener('hashchange', routeHash);
document.body.classList.add('pages-ready');
routeHash();

// ── Info Tooltip (JS-powered, immune to overflow clipping) ──
(function() {
    var tip = document.createElement('div');
    tip.className = 'info-tooltip';
    document.body.appendChild(tip);
    document.addEventListener('mouseover', function(e) {
        var el = e.target.closest('.col-info');
        if (!el) return;
        var text = el.getAttribute('data-tip');
        if (!text) return;
        tip.textContent = text;
        tip.classList.add('visible');
        var rect = el.getBoundingClientRect();
        var tipW = tip.offsetWidth;
        var tipH = tip.offsetHeight;
        var left = rect.left + rect.width / 2 - tipW / 2;
        var top = rect.top - tipH - 8;
        if (top < 4) top = rect.bottom + 8;
        if (left < 4) left = 4;
        if (left + tipW > window.innerWidth - 4) left = window.innerWidth - tipW - 4;
        tip.style.left = left + 'px';
        tip.style.top = top + 'px';
    });
    document.addEventListener('mouseout', function(e) {
        var el = e.target.closest('.col-info');
        if (el) tip.classList.remove('visible');
    });
})();

// Navigate to a section and open a specific details element
function navigateTo(sectionId, detailsId) {
    const section = document.getElementById(sectionId);
    if (section) {
        showPageForElement(section);
        const pageDetail = section.closest('.page-detail');
        if (pageDetail) pageDetail.open = true;
        const sectionDetail = section.querySelector(':scope > details.section-disclosure');
        if (sectionDetail) sectionDetail.open = true;
        section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    if (detailsId) {
        const details = document.getElementById(detailsId);
        if (details) {
            details.open = true;
            setTimeout(() => details.scrollIntoView({ behavior: 'smooth', block: 'start' }), 300);
        }
    }
}

// ── Table filtering ──
function filterTable(tableId, inputId) {
    const q = document.getElementById(inputId).value.toLowerCase();
    const rows = document.querySelectorAll('#' + tableId + ' tbody tr');
    let visible = 0;
    rows.forEach(r => {
        const match = r.textContent.toLowerCase().includes(q);
        r.style.display = match ? '' : 'none';
        if (match) visible++;
    });
    const countEl = document.getElementById('count-' + inputId.replace('filter-',''));
    if (countEl) countEl.textContent = visible + ' of ' + rows.length + ' shown';
}

// ── Copy table to clipboard (TSV — pastes into Excel) ──
function copyTable(tableId, btn) {
    const table = document.getElementById(tableId);
    if (!table) return;
    const rows = table.querySelectorAll('tr');
    const lines = [];
    rows.forEach(r => {
        if (r.style.display === 'none') return;
        const cells = Array.from(r.querySelectorAll('th, td'));
        lines.push(cells.map(c => c.textContent.trim().replace(/\t/g, ' ')).join('\t'));
    });
    navigator.clipboard.writeText(lines.join('\n')).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = '&#x2705; Copied!';
        btn.classList.add('copied');
        setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('copied'); }, 2000);
    });
}

// ── Table sorting ──
let sortDirs = {};
function sortTable(tableId, colIdx) {
    const key = tableId + '-' + colIdx;
    sortDirs[key] = !sortDirs[key];
    const asc = sortDirs[key];
    const tbody = document.querySelector('#' + tableId + ' tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((a, b) => {
        let av = a.cells[colIdx]?.textContent.trim() || '';
        let bv = b.cells[colIdx]?.textContent.trim() || '';
        const an = parseFloat(av), bn = parseFloat(bv);
        if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    rows.forEach(r => tbody.appendChild(r));
}
</script>
</body>
</html>
"@

    $html = $html.Replace('Audit Only', 'Enforcement Disabled').Replace('Audit-only', 'Enforcement disabled').Replace('audit-only', 'enforcement disabled')
    $html | Out-File -FilePath $OutputPath -Encoding utf8 -Force
}

#endregion Function Definitions

#region CE/CE+ Test Functions

# Friendly display names for known Cyber Essentials v3.1 control groups
$Global:CEPGroupFriendlyNames = @{
    'Cyber_Essentials_v3.1_'  = 'General Controls'
    'Cyber_Essentials_v3.1_1' = 'Firewalls'
    'Cyber_Essentials_v3.1_2' = 'Secure Configuration'
    'Cyber_Essentials_v3.1_3' = 'Malware protection'
    'Cyber_Essentials_v3.1_4' = 'User Access Control'
    'Cyber_Essentials_v3.1_5' = 'Security Update Management'
}

function New-CEPAssessment {
    param(
        [Parameter(Mandatory)][bool]$Requested,
        [Parameter(Mandatory)]
        [ValidateSet('NotRequested', 'PrerequisiteUnavailable', 'PartiallyEvaluated', 'Evaluated', 'EvaluationFailed')]
        [string]$State,
        [ValidateSet('NotRequested', 'Pending', 'Available', 'Unavailable', 'Failed')]
        [string]$MappingState = 'NotRequested',
        [ValidateSet('NotRequested', 'Pending', 'PartiallyEvaluated', 'Evaluated', 'Failed')]
        [string]$TestState = 'NotRequested',
        [ValidateSet('NotMeasured', 'Measured')]
        [string]$ScoreState = 'NotMeasured',
        [AllowNull()][Nullable[double]]$Score = $null,
        [string]$PrerequisiteReason = '',
        [ValidateSet('NotRequested', 'Pending', 'Available', 'Renamed', 'RetiredOrUnavailable', 'Unavailable', 'DiscoveryFailed')]
        [string]$MappingSourceState = 'NotRequested',
        [string]$DefinitionId = '',
        [string]$DefinitionVersion = '',
        [string]$DefinitionDisplayName = '',
        [string]$SelectionMethod = '',
        [array]$CandidateDefinitions = @(),
        $DataQuality = $null
    )

    if ($ScoreState -eq 'NotMeasured') { $Score = $null }
    if ($null -eq $DataQuality) {
        $DataQuality = [PSCustomObject][ordered]@{
            State       = switch ($State) {
                'NotRequested' { 'NotMeasured' }
                'PrerequisiteUnavailable' { 'Unavailable' }
                'PartiallyEvaluated' { 'Partial' }
                'Evaluated' { 'Complete' }
                'EvaluationFailed' { 'Failed' }
            }
            EvidenceCount = 0
            Limitations = @(
                if ($PrerequisiteReason) { $PrerequisiteReason }
            )
        }
    }

    return [PSCustomObject][ordered]@{
        Requested          = $Requested
        State              = $State
        MappingState       = $MappingState
        TestState          = $TestState
        ScoreState         = $ScoreState
        Score              = $Score
        PrerequisiteReason = $PrerequisiteReason
        MappingSourceState = $MappingSourceState
        DefinitionId       = $DefinitionId
        DefinitionVersion  = $DefinitionVersion
        DefinitionDisplayName = $DefinitionDisplayName
        SelectionMethod    = $SelectionMethod
        CandidateDefinitions = @($CandidateDefinitions)
        DataQuality        = $DataQuality
    }
}

function Resolve-CEPMappingSource {
    param(
        [string]$DefinitionId = '',
        [ValidateNotNullOrEmpty()][string]$DefinitionVersion = '3.1',
        [AllowNull()][AllowEmptyCollection()][object[]]$Definitions = $null
    )

    $expectedDisplayName = "UK NCSC Cyber Essentials v$DefinitionVersion"
    try {
        if ($null -eq $Definitions) {
            $Definitions = @(Get-AzPolicySetDefinition -BuiltIn -ErrorAction Stop)
        }
    } catch {
        $diagnosticMessage = [string]$_.Exception.Message
        $safeMessage = if ($diagnosticMessage -match '(?i)InvalidAuthenticationTokenTenant|access token is from the wrong issuer') {
            'Azure Policy definition discovery could not run because the active Azure token tenant does not match the subscription tenant. Reauthenticate against a tenant associated with the subscription and rerun the assessment.'
        } else {
            'Azure Policy built-in definition discovery failed. Review the console diagnostic and rerun the assessment.'
        }
        return [PSCustomObject][ordered]@{
            State = 'DiscoveryFailed'; Definition = $null; SelectionMethod = ''
            ExpectedDisplayName = $expectedDisplayName; ConfiguredId = $DefinitionId; ConfiguredVersion = $DefinitionVersion
            Candidates = @(); Message = $safeMessage; DiagnosticMessage = $diagnosticMessage
        }
    }

    $definitionRecords = @($Definitions | ForEach-Object {
        $resourceId = if ($_.ResourceId) { [string]$_.ResourceId } elseif ($_.Id) { [string]$_.Id } else { '' }
        $name = [string]$_.Name
        $displayName = [string]$_.DisplayName
        $metadata = if ($_.Metadata) { $_.Metadata } elseif ($_.Properties.Metadata) { $_.Properties.Metadata } else { $null }
        [PSCustomObject][ordered]@{
            Definition = $_
            Id = $resourceId
            Name = $name
            DisplayName = $displayName
            Version = if ($metadata -and $metadata.version) { [string]$metadata.version } else { '' }
        }
    })
    $candidates = @($definitionRecords | Where-Object { $_.DisplayName -match '(?i)Cyber Essentials' } | ForEach-Object {
        [PSCustomObject][ordered]@{ Id = $_.Id; Name = $_.Name; DisplayName = $_.DisplayName; Version = $_.Version }
    })

    $selected = $null
    $selectionMethod = ''
    if (-not [string]::IsNullOrWhiteSpace($DefinitionId)) {
        $configuredLeaf = ($DefinitionId.TrimEnd('/') -split '/')[-1]
        $selected = $definitionRecords | Where-Object {
            [string]::Equals($_.Id, $DefinitionId, [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals($_.Name, $configuredLeaf, [System.StringComparison]::OrdinalIgnoreCase)
        } | Select-Object -First 1
        if ($selected) { $selectionMethod = 'DefinitionId' }
    }

    if (-not $selected) {
        $selected = $definitionRecords | Where-Object {
            [string]::Equals($_.DisplayName, $expectedDisplayName, [System.StringComparison]::OrdinalIgnoreCase)
        } | Select-Object -First 1
        if ($selected) { $selectionMethod = 'ExactDisplayName' }
    }

    if ($selected) {
        $message = if ($selectionMethod -eq 'DefinitionId') {
            "Azure Policy mapping source resolved by configured definition ID '$DefinitionId'."
        } elseif ($DefinitionId) {
            "Configured definition ID '$DefinitionId' was not returned; exact display-name fallback resolved '$expectedDisplayName'."
        } else {
            "Azure Policy mapping source resolved by exact display name '$expectedDisplayName'."
        }
        return [PSCustomObject][ordered]@{
            State = 'Available'; Definition = $selected.Definition; SelectionMethod = $selectionMethod
            ExpectedDisplayName = $expectedDisplayName; ConfiguredId = $DefinitionId; ConfiguredVersion = $DefinitionVersion
            Candidates = $candidates; Message = $message
        }
    }

    if ($candidates.Count -gt 0) {
        $state = 'Renamed'
        $message = "Expected Azure Policy mapping source '$expectedDisplayName' was not matched exactly; candidate Cyber Essentials definitions were discovered and require explicit selection."
    } elseif ($DefinitionId) {
        $state = 'RetiredOrUnavailable'
        $message = "Configured CE mapping definition ID '$DefinitionId' was not returned and no Cyber Essentials candidates were discovered; the source may be retired or unavailable."
    } else {
        $state = 'Unavailable'
        $message = "Azure Policy mapping source '$expectedDisplayName' and candidate Cyber Essentials definitions were not returned by built-in definition discovery."
    }

    [PSCustomObject][ordered]@{
        State = $state; Definition = $null; SelectionMethod = ''
        ExpectedDisplayName = $expectedDisplayName; ConfiguredId = $DefinitionId; ConfiguredVersion = $DefinitionVersion
        Candidates = $candidates; Message = $message
    }
}

function Get-CEPScore {
    param(
        [array]$TestResults = @(),
        [switch]$MeasurementBlocked
    )

    $technicalVerdicts = @($TestResults | Where-Object {
        $_.'Test #' -match '^TC[1-5]$' -and $_.Status -in @('PASS', 'FAIL')
    })
    $passCount = @($technicalVerdicts | Where-Object Status -eq 'PASS').Count
    $failCount = @($technicalVerdicts | Where-Object Status -eq 'FAIL').Count
    $denominator = $passCount + $failCount
    $isMeasured = -not $MeasurementBlocked -and $denominator -gt 0

    return [PSCustomObject][ordered]@{
        Pass        = $passCount
        Fail        = $failCount
        Denominator = $denominator
        ScoreState  = if ($isMeasured) { 'Measured' } else { 'NotMeasured' }
        Score       = if ($isMeasured) { [math]::Round(($passCount / $denominator) * 100, 1) } else { $null }
    }
}

function Invoke-CEPInitiativeAssessment {
    <#
    .SYNOPSIS
        Runs Azure Policy mapping against the UK NCSC Cyber Essentials v3.1 initiative
        and independent technical checks against the NCSC CE+ v3.2 test specification.
    .DESCRIPTION
        This function performs two phases:
        Phase 1 — Initiative Compliance (Tests T1-T5+):
            1. Verifies the Azure Policy mapping source (UK NCSC Cyber Essentials v3.1) exists in the tenant
            2. Checks the initiative is assigned at an appropriate scope
            3. Optionally triggers an on-demand compliance scan
            4. Queries per-policy compliance state from Azure Resource Graph
            5. Evaluates each policy against PASS/FAIL/WARN criteria grouped by CE control area
        Phase 2 — CE+ v3.2 Test Specification (Test Cases TC1-TC5):
            TC1. Remote Vulnerability Assessment (public IPs, open ports, vulnerability scan results)
            TC2. Patching / Authenticated Scan (missing patches, CVSS 7+ vulns, 14-day fix window)
            TC3. Malware Protection (endpoint protection, anti-malware status, signature currency)
            TC4. MFA Configuration (conditional access, MFA enforcement for users and admins)
            TC5. Account Separation (admin vs standard user role assignment checks)
        
        Automated checks use Azure Resource Graph queries. Subtests that require physical or
        interactive verification are flagged as MANUAL and listed for the assessor to complete.
        
        References:
        - NCSC CE+ v3.2 Test Specification : https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf
        - Azure CE+ Compliance Offering    : https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$PolicyAssignments,
        
        [Parameter(Mandatory=$false)]
        [switch]$TriggerScan,
        
        [Parameter(Mandatory=$false)]
        [switch]$ExportResults,

        [string]$DefinitionId = '',

        [ValidateNotNullOrEmpty()][string]$DefinitionVersion = '3.1'
    )
    
    Write-Host ""
    Write-Host "   ═══════════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "     CYBER ESSENTIALS — COMPLIANCE EVALUATION TESTS (CE & CE+)" -ForegroundColor Magenta
    Write-Host "     Policy Map : UK NCSC Cyber Essentials v3.1 initiative" -ForegroundColor White
    Write-Host "     Test Spec  : NCSC CE+ v3.2 Test Specification" -ForegroundColor White
    Write-Host "     " -NoNewline; Write-Host "⚠️  EXPERIMENTAL — Results may not be 100% accurate" -ForegroundColor Yellow
    Write-Host "   ═══════════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""
    
    $testResults = [System.Collections.ArrayList]@()
    $testNumber = 0
    $passCount = 0
    $failCount = 0
    $warnCount = 0
    $skipCount = 0
    $manualCount = 0
    $cepAssessment = New-CEPAssessment -Requested $true -State PartiallyEvaluated -MappingState Pending -TestState Pending
    
    # ─── Helper to record a test result ───
    function Add-TestResult {
        param(
            [string]$TestId,
            [string]$ControlGroup,
            [string]$TestName,
            [string]$Status,        # PASS, FAIL, WARN, SKIP, MANUAL
            [string]$Details,
            [int]$NonCompliant = 0,
            [int]$Compliant = 0,
            [int]$Total = 0
        )
        [void]$testResults.Add([PSCustomObject]@{
            'Test #'           = $TestId
            'Control Group'    = $ControlGroup
            'Test Name'        = $TestName
            'Status'           = $Status
            'Details'          = $Details
            'Non-Compliant'    = $NonCompliant
            'Compliant'        = $Compliant
            'Total Resources'  = $Total
        })
    }
    
    # ═══════════════════════════════════════════════════════
    # TEST 1: Initiative Definition Exists
    # ═══════════════════════════════════════════════════════
    $testNumber++
    Write-Host "   TEST $testNumber : Azure Policy CE Mapping Source Exists" -ForegroundColor White -NoNewline
    
    Write-Progress -Activity "CE Compliance Tests" -Status "Resolving CE mapping source..." -PercentComplete 5 -Id 20
    $sourceResolution = Resolve-CEPMappingSource -DefinitionId $DefinitionId -DefinitionVersion $DefinitionVersion
    $ceInitiative = $sourceResolution.Definition
    
    if ($ceInitiative) {
        Write-Host " [PASS]" -ForegroundColor Green
        Write-Host "         Found: $($ceInitiative.DisplayName) via $($sourceResolution.SelectionMethod)" -ForegroundColor DarkGray
        $passCount++
        Add-TestResult -TestId "T$testNumber" -ControlGroup "Prerequisites" -TestName "Azure Policy CE Mapping Source Exists" -Status "PASS" -Details "$($sourceResolution.Message) Found: $($ceInitiative.DisplayName)"
    } else {
        Write-Host " [SKIP]" -ForegroundColor DarkGray
        Write-Host "         $($sourceResolution.Message)" -ForegroundColor Yellow
        if ($sourceResolution.DiagnosticMessage) {
            Write-Host "         Diagnostic: $($sourceResolution.DiagnosticMessage)" -ForegroundColor DarkGray
        }
        if ($sourceResolution.Candidates.Count -gt 0) {
            Write-Host "         Candidate definitions:" -ForegroundColor DarkGray
            $sourceResolution.Candidates | ForEach-Object { Write-Host "           • $($_.DisplayName) [$($_.Name)]" -ForegroundColor DarkGray }
        }
        $skipCount++
        Add-TestResult -TestId "T$testNumber" -ControlGroup "Prerequisites" -TestName "Azure Policy CE Mapping Source Exists" -Status "SKIP" -Details "$($sourceResolution.Message) Azure Policy mapping was not evaluated."
        $mappingFailed = $sourceResolution.State -eq 'DiscoveryFailed'
        $cepAssessment = New-CEPAssessment `
            -Requested $true `
            -State $(if ($mappingFailed) { 'EvaluationFailed' } else { 'PrerequisiteUnavailable' }) `
            -MappingState $(if ($mappingFailed) { 'Failed' } else { 'Unavailable' }) `
            -TestState PartiallyEvaluated `
            -ScoreState NotMeasured `
            -PrerequisiteReason $sourceResolution.Message `
            -MappingSourceState $sourceResolution.State `
            -DefinitionId $sourceResolution.ConfiguredId `
            -DefinitionVersion $sourceResolution.ConfiguredVersion `
            -DefinitionDisplayName $sourceResolution.ExpectedDisplayName `
            -CandidateDefinitions $sourceResolution.Candidates
        
        Write-Host "`n   Mapping phase blocked; independent CE+ technical tests will continue." -ForegroundColor Yellow
        return @{ Assessment = $cepAssessment; TestResults = $testResults; NextTestNumber = $testNumber; PerScopeData = @(); PerScopeGroupData = @{}; PerScopeGroupRaw = @{}; RefIdToGroupDisplay = @{} }
    }
    
    $ceInitiativeName = $ceInitiative.Name
    
    # Parse policy definitions and groups from the initiative
    $cePolicyDefinitions = @()
    try {
        if ($ceInitiative.PolicyDefinition -is [string]) {
            $cePolicyDefinitions = $ceInitiative.PolicyDefinition | ConvertFrom-Json
        } else {
            $cePolicyDefinitions = @($ceInitiative.PolicyDefinition)
        }
    } catch { }
    
    $ceGroupDefinitions = @()
    try {
        if ($ceInitiative.PolicyDefinitionGroup -is [string]) {
            $ceGroupDefinitions = $ceInitiative.PolicyDefinitionGroup | ConvertFrom-Json
        } else {
            $ceGroupDefinitions = @($ceInitiative.PolicyDefinitionGroup)
        }
    } catch { }
    
    # ═══════════════════════════════════════════════════════
    # TEST 2: Initiative is Assigned
    # ═══════════════════════════════════════════════════════
    $testNumber++
    Write-Host "   TEST $testNumber : CE Initiative is Assigned" -ForegroundColor White -NoNewline
    Write-Progress -Activity "CE Compliance Tests" -Status "Checking initiative assignments..." -PercentComplete 15 -Id 20
    
    $ceAssignments = @($PolicyAssignments | Where-Object {
        $_.policyDefinitionId -like "*$ceInitiativeName*"
    })
    
    if ($ceAssignments.Count -gt 0) {
        Write-Host " [PASS]" -ForegroundColor Green
        Write-Host "         Assigned at $($ceAssignments.Count) scope(s)" -ForegroundColor DarkGray
        foreach ($a in $ceAssignments) {
            $enfTag = if ($a.enforcementMode -eq 'DoNotEnforce') { " (DoNotEnforce)" } else { "" }
            Write-Host "         • $($a.displayName)$enfTag — $($a.scopeType)" -ForegroundColor DarkGray
        }
        if ($ceAssignments.Count -gt 1) {
            $enforcedCount = @($ceAssignments | Where-Object { $_.enforcementMode -ne 'DoNotEnforce' }).Count
            $auditOnlyCount = @($ceAssignments | Where-Object { $_.enforcementMode -eq 'DoNotEnforce' }).Count
            Write-Host ""
            Write-Host "         ℹ️  MULTI-ASSIGNMENT DETECTED: $($ceAssignments.Count) assignments found" -ForegroundColor Cyan
            Write-Host "            Enforced: $enforcedCount | Enforcement disabled (DoNotEnforce): $auditOnlyCount" -ForegroundColor Cyan
            Write-Host "            Compliance data will be deduplicated using strictest-state-wins per resource." -ForegroundColor DarkGray
            Write-Host "            This prevents double-counting when the same resource is evaluated by overlapping scopes." -ForegroundColor DarkGray
        }
        $passCount++
        $multiAssignmentDetail = if ($ceAssignments.Count -gt 1) { " — Multi-assignment: compliance deduplicated (strictest-state-wins)" } else { "" }
        Add-TestResult -TestId "T$testNumber" -ControlGroup "Prerequisites" -TestName "CE Initiative is Assigned" -Status "PASS" -Details "Assigned at $($ceAssignments.Count) scope(s)$multiAssignmentDetail"
    } else {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "         Initiative is not directly assigned. Will check individual policy coverage." -ForegroundColor Yellow
        $warnCount++
        Add-TestResult -TestId "T$testNumber" -ControlGroup "Prerequisites" -TestName "CE Initiative is Assigned" -Status "WARN" -Details "Not directly assigned — checking individual policy coverage"
    }
    
    # ═══════════════════════════════════════════════════════
    # TEST 3: Enforcement Mode
    # ═══════════════════════════════════════════════════════
    $testNumber++
    Write-Host "   TEST $testNumber : Enforcement Mode is Active" -ForegroundColor White -NoNewline
    
    if ($ceAssignments.Count -gt 0) {
        $doNotEnforceAssignments = @($ceAssignments | Where-Object { $_.enforcementMode -eq 'DoNotEnforce' })
        if ($doNotEnforceAssignments.Count -eq 0) {
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "         All assignments are in Default (enforced) mode" -ForegroundColor DarkGray
            $passCount++
            Add-TestResult -TestId "T$testNumber" -ControlGroup "Prerequisites" -TestName "Enforcement Mode is Active" -Status "PASS" -Details "All assignments enforced"
        } elseif ($doNotEnforceAssignments.Count -lt $ceAssignments.Count) {
            Write-Host " [WARN]" -ForegroundColor Yellow
            Write-Host "         $($doNotEnforceAssignments.Count)/$($ceAssignments.Count) assignments in DoNotEnforce mode" -ForegroundColor Yellow
            $warnCount++
            Add-TestResult -TestId "T$testNumber" -ControlGroup "Prerequisites" -TestName "Enforcement Mode is Active" -Status "WARN" -Details "$($doNotEnforceAssignments.Count)/$($ceAssignments.Count) in DoNotEnforce"
        } else {
            Write-Host " [FAIL]" -ForegroundColor Red
            Write-Host "         All assignments are in DoNotEnforce mode — policies are NOT actively protecting" -ForegroundColor Red
            $failCount++
            Add-TestResult -TestId "T$testNumber" -ControlGroup "Prerequisites" -TestName "Enforcement Mode is Active" -Status "FAIL" -Details "All assignments in DoNotEnforce"
        }
    } else {
        Write-Host " [SKIP]" -ForegroundColor DarkGray
        Write-Host "         No direct initiative assignment to check" -ForegroundColor DarkGray
        $skipCount++
        Add-TestResult -TestId "T$testNumber" -ControlGroup "Prerequisites" -TestName "Enforcement Mode is Active" -Status "SKIP" -Details "No direct initiative assignment"
    }
    
    # ═══════════════════════════════════════════════════════
    # TEST 4: Trigger Compliance Scan (optional)
    # ═══════════════════════════════════════════════════════
    $testNumber++
    Write-Host "   TEST $testNumber : Compliance Data Freshness" -ForegroundColor White -NoNewline
    
    if ($TriggerScan) {
        Write-Host "" # newline
        Write-Host "         Triggering on-demand compliance scan..." -ForegroundColor Cyan
        try {
            Start-AzPolicyComplianceScan -AsJob | Out-Null
            Write-Host "         Scan triggered (runs in background, may take minutes)." -ForegroundColor DarkGray
            Write-Host " [PASS]" -ForegroundColor Green
            $passCount++
            Add-TestResult -TestId "T$testNumber" -ControlGroup "Prerequisites" -TestName "Compliance Scan Triggered" -Status "PASS" -Details "On-demand scan triggered"
        } catch {
            Write-Host " [WARN]" -ForegroundColor Yellow
            Write-Host "         Could not trigger scan: $($_.Exception.Message)" -ForegroundColor Yellow
            $warnCount++
            Add-TestResult -TestId "T$testNumber" -ControlGroup "Prerequisites" -TestName "Compliance Scan Triggered" -Status "WARN" -Details "Scan failed: $($_.Exception.Message)"
        }
    } else {
        Write-Host " [SKIP]" -ForegroundColor DarkGray
        Write-Host "         Use -TriggerScan to force an on-demand compliance scan" -ForegroundColor DarkGray
        $skipCount++
        Add-TestResult -TestId "T$testNumber" -ControlGroup "Prerequisites" -TestName "Compliance Scan Triggered" -Status "SKIP" -Details "Not requested — use Invoke-CEPComplianceTests -TriggerScan"
    }
    
    # ═══════════════════════════════════════════════════════
    # TEST 5: Individual Policy Coverage
    # ═══════════════════════════════════════════════════════
    $testNumber++
    Write-Host "   TEST $testNumber : Individual Policy Coverage vs CE Initiative" -ForegroundColor White -NoNewline
    Write-Progress -Activity "CE Compliance Tests" -Status "Cross-referencing policy coverage..." -PercentComplete 20 -Id 20
    
    # Build lookup of CE policy definition GUIDs
    $ceDefGuids = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($policyRef in $cePolicyDefinitions) {
        $defId = if ($policyRef.policyDefinitionId) { $policyRef.policyDefinitionId } elseif ($policyRef.PolicyDefinitionId) { $policyRef.PolicyDefinitionId } else { $null }
        if ($defId) {
            $defGuid = if ($defId -match '/([^/]+)$') { $Matches[1].ToLower() } else { $defId.ToLower() }
            [void]$ceDefGuids.Add($defGuid)
        }
    }
    
    # Cross-reference all assigned policies
    $coveredGuids = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($assignment in $PolicyAssignments) {
        if ($assignment.policyType -eq 'Initiative') { continue }
        $assignedDefId = $assignment.policyDefinitionId
        if (-not $assignedDefId) { continue }
        $assignedGuid = if ($assignedDefId -match '/([^/]+)$') { $Matches[1].ToLower() } else { $assignedDefId.ToLower() }
        if ($ceDefGuids.Contains($assignedGuid)) {
            [void]$coveredGuids.Add($assignedGuid)
        }
    }
    # Also count initiative assignment as covering all its policies
    if ($ceAssignments.Count -gt 0) {
        foreach ($guid in $ceDefGuids) { [void]$coveredGuids.Add($guid) }
    }
    
    $coveragePct = if ($ceDefGuids.Count -gt 0) { [math]::Round(($coveredGuids.Count / $ceDefGuids.Count) * 100, 1) } else { 0 }
    $uncoveredCount = $ceDefGuids.Count - $coveredGuids.Count
    
    if ($coveragePct -ge 80) {
        Write-Host " [PASS]" -ForegroundColor Green
        $passCount++
        $status = "PASS"
    } elseif ($coveragePct -ge 50) {
        Write-Host " [WARN]" -ForegroundColor Yellow
        $warnCount++
        $status = "WARN"
    } else {
        Write-Host " [FAIL]" -ForegroundColor Red
        $failCount++
        $status = "FAIL"
    }
    Write-Host "         $($coveredGuids.Count)/$($ceDefGuids.Count) unique CE policies covered ($coveragePct%)" -ForegroundColor DarkGray
    if ($uncoveredCount -gt 0) {
        Write-Host "         $uncoveredCount policies not covered by any assignment" -ForegroundColor $(if ($coveragePct -lt 50) { 'Red' } else { 'Yellow' })
    }
    Add-TestResult -TestId "T$testNumber" -ControlGroup "Policy Coverage" -TestName "Individual Policy Coverage" -Status $status -Details "$($coveredGuids.Count)/$($ceDefGuids.Count) covered ($coveragePct%)" -Compliant $coveredGuids.Count -Total $ceDefGuids.Count
    
    # ═══════════════════════════════════════════════════════
    # TESTS 6+: Per-Control-Group Compliance Evaluation
    # ═══════════════════════════════════════════════════════
    Write-Host "`n   ─── Per-Control-Group Compliance Tests ───" -ForegroundColor Cyan
    
    # Resolve policy display names (reuse cache from -CEP if available)
    $allGuids = @($ceDefGuids) | Select-Object -Unique
    $policyDefDisplayNames = @{}
    if ($Script:CachedPolicyDisplayNames -and $Script:CachedPolicyDisplayNames.Count -gt 0) {
        # Reuse names already resolved by the main CE compliance section
        foreach ($key in $Script:CachedPolicyDisplayNames.Keys) {
            $policyDefDisplayNames[$key] = $Script:CachedPolicyDisplayNames[$key]
        }
        $missingGuids = @($allGuids | Where-Object { -not $policyDefDisplayNames.ContainsKey($_) })
        if ($missingGuids.Count -gt 0) {
            Write-Host "   Resolving $($missingGuids.Count) additional policy display names..." -ForegroundColor Gray
            $resolveCount = 0
            $resolveTotal = $missingGuids.Count
            foreach ($guid in $missingGuids) {
                $resolveCount++
                $resolvePct = [math]::Round(($resolveCount / [math]::Max($resolveTotal, 1)) * 100)
                Write-Progress -Activity "CE Compliance Tests" -Status "Resolving additional names ($resolveCount/$resolveTotal)..." -PercentComplete ([math]::Min(20 + ($resolvePct * 0.70), 90)) -Id 20
                try {
                    $policyDef = Get-AzPolicyDefinition -Name $guid -ErrorAction SilentlyContinue
                    if ($policyDef -and $policyDef.DisplayName) {
                        $policyDefDisplayNames[$guid] = $policyDef.DisplayName
                    }
                } catch { }
            }
            Write-Host "   ✓ Resolved $($missingGuids.Count) additional + $($Script:CachedPolicyDisplayNames.Count) cached display names" -ForegroundColor Green
        } else {
            Write-Host "   ✓ Reusing $($policyDefDisplayNames.Count)/$($allGuids.Count) cached display names (no API calls needed)" -ForegroundColor Green
        }
    } else {
        Write-Host "   Resolving policy display names..." -ForegroundColor Gray
        $resolveCount = 0
        $resolveTotal = $allGuids.Count
        foreach ($guid in $allGuids) {
            $resolveCount++
            $resolvePct = [math]::Round(($resolveCount / [math]::Max($resolveTotal, 1)) * 100)
            Write-Progress -Activity "CE Compliance Tests" -Status "Resolving policy names ($resolveCount/$resolveTotal)..." -PercentComplete ([math]::Min(20 + ($resolvePct * 0.70), 90)) -Id 20
            try {
                $policyDef = Get-AzPolicyDefinition -Name $guid -ErrorAction SilentlyContinue
                if ($policyDef -and $policyDef.DisplayName) {
                    $policyDefDisplayNames[$guid] = $policyDef.DisplayName
                }
            } catch { }
        }
        Write-Host "   ✓ Resolved $($policyDefDisplayNames.Count)/$($allGuids.Count) display names" -ForegroundColor Green
    }
    
    # Query compliance data
    $complianceByAssignment = @{}
    if ($ceAssignments.Count -gt 0) {
        Write-Progress -Activity "CE Compliance Tests" -Status "Querying initiative compliance data..." -PercentComplete 91 -Id 20
        if ($ceAssignments.Count -gt 1) {
            Write-Host "   Querying per-policy compliance across $($ceAssignments.Count) initiative assignments (deduplicating overlapping resources)..." -ForegroundColor Gray
        } else {
            Write-Host "   Querying per-policy compliance for initiative assignments..." -ForegroundColor Gray
        }
        $ceAssignmentIds = ($ceAssignments | Where-Object { $_.assignmentId } | ForEach-Object { "'$($_.assignmentId.ToLower())'" }) -join ', '
        
        if ($ceAssignmentIds) {
            $ceCompQuery = @"
policyresources
| where type == 'microsoft.policyinsights/policystates'
| extend assignmentId = tolower(tostring(properties.policyAssignmentId))
| where assignmentId in~ ($ceAssignmentIds)
| extend 
    policyDefinitionName = tostring(properties.policyDefinitionName),
    policyDefinitionReferenceId = tostring(properties.policyDefinitionReferenceId),
    complianceState = tostring(properties.complianceState),
    resourceId = tostring(properties.resourceId)
| extend stateRank = case(
    complianceState == 'NonCompliant', 1,
    complianceState == 'Unknown', 2,
    complianceState == 'Exempt', 3,
    complianceState == 'Compliant', 4,
    5)
| summarize arg_min(stateRank, complianceState) by resourceId, policyDefinitionName, policyDefinitionReferenceId
| summarize 
    TotalResources = dcount(resourceId),
    CompliantCount = dcountif(resourceId, complianceState == 'Compliant'),
    NonCompliantCount = dcountif(resourceId, complianceState == 'NonCompliant'),
    ExemptCount = dcountif(resourceId, complianceState == 'Exempt')
    by policyDefinitionName, policyDefinitionReferenceId
"@
            try {
                $compResults = @(Search-AzGraph -Query $ceCompQuery -First 1000 -UseTenantScope | Expand-AzGraphResult)
                foreach ($r in $compResults) {
                    $complianceByAssignment[$r.policyDefinitionReferenceId] = @{
                        DefName = $r.policyDefinitionName
                        NonCompliant = $r.NonCompliantCount
                        Compliant = $r.CompliantCount
                        Exempt = $r.ExemptCount
                        Total = $r.TotalResources
                    }
                }
                $dedupNote = if ($ceAssignments.Count -gt 1) { " (deduplicated across $($ceAssignments.Count) assignments)" } else { "" }
                Write-Host "   ✓ Compliance data for $($compResults.Count) policies$dedupNote" -ForegroundColor Green
            } catch {
                Write-Host "   ⚠️  Could not query compliance: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        # Per-assignment (per-scope) compliance breakdown — only when multiple assignments exist
        $perScopeCompliance = @{}
        if ($ceAssignments.Count -gt 1 -and $ceAssignmentIds) {
            Write-Host "   Querying per-scope compliance breakdown..." -ForegroundColor Gray
            $perScopeQuery = @"
policyresources
| where type == 'microsoft.policyinsights/policystates'
| extend assignmentId = tolower(tostring(properties.policyAssignmentId))
| where assignmentId in~ ($ceAssignmentIds)
| extend 
    complianceState = tostring(properties.complianceState),
    resourceId = tostring(properties.resourceId)
| extend stateRank = case(
    complianceState == 'NonCompliant', 1,
    complianceState == 'Unknown', 2,
    complianceState == 'Exempt', 3,
    complianceState == 'Compliant', 4,
    5)
| summarize arg_min(stateRank, complianceState) by resourceId, assignmentId
| summarize 
    TotalResources = dcount(resourceId),
    CompliantCount = dcountif(resourceId, complianceState == 'Compliant'),
    NonCompliantCount = dcountif(resourceId, complianceState == 'NonCompliant'),
    ExemptCount = dcountif(resourceId, complianceState == 'Exempt')
    by assignmentId
"@
            try {
                $perScopeResults = @(Search-AzGraph -Query $perScopeQuery -First 1000 -UseTenantScope | Expand-AzGraphResult)
                foreach ($psr in $perScopeResults) {
                    $perScopeCompliance[$psr.assignmentId] = @{
                        Total = $psr.TotalResources
                        Compliant = $psr.CompliantCount
                        NonCompliant = $psr.NonCompliantCount
                        Exempt = $psr.ExemptCount
                    }
                }
                Write-Host "   ✓ Per-scope compliance for $($perScopeResults.Count) assignments" -ForegroundColor Green
            } catch {
                Write-Host "   ⚠️  Could not query per-scope compliance: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        # Per-scope per-policy-reference compliance — for control group bars per scope
        $perScopeGroupRaw = @{}
        if ($ceAssignmentIds) {
            Write-Host "   Querying per-scope control group breakdown..." -ForegroundColor Gray
            $perScopeGroupQuery = @"
policyresources
| where type == 'microsoft.policyinsights/policystates'
| extend assignmentId = tolower(tostring(properties.policyAssignmentId))
| where assignmentId in~ ($ceAssignmentIds)
| extend 
    policyDefinitionReferenceId = tostring(properties.policyDefinitionReferenceId),
    complianceState = tostring(properties.complianceState),
    resourceId = tostring(properties.resourceId)
| summarize 
    TotalResources = dcount(resourceId),
    CompliantCount = dcountif(resourceId, complianceState == 'Compliant'),
    NonCompliantCount = dcountif(resourceId, complianceState == 'NonCompliant'),
    ExemptCount = dcountif(resourceId, complianceState == 'Exempt')
    by assignmentId, policyDefinitionReferenceId
"@
            try {
                $psgResults = @(Search-AzGraph -Query $perScopeGroupQuery -First 1000 -UseTenantScope | Expand-AzGraphResult)
                foreach ($psg in $psgResults) {
                    $aid = $psg.assignmentId
                    if (-not $perScopeGroupRaw.ContainsKey($aid)) { $perScopeGroupRaw[$aid] = @{} }
                    $perScopeGroupRaw[$aid][$psg.policyDefinitionReferenceId] = @{
                        Compliant    = [int]$psg.CompliantCount
                        NonCompliant = [int]$psg.NonCompliantCount
                        Exempt       = [int]$psg.ExemptCount
                        Total        = [int]$psg.TotalResources
                    }
                }
                Write-Host "   ✓ Per-scope control group data for $($perScopeGroupRaw.Count) assignments ($($psgResults.Count) policy records)" -ForegroundColor Green
            } catch {
                Write-Host "   ⚠️  Could not query per-scope control group breakdown: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        # Map policyDefinitionReferenceId → control group display name
        $refIdToGroupName = @{}
        foreach ($policyRef in $cePolicyDefinitions) {
            $refId = if ($policyRef.policyDefinitionReferenceId) { $policyRef.policyDefinitionReferenceId } elseif ($policyRef.PolicyDefinitionReferenceId) { $policyRef.PolicyDefinitionReferenceId } else { $null }
            $groups = if ($policyRef.groupNames) { @($policyRef.groupNames) } elseif ($policyRef.GroupNames) { @($policyRef.GroupNames) } else { @() }
            if ($refId -and $groups.Count -gt 0) {
                $refIdToGroupName[$refId] = $groups[0]
            }
        }
        # Resolve group internal names to display names
        $groupNameToDisplay = @{}
        foreach ($gDef in $ceGroupDefinitions) {
            $gN = if ($gDef.name) { $gDef.name } elseif ($gDef.Name) { $gDef.Name } else { '' }
            $gD = if ($Global:CEPGroupFriendlyNames -and $Global:CEPGroupFriendlyNames[$gN]) { $Global:CEPGroupFriendlyNames[$gN] } elseif ($gDef.displayName -and $gDef.displayName -ne $gN) { $gDef.displayName } else { $gN }
            if ($gN) { $groupNameToDisplay[$gN] = $gD }
        }

        # Aggregate per-assignment-per-group
        $perScopeGroupData = @{}
        foreach ($aid in $perScopeGroupRaw.Keys) {
            $perScopeGroupData[$aid] = @{}
            foreach ($refId in $perScopeGroupRaw[$aid].Keys) {
                $groupInternalName = $refIdToGroupName[$refId]
                if (-not $groupInternalName) { continue }
                $groupDisplay = if ($groupNameToDisplay[$groupInternalName]) { $groupNameToDisplay[$groupInternalName] } else { $groupInternalName }
                if (-not $perScopeGroupData[$aid].ContainsKey($groupDisplay)) {
                    $perScopeGroupData[$aid][$groupDisplay] = @{ Compliant = 0; NonCompliant = 0; Exempt = 0; Total = 0 }
                }
                $d = $perScopeGroupRaw[$aid][$refId]
                $perScopeGroupData[$aid][$groupDisplay].Compliant    += $d.Compliant
                $perScopeGroupData[$aid][$groupDisplay].NonCompliant += $d.NonCompliant
                $perScopeGroupData[$aid][$groupDisplay].Exempt       += $d.Exempt
                $perScopeGroupData[$aid][$groupDisplay].Total        += $d.Total
            }
        }

        # Build direct refId → display name mapping for HTML rendering
        $refIdToGroupDisplay = @{}
        foreach ($refId in $refIdToGroupName.Keys) {
            $internalName = $refIdToGroupName[$refId]
            $refIdToGroupDisplay[$refId] = if ($groupNameToDisplay[$internalName]) { $groupNameToDisplay[$internalName] } else { $internalName }
        }
    }
    
    # Also query compliance for individually matched assignments
    $individualCompData = @{}
    $matchedAssignments = @($PolicyAssignments | Where-Object {
        $_.policyType -ne 'Initiative' -and $_.assignmentId -and $_.policyDefinitionId
    } | Where-Object {
        $defGuid = if ($_.policyDefinitionId -match '/([^/]+)$') { $Matches[1].ToLower() } else { $null }
        $defGuid -and $ceDefGuids.Contains($defGuid)
    })
    
    if ($matchedAssignments.Count -gt 0 -and $ceAssignments.Count -eq 0) {
        Write-Progress -Activity "CE Compliance Tests" -Status "Querying individual assignment compliance..." -PercentComplete 92 -Id 20
        Write-Host "   Querying compliance for $($matchedAssignments.Count) individually matched assignments..." -ForegroundColor Gray
        $validAssignments = @($matchedAssignments | Where-Object { $_.assignmentId -and $_.assignmentId -ne '' })
        if ($validAssignments.Count -gt 0) {
            $matchedIds = ($validAssignments | ForEach-Object { 
                $aid = "$($_.assignmentId)".Trim().ToLower()
                if ($aid) { "'$aid'" }
            } | Where-Object { $_ }) -join ', '
            if (-not $matchedIds) {
                Write-Host "   ⚠️  No valid assignment IDs to query compliance for" -ForegroundColor Yellow
            } else {
            $indCompQuery = @"
policyresources
| where type == 'microsoft.policyinsights/policystates'
| extend assignmentId = tolower(tostring(properties.policyAssignmentId))
| where assignmentId in~ ($matchedIds)
| extend 
    complianceState = tostring(properties.complianceState),
    resourceId = tostring(properties.resourceId)
| extend stateRank = case(
    complianceState == 'NonCompliant', 1,
    complianceState == 'Unknown', 2,
    complianceState == 'Exempt', 3,
    complianceState == 'Compliant', 4,
    5)
| summarize arg_min(stateRank, complianceState) by resourceId, assignmentId
| summarize 
    TotalResources = dcount(resourceId),
    CompliantCount = dcountif(resourceId, complianceState == 'Compliant'),
    NonCompliantCount = dcountif(resourceId, complianceState == 'NonCompliant'),
    ExemptCount = dcountif(resourceId, complianceState == 'Exempt')
    by assignmentId
"@
            try {
                $indResults = @(Search-AzGraph -Query $indCompQuery -First 1000 -UseTenantScope | Expand-AzGraphResult)
                foreach ($r in $indResults) {
                    $individualCompData[$r.assignmentId] = @{
                        NonCompliant = $r.NonCompliantCount
                        Compliant = $r.CompliantCount
                        Exempt = $r.ExemptCount
                        Total = $r.TotalResources
                    }
                }
                Write-Host "   ✓ Compliance data for $($indResults.Count) individual assignments" -ForegroundColor Green
            } catch {
                Write-Host "   ⚠️  Could not query individual compliance: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            } # end else (matchedIds not empty)
        }
    }
    Write-Host ""
    
    # Run per-group tests
    $sortedGroups = $ceGroupDefinitions | Sort-Object { if ($_.name) { $_.name } else { $_.Name } }
    $groupIndex = 0
    $groupTotal = @($sortedGroups).Count
    
    foreach ($group in $sortedGroups) {
        $groupIndex++
        $groupPct = [math]::Round(($groupIndex / [math]::Max($groupTotal, 1)) * 100)
        Write-Progress -Activity "CE Compliance Tests" -Status "Evaluating control group $groupIndex/$groupTotal..." -PercentComplete ([math]::Min(93 + ($groupPct * 0.06), 99)) -Id 20
        $gName = if ($group.name) { $group.name } elseif ($group.Name) { $group.Name } else { '' }
        $gDisplayName = if ($Global:CEPGroupFriendlyNames[$gName]) { $Global:CEPGroupFriendlyNames[$gName] } elseif ($group.displayName -and $group.displayName -ne $gName) { $group.displayName } else { $gName }
        
        # Find policies in this group
        $groupPolicies = @()
        foreach ($policyRef in $cePolicyDefinitions) {
            $groups = if ($policyRef.groupNames) { @($policyRef.groupNames) } elseif ($policyRef.GroupNames) { @($policyRef.GroupNames) } else { @() }
            if ($groups -contains $gName) {
                $defId = if ($policyRef.policyDefinitionId) { $policyRef.policyDefinitionId } elseif ($policyRef.PolicyDefinitionId) { $policyRef.PolicyDefinitionId } else { $null }
                $refId = if ($policyRef.policyDefinitionReferenceId) { $policyRef.policyDefinitionReferenceId } elseif ($policyRef.PolicyDefinitionReferenceId) { $policyRef.PolicyDefinitionReferenceId } else { $null }
                if ($defId) {
                    $defGuid = if ($defId -match '/([^/]+)$') { $Matches[1].ToLower() } else { $defId.ToLower() }
                    $groupPolicies += @{ DefGuid = $defGuid; RefId = $refId }
                }
            }
        }
        
        if ($groupPolicies.Count -eq 0) { continue }
        
        $testNumber++
        Write-Host "   TEST $testNumber : $gDisplayName ($($groupPolicies.Count) policies)" -ForegroundColor White
        
        $groupPass = 0
        $groupFail = 0
        $groupWarn = 0
        $groupSkip = 0
        $groupNonCompliant = 0
        $groupCompliant = 0
        $groupTotal = 0
        
        foreach ($gp in $groupPolicies) {
            $displayName = if ($policyDefDisplayNames[$gp.DefGuid]) { $policyDefDisplayNames[$gp.DefGuid] } else { $gp.RefId }
            
            $isCovered = $coveredGuids.Contains($gp.DefGuid)
            
            # Get compliance data
            $compData = $null
            if ($complianceByAssignment.ContainsKey($gp.RefId)) {
                $compData = $complianceByAssignment[$gp.RefId]
            }
            
            # Determine test status for this policy
            if (-not $isCovered) {
                Write-Host "         ✗ $displayName" -ForegroundColor Red
                Write-Host "           NOT ASSIGNED — no coverage" -ForegroundColor DarkRed
                $groupFail++
            } elseif ($compData) {
                $groupCompliant += $compData.Compliant
                $groupNonCompliant += $compData.NonCompliant
                $groupTotal += $compData.Total
                if ($compData.NonCompliant -gt 0) {
                    Write-Host "         ⚠ $displayName" -ForegroundColor Yellow
                    Write-Host "           Non-Compliant: $($compData.NonCompliant) | Compliant: $($compData.Compliant)" -ForegroundColor DarkGray
                    $groupWarn++
                } else {
                    Write-Host "         ✓ $displayName" -ForegroundColor Green
                    Write-Host "           Compliant: $($compData.Compliant) resources" -ForegroundColor DarkGray
                    $groupPass++
                }
            } elseif ($isCovered) {
                Write-Host "         ― $displayName" -ForegroundColor DarkGray
                Write-Host "           Assigned but no compliance data yet" -ForegroundColor DarkGray
                $groupSkip++
            }
        }
        
        # Group-level verdict
        $groupVerdict = if ($groupFail -gt 0) { "FAIL" } elseif ($groupWarn -gt 0) { "WARN" } elseif ($groupSkip -eq $groupPolicies.Count) { "SKIP" } else { "PASS" }
        $verdictColor = switch ($groupVerdict) { "PASS" { "Green" } "FAIL" { "Red" } "WARN" { "Yellow" } "SKIP" { "DarkGray" } }
        
        Write-Host "         ─────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "         Result: [$groupVerdict] — ✓ $groupPass | ⚠ $groupWarn | ✗ $groupFail | ― $groupSkip" -ForegroundColor $verdictColor
        Write-Host ""
        
        switch ($groupVerdict) {
            "PASS" { $passCount++ }
            "FAIL" { $failCount++ }
            "WARN" { $warnCount++ }
            "SKIP" { $skipCount++ }
        }
        
        Add-TestResult -TestId "T$testNumber" -ControlGroup $gDisplayName -TestName "$gDisplayName Compliance" -Status $groupVerdict `
            -Details "$groupPass passed | $groupWarn warnings | $groupFail failed | $groupSkip skipped — $($groupPolicies.Count) policies evaluated" `
            -NonCompliant $groupNonCompliant -Compliant $groupCompliant -Total $groupTotal
    }

    $perScopeData = @()
    if ($perScopeCompliance.Count -gt 0 -and $ceAssignments.Count -gt 1) {
        foreach ($assignment in $ceAssignments) {
            $assignmentId = $assignment.assignmentId.ToLower()
            $scopeData = if ($perScopeCompliance.ContainsKey($assignmentId)) { $perScopeCompliance[$assignmentId] } else { $null }
            $perScopeData += [PSCustomObject]@{
                AssignmentId    = $assignmentId
                DisplayName     = $assignment.displayName
                ScopeType       = $assignment.scopeType
                EnforcementMode = $assignment.enforcementMode
                Total           = if ($scopeData) { [int]$scopeData.Total } else { 0 }
                Compliant       = if ($scopeData) { [int]$scopeData.Compliant } else { 0 }
                NonCompliant    = if ($scopeData) { [int]$scopeData.NonCompliant } else { 0 }
                Exempt          = if ($scopeData) { [int]$scopeData.Exempt } else { 0 }
                CompliancePct   = if ($scopeData -and [int]$scopeData.Total -gt 0) { [math]::Round(([int]$scopeData.Compliant / [int]$scopeData.Total) * 100, 1) } else { 0 }
            }
        }
    }

    $mappingState = if ($warnCount -gt 0 -or $skipCount -gt 0) { 'PartiallyEvaluated' } else { 'Evaluated' }
    $cepAssessment = New-CEPAssessment `
        -Requested $true `
        -State $mappingState `
        -MappingState Available `
        -TestState NotRequested `
        -MappingSourceState Available `
        -DefinitionId $(if ($ceInitiative.ResourceId) { $ceInitiative.ResourceId } elseif ($ceInitiative.Id) { $ceInitiative.Id } else { $ceInitiative.Name }) `
        -DefinitionVersion $sourceResolution.ConfiguredVersion `
        -DefinitionDisplayName $ceInitiative.DisplayName `
        -SelectionMethod $sourceResolution.SelectionMethod `
        -CandidateDefinitions $sourceResolution.Candidates

    return @{
        Assessment = $cepAssessment
        TestResults = $testResults
        NextTestNumber = $testNumber
        PerScopeData = $perScopeData
        PerScopeGroupData = if ($perScopeGroupData) { $perScopeGroupData } else { @{} }
        PerScopeGroupRaw = if ($perScopeGroupRaw) { $perScopeGroupRaw } else { @{} }
        RefIdToGroupDisplay = if ($refIdToGroupDisplay) { $refIdToGroupDisplay } else { @{} }
    }
}

function Invoke-CEPPlusTechnicalAssessment {
    param(
        [Parameter(Mandatory)][object[]]$PolicyAssignments,
        [int]$StartTestNumber = 0
    )

    $testResults = [System.Collections.ArrayList]@()
    $testNumber = $StartTestNumber
    $passCount = 0
    $failCount = 0
    $warnCount = 0
    $skipCount = 0
    $manualCount = 0

    function Add-TestResult {
        param(
            [string]$TestId,
            [string]$ControlGroup,
            [string]$TestName,
            [string]$Status,
            [string]$Details,
            [int]$NonCompliant = 0,
            [int]$Compliant = 0,
            [int]$Total = 0,
            [string]$EvidenceType = '',
            [string]$Source = '',
            [string]$Query = ''
        )
        [void]$testResults.Add([PSCustomObject]@{
            'Test #'          = $TestId
            'Control Group'   = $ControlGroup
            'Test Name'       = $TestName
            'Status'          = $Status
            'Details'         = $Details
            'Non-Compliant'   = $NonCompliant
            'Compliant'       = $Compliant
            'Total Resources' = $Total
            'Evidence Type'    = $EvidenceType
            'Source'           = $Source
            'Query'            = $Query
        })
    }
    
    # ═══════════════════════════════════════════════════════════════════════════════
    #  PHASE 2 — CE+ v3.2 TEST SPECIFICATION
    #  These tests map the official NCSC Cyber Essentials Plus v3.2 test
    #  specification to Azure Resource Graph queries where automatable, and flag
    #  manual/physical subtests for the assessor.
    #  Source: https://www.ncsc.gov.uk/files/cyber-essentials-plus-test-specification-v3-2.pdf
    #  Azure:  https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus
    # ═══════════════════════════════════════════════════════════════════════════════
    Write-Host "`n   ═══════════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "     PHASE 2 — CE+ v3.2 TEST SPECIFICATION" -ForegroundColor Magenta
    Write-Host "     Automated Azure checks + manual test checklist" -ForegroundColor White
    Write-Host "     Source: NCSC CE+ v3.2 Test Specification" -ForegroundColor DarkGray
    Write-Host "   ═══════════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""
    
    # ═══════════════════════════════════════════════════════
    # TC1: Remote Vulnerability Assessment (Test Case 1)
    # ═══════════════════════════════════════════════════════
    $testNumber++
    Write-Host "   ─── TC1: REMOTE VULNERABILITY ASSESSMENT ───" -ForegroundColor Cyan
    Write-Host "   TEST $testNumber : TC1 — Remote Vulnerability Assessment" -ForegroundColor White
    Write-Progress -Activity "CE+ v3.2 Tests" -Status "TC1: Remote Vulnerability Assessment..." -PercentComplete 5 -Id 21
    
    $tc1Pass = 0; $tc1Fail = 0; $tc1Warn = 0; $tc1Skip = 0; $tc1Manual = 0
    
    # --- TC1.1: Identify Public IP Addresses ---
    Write-Host "         1.1 Identify Public IP Addresses" -ForegroundColor White -NoNewline
    $tc11Status = 'WARN'; $tc11Details = 'The Azure Resource Graph query did not complete.'
    try {
        $publicIpQuery = @"
resources
| where type == 'microsoft.network/publicipaddresses'
| extend ipAddress = tostring(properties.ipAddress),
         allocationMethod = tostring(properties.publicIPAllocationMethod),
         associatedTo = tostring(properties.ipConfiguration.id)
| summarize TotalPublicIPs = count(),
            AssociatedIPs = countif(isnotempty(associatedTo)),
            UnassociatedIPs = countif(isempty(associatedTo))
"@
        $publicIpResults = @(Search-AzGraph -Query $publicIpQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
        if ($publicIpResults.Count -gt 0 -and $publicIpResults[0].TotalPublicIPs -gt 0) {
            $totalPubIps = $publicIpResults[0].TotalPublicIPs
            $unassociated = $publicIpResults[0].UnassociatedIPs
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "           Found $totalPubIps public IPs ($unassociated unassociated — review for necessity)" -ForegroundColor DarkGray
            if ($unassociated -gt 0) {
                Write-Host "           ⚠ Unassociated public IPs should be removed if not needed" -ForegroundColor Yellow
            }
            $tc11Status = 'PASS'; $tc11Details = "Found $totalPubIps public IP addresses; $unassociated are unassociated and require necessity review."
            $tc1Pass++
        } else {
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "           No public IP addresses found in the environment" -ForegroundColor DarkGray
            $tc11Status = 'PASS'; $tc11Details = 'No public IP addresses were returned by Azure Resource Graph.'
            $tc1Pass++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query public IPs: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc11Details = "Public IP query failed: $($_.Exception.Message)"
        $tc1Warn++
    }
    Add-TestResult -TestId 'TC1.1' -ControlGroup 'TC1: Vulnerability' -TestName 'Public IP Address Inventory' -Status $tc11Status -Details $tc11Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: resources/public IP addresses' -Query $publicIpQuery
    
    # --- TC1.2: Scan for open management ports from Internet ---
    Write-Host "         1.2 Evaluate Open Management Ports from Internet" -ForegroundColor White -NoNewline
    $tc12Status = 'WARN'; $tc12Details = 'The Azure Resource Graph query did not complete.'
    try {
        $nsgRulesQuery = @"
resources
| where type == 'microsoft.network/networksecuritygroups'
| mv-expand rules = properties.securityRules
| extend ruleName = tostring(rules.name),
         direction = tostring(rules.properties.direction),
         access = tostring(rules.properties.access),
         destPort = tostring(rules.properties.destinationPortRange),
         sourceAddr = tostring(rules.properties.sourceAddressPrefix),
         priority = toint(rules.properties.priority)
| where direction == 'Inbound' and access == 'Allow'
| where sourceAddr in ('*', 'Internet', '0.0.0.0/0', 'Any')
| where destPort in ('22', '3389', '445', '5985', '5986', '23') 
        or destPort == '*'
| summarize DangerousRules = count(),
            AffectedNSGs = dcount(id)
"@
        $nsgResults = @(Search-AzGraph -Query $nsgRulesQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
        if ($nsgResults.Count -gt 0 -and $nsgResults[0].DangerousRules -gt 0) {
            Write-Host " [FAIL]" -ForegroundColor Red
            Write-Host "           $($nsgResults[0].DangerousRules) NSG rules allow management ports (SSH/RDP/SMB/WinRM) from Internet" -ForegroundColor Red
            Write-Host "           Across $($nsgResults[0].AffectedNSGs) NSGs — these MUST be restricted" -ForegroundColor Red
            $tc12Status = 'FAIL'; $tc12Details = "$($nsgResults[0].DangerousRules) inbound NSG rules expose management ports across $($nsgResults[0].AffectedNSGs) NSGs."
            $tc1Fail++
        } else {
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "           No NSG rules expose management ports to the Internet" -ForegroundColor DarkGray
            $tc12Status = 'PASS'; $tc12Details = 'No inbound NSG rules exposing the evaluated management ports to the Internet were found.'
            $tc1Pass++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query NSG rules: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc12Details = "NSG rule query failed: $($_.Exception.Message)"
        $tc1Warn++
    }
    Add-TestResult -TestId 'TC1.2' -ControlGroup 'TC1: Vulnerability' -TestName 'Internet-Exposed Management Ports' -Status $tc12Status -Details $tc12Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: resources/network security groups' -Query $nsgRulesQuery
    
    # --- TC1.3: Evaluate high-risk vulnerabilities (Defender for Cloud) ---
    Write-Host "         1.3 Evaluate High-Risk Vulnerabilities (Defender)" -ForegroundColor White -NoNewline
    $tc13Status = 'WARN'; $tc13Details = 'The Azure Resource Graph query did not complete.'
    try {
        $vulnQuery = @"
securityresources
| where type == 'microsoft.security/assessments'
| extend severity = tostring(properties.metadata.severity),
     category = tostring(properties.metadata.categories[0]),
     statusCode = tostring(properties.status.code)
| summarize CoverageCount = count(),
        HighSevFindings = countif(statusCode == 'Unhealthy' and severity in ('High', 'Critical')),
        CriticalFindings = countif(statusCode == 'Unhealthy' and severity == 'Critical'),
        HighFindings = countif(statusCode == 'Unhealthy' and severity == 'High')
"@
        $vulnResults = @(Search-AzGraph -Query $vulnQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
    if ($vulnResults.Count -eq 0 -or $vulnResults[0].CoverageCount -eq 0) {
        Write-Host " [SKIP]" -ForegroundColor DarkYellow
        Write-Host "           No Defender for Cloud assessment coverage was returned" -ForegroundColor DarkYellow
        $tc13Status = 'SKIP'; $tc13Details = 'No Defender for Cloud assessments were available to establish vulnerability coverage.'
        $tc1Skip++
    } elseif ($vulnResults[0].HighSevFindings -gt 0) {
            $critical = $vulnResults[0].CriticalFindings
            $high = $vulnResults[0].HighFindings
            Write-Host " [FAIL]" -ForegroundColor Red
            Write-Host "           Critical: $critical | High: $high — unresolved Defender for Cloud findings" -ForegroundColor Red
            Write-Host "           All high/critical findings must be remediated for CE+ certification" -ForegroundColor DarkRed
            $tc13Status = 'FAIL'; $tc13Details = "$critical critical and $high high-severity unhealthy Defender for Cloud assessments were found."
            $tc1Fail++
        } else {
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "           No high or critical severity Defender for Cloud findings" -ForegroundColor DarkGray
            $tc13Status = 'PASS'; $tc13Details = 'No high or critical unhealthy Defender for Cloud assessments were returned.'
            $tc1Pass++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query security assessments: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc13Details = "Defender assessment query failed: $($_.Exception.Message)"
        $tc1Warn++
    }
    Add-TestResult -TestId 'TC1.3' -ControlGroup 'TC1: Vulnerability' -TestName 'High-Risk Defender Vulnerabilities' -Status $tc13Status -Details $tc13Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: securityresources/assessments' -Query $vulnQuery
    
    # --- TC1.4: Evaluate public/anonymous access on storage ---
    Write-Host "         1.4 Evaluate Public/Anonymous Storage Access" -ForegroundColor White -NoNewline
    $tc14Status = 'WARN'; $tc14Details = 'The Azure Resource Graph query did not complete.'
    try {
        $storageQuery = @"
resources
| where type == 'microsoft.storage/storageaccounts'
| extend allowBlobPublicAccess = tobool(properties.allowBlobPublicAccess),
         minTlsVersion = tostring(properties.minimumTlsVersion),
         httpsOnly = tobool(properties.supportsHttpsTrafficOnly)
| summarize TotalAccounts = count(),
            PublicAccessEnabled = countif(allowBlobPublicAccess == true),
            NotHttpsOnly = countif(httpsOnly == false),
            OldTls = countif(minTlsVersion != 'TLS1_2' and minTlsVersion != 'TLS1_3')
"@
        $storageResults = @(Search-AzGraph -Query $storageQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
        if ($storageResults.Count -gt 0) {
            $totalAccounts = [int]$storageResults[0].TotalAccounts
            $pubAccess = $storageResults[0].PublicAccessEnabled
            $noHttps = $storageResults[0].NotHttpsOnly
            $oldTls = $storageResults[0].OldTls
            $issues = $pubAccess + $noHttps + $oldTls
            if ($totalAccounts -eq 0) {
                Write-Host " [SKIP]" -ForegroundColor DarkYellow
                Write-Host "           No storage accounts in scope" -ForegroundColor DarkGray
                $tc14Status = 'SKIP'; $tc14Details = 'No storage accounts were found in scope; the configuration check is not applicable.'
                $tc1Skip++
            } elseif ($issues -gt 0) {
                Write-Host " [FAIL]" -ForegroundColor Red
                if ($pubAccess -gt 0) { Write-Host "           $pubAccess storage accounts allow public blob access" -ForegroundColor Red }
                if ($noHttps -gt 0) { Write-Host "           $noHttps storage accounts do not enforce HTTPS" -ForegroundColor Red }
                if ($oldTls -gt 0) { Write-Host "           $oldTls storage accounts use TLS version below 1.2" -ForegroundColor Red }
                $tc14Status = 'FAIL'; $tc14Details = "$pubAccess accounts allow public blob access; $noHttps do not enforce HTTPS; $oldTls use TLS below 1.2."
                $tc1Fail++
            } else {
                Write-Host " [PASS]" -ForegroundColor Green
                Write-Host "           All $totalAccounts storage accounts: no public access, HTTPS enforced, TLS 1.2+" -ForegroundColor DarkGray
                $tc14Status = 'PASS'; $tc14Details = "All $totalAccounts storage accounts disable public blob access, enforce HTTPS, and use TLS 1.2 or later."
                $tc1Pass++
            }
        } else {
            Write-Host " [SKIP]" -ForegroundColor DarkYellow
            Write-Host "           No storage accounts in scope" -ForegroundColor DarkGray
            $tc14Status = 'SKIP'; $tc14Details = 'No storage accounts were found in scope; the configuration check is not applicable.'
            $tc1Skip++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query storage accounts: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc14Details = "Storage configuration query failed: $($_.Exception.Message)"
        $tc1Warn++
    }
    Add-TestResult -TestId 'TC1.4' -ControlGroup 'TC1: Vulnerability' -TestName 'Public and Anonymous Storage Access' -Status $tc14Status -Details $tc14Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: resources/storage accounts' -Query $storageQuery
    
    # --- TC1.5: Evaluate authentication and account lockout (Manual) ---
    Write-Host "         1.5 Evaluate Account Lockout & Login Throttling" -ForegroundColor White -NoNewline
    Write-Host " [MANUAL]" -ForegroundColor DarkYellow
    Write-Host "           ☐ Verify account lockout policy is configured (Entra ID > Protection > Smart Lockout)" -ForegroundColor DarkGray
    Write-Host "           ☐ Verify login throttling is active on all internet-facing services" -ForegroundColor DarkGray
    Write-Host "           ☐ Confirm default/factory passwords have been changed on all devices" -ForegroundColor DarkGray
    $tc1Manual++
    $manualCount++
    Add-TestResult -TestId "TC1.5" -ControlGroup "TC1: Vulnerability" -TestName "Account Lockout & Login Throttling" -Status "MANUAL" -Details "Verify Smart Lockout, login throttling, default passwords changed"
    
    # --- TC1.6: Scan with approved vulnerability scanner (Manual) ---
    Write-Host "         1.6 External Vulnerability Scan with Approved Scanner" -ForegroundColor White -NoNewline
    Write-Host " [MANUAL]" -ForegroundColor DarkYellow
    Write-Host "           ☐ Resolve all dynamic DNS entries for the organisation" -ForegroundColor DarkGray
    Write-Host "           ☐ Scan all public IP ranges with a CE+ approved vulnerability scanner" -ForegroundColor DarkGray
    Write-Host "           ☐ Scan recommended TCP/UDP ports per NCSC guidance" -ForegroundColor DarkGray
    Write-Host "           ☐ Determine PASS/FAIL per individual service exposed" -ForegroundColor DarkGray
    $tc1Manual++
    $manualCount++
    Add-TestResult -TestId "TC1.6" -ControlGroup "TC1: Vulnerability" -TestName "External Vulnerability Scan with Approved Scanner" -Status "MANUAL" -Details "Scan all public IPs with CE+ approved scanner, check TCP/UDP ports"
    
    # TC1 Verdict
    $tc1Verdict = if ($tc1Fail -gt 0) { "FAIL" } elseif ($tc1Warn -gt 0 -or $tc1Skip -gt 0) { "WARN" } elseif ($tc1Manual -gt 0 -and $tc1Pass -eq 0) { "MANUAL" } else { "PASS" }
    $tc1VerdictColor = switch ($tc1Verdict) { "PASS" { "Green" } "FAIL" { "Red" } "WARN" { "Yellow" } "MANUAL" { "DarkYellow" } default { "DarkGray" } }
    Write-Host "         ─────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "         TC1 Result: [$tc1Verdict] — ✓ $tc1Pass | ✗ $tc1Fail | ⚠ $tc1Warn | ↷ $tc1Skip skipped | ✋ $tc1Manual manual" -ForegroundColor $tc1VerdictColor
    Write-Host ""
    switch ($tc1Verdict) { "PASS" { $passCount++ } "FAIL" { $failCount++ } "WARN" { $warnCount++ } "MANUAL" { $manualCount++ } }
    Add-TestResult -TestId "TC1" -ControlGroup "CE+ v3.2 Spec" -TestName "TC1: Remote Vulnerability Assessment" -Status $tc1Verdict `
        -Details "$tc1Pass passed | $tc1Fail failed | $tc1Warn warnings | $tc1Skip skipped | 🤚 $tc1Manual manual subtests"
    
    # ═══════════════════════════════════════════════════════
    # TC2: Patching / Authenticated Scan (Test Case 2)
    # ═══════════════════════════════════════════════════════
    $testNumber++
    Write-Host "   ─── TC2: PATCHING / AUTHENTICATED SCAN ───" -ForegroundColor Cyan
    Write-Host "   TEST $testNumber : TC2 — Patching & Authenticated Vulnerability Scan" -ForegroundColor White
    Write-Progress -Activity "CE+ v3.2 Tests" -Status "TC2: Patching / Authenticated Scan..." -PercentComplete 25 -Id 21
    
    $tc2Pass = 0; $tc2Fail = 0; $tc2Warn = 0; $tc2Skip = 0; $tc2Manual = 0
    
    # --- TC2.1: Check for missing critical/high patches (system updates) ---
    Write-Host "         2.1 Missing Critical/High Security Updates" -ForegroundColor White -NoNewline
    $tc21Status = 'WARN'; $tc21Details = 'The Azure Resource Graph query did not complete.'
    try {
        $patchQuery = @"
securityresources
| where type == 'microsoft.security/assessments'
| extend isPatchAssessment = properties.displayName has_any ('system updates', 'update', 'patch', 'missing'),
     statusCode = tostring(properties.status.code),
     severity = tostring(properties.metadata.severity)
| summarize CoverageCount = countif(isPatchAssessment),
        MissingPatches = countif(isPatchAssessment and statusCode == 'Unhealthy' and severity in ('High', 'Critical')),
        AffectedResources = dcountif(tostring(properties.resourceDetails.Id), isPatchAssessment and statusCode == 'Unhealthy' and severity in ('High', 'Critical'))
"@
        $patchResults = @(Search-AzGraph -Query $patchQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
    if ($patchResults.Count -eq 0 -or $patchResults[0].CoverageCount -eq 0) {
        Write-Host " [SKIP]" -ForegroundColor DarkYellow
        Write-Host "           No applicable Defender patch assessments were returned" -ForegroundColor DarkYellow
        $tc21Status = 'SKIP'; $tc21Details = 'No applicable Defender patch assessments were available to establish update coverage.'
        $tc2Skip++
    } elseif ($patchResults[0].MissingPatches -gt 0) {
            Write-Host " [FAIL]" -ForegroundColor Red
            Write-Host "           $($patchResults[0].MissingPatches) critical/high patch findings across $($patchResults[0].AffectedResources) resources" -ForegroundColor Red
            Write-Host "           CE+ requires critical/high patches applied within 14 days of vendor release" -ForegroundColor DarkRed
            $tc21Status = 'FAIL'; $tc21Details = "$($patchResults[0].MissingPatches) critical or high patch findings affect $($patchResults[0].AffectedResources) resources."
            $tc2Fail++
        } else {
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "           No missing critical/high security update findings in Defender for Cloud" -ForegroundColor DarkGray
            $tc21Status = 'PASS'; $tc21Details = 'No unhealthy critical or high patch assessments were returned by Defender for Cloud.'
            $tc2Pass++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query patch status: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc21Details = "Patch assessment query failed: $($_.Exception.Message)"
        $tc2Warn++
    }
    Add-TestResult -TestId 'TC2.1' -ControlGroup 'TC2: Patching' -TestName 'Missing Critical or High Security Updates' -Status $tc21Status -Details $tc21Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: securityresources/assessments' -Query $patchQuery
    
    # --- TC2.2: Check for CVSS >= 7.0 vulnerabilities ---
    Write-Host "         2.2 CVSS 7.0+ Vulnerabilities" -ForegroundColor White -NoNewline
    $tc22Status = 'WARN'; $tc22Details = 'The Azure Resource Graph query did not complete.'
    try {
        $cvssQuery = @"
securityresources
| where type == 'microsoft.security/assessments/subassessments'
| extend cvssScore = todouble(properties.additionalData.cvss.base),
         patchable = tobool(properties.status.cause == 'Patchable' or properties.remediation != ''),
         severity = tostring(properties.status.severity)
| summarize CoverageCount = countif(isnotnull(cvssScore)),
        TotalHighCvss = countif(cvssScore >= 7.0),
        PatchableCount = countif(cvssScore >= 7.0 and patchable == true),
        CriticalCvss = countif(cvssScore >= 9.0)
"@
        $cvssResults = @(Search-AzGraph -Query $cvssQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
    if ($cvssResults.Count -eq 0 -or $cvssResults[0].CoverageCount -eq 0) {
        Write-Host " [SKIP]" -ForegroundColor DarkYellow
        Write-Host "           No Defender CVSS sub-assessment coverage was returned" -ForegroundColor DarkYellow
        $tc22Status = 'SKIP'; $tc22Details = 'No Defender sub-assessments with CVSS data were available to establish vulnerability coverage.'
        $tc2Skip++
    } elseif ($cvssResults[0].TotalHighCvss -gt 0) {
            $totalCvss = $cvssResults[0].TotalHighCvss
            $patchable = $cvssResults[0].PatchableCount
            $critCvss = $cvssResults[0].CriticalCvss
            Write-Host " [FAIL]" -ForegroundColor Red
            Write-Host "           $totalCvss vulnerabilities with CVSS >= 7.0 (Critical >=9.0: $critCvss, Patchable: $patchable)" -ForegroundColor Red
            Write-Host "           FAIL if vendor fix available > 14 days ago" -ForegroundColor DarkRed
            $tc22Status = 'FAIL'; $tc22Details = "$totalCvss vulnerabilities have CVSS 7.0 or higher; $critCvss are critical and $patchable are marked patchable."
            $tc2Fail++
        } else {
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "           No CVSS 7.0+ vulnerabilities found in sub-assessments" -ForegroundColor DarkGray
            $tc22Status = 'PASS'; $tc22Details = 'No Defender sub-assessments with CVSS 7.0 or higher were returned.'
            $tc2Pass++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query CVSS data: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc22Details = "CVSS sub-assessment query failed: $($_.Exception.Message)"
        $tc2Warn++
    }
    Add-TestResult -TestId 'TC2.2' -ControlGroup 'TC2: Patching' -TestName 'CVSS 7.0 or Higher Vulnerabilities' -Status $tc22Status -Details $tc22Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: securityresources/subassessments' -Query $cvssQuery
    
    # --- TC2.3: Check for unsupported / end-of-life software ---
    Write-Host "         2.3 Unsupported / End-of-Life Software" -ForegroundColor White -NoNewline
    $tc23Status = 'WARN'; $tc23Details = 'The Azure Resource Graph query did not complete.'
    try {
        $eolQuery = @"
securityresources
| where type == 'microsoft.security/assessments'
| extend isEolAssessment = properties.displayName has_any ('end of life', 'end of support', 'unsupported', 'deprecated', 'eol', 'end-of-life'),
     statusCode = tostring(properties.status.code)
| summarize CoverageCount = countif(isEolAssessment),
        EolFindings = countif(isEolAssessment and statusCode == 'Unhealthy'),
        AffectedResources = dcountif(tostring(properties.resourceDetails.Id), isEolAssessment and statusCode == 'Unhealthy')
"@
        $eolResults = @(Search-AzGraph -Query $eolQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
    if ($eolResults.Count -eq 0 -or $eolResults[0].CoverageCount -eq 0) {
        Write-Host " [SKIP]" -ForegroundColor DarkYellow
        Write-Host "           No applicable Defender end-of-life assessments were returned" -ForegroundColor DarkYellow
        $tc23Status = 'SKIP'; $tc23Details = 'No applicable Defender end-of-life assessments were available to establish software support coverage.'
        $tc2Skip++
    } elseif ($eolResults[0].EolFindings -gt 0) {
            Write-Host " [FAIL]" -ForegroundColor Red
            Write-Host "           $($eolResults[0].EolFindings) findings for end-of-life/unsupported software across $($eolResults[0].AffectedResources) resources" -ForegroundColor Red
            Write-Host "           Unsupported software must be removed or isolated for CE+ compliance" -ForegroundColor DarkRed
            $tc23Status = 'FAIL'; $tc23Details = "$($eolResults[0].EolFindings) end-of-life or unsupported software findings affect $($eolResults[0].AffectedResources) resources."
            $tc2Fail++
        } else {
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "           No end-of-life or unsupported software findings" -ForegroundColor DarkGray
            $tc23Status = 'PASS'; $tc23Details = 'No unhealthy assessments matching unsupported or end-of-life software were returned.'
            $tc2Pass++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query end-of-life status: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc23Details = "End-of-life software query failed: $($_.Exception.Message)"
        $tc2Warn++
    }
    Add-TestResult -TestId 'TC2.3' -ControlGroup 'TC2: Patching' -TestName 'Unsupported or End-of-Life Software' -Status $tc23Status -Details $tc23Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: securityresources/assessments' -Query $eolQuery
    
    # --- TC2.4: Authenticated scan on sampled devices (Manual) ---
    Write-Host "         2.4 Authenticated Scan on Sampled Devices" -ForegroundColor White -NoNewline
    Write-Host " [MANUAL]" -ForegroundColor DarkYellow
    Write-Host "           ☐ Select a representative sample of devices from each device type" -ForegroundColor DarkGray
    Write-Host "           ☐ Run authenticated vulnerability scan with approved scanner" -ForegroundColor DarkGray
    Write-Host "           ☐ Extract critical/high vendor-rated and CVSS 7+ vulnerabilities" -ForegroundColor DarkGray
    Write-Host "           ☐ Check vendor fix release dates — FAIL if fix available > 14 days" -ForegroundColor DarkGray
    Write-Host "           ☐ Determine PASS/FAIL per sampled device" -ForegroundColor DarkGray
    $tc2Manual++
    $manualCount++
    Add-TestResult -TestId "TC2.4" -ControlGroup "TC2: Patching" -TestName "Authenticated Scan on Sampled Devices" -Status "MANUAL" -Details "Run authenticated vuln scan, check CVSS 7+ fixes within 14 days"
    
    # TC2 Verdict
    $tc2Verdict = if ($tc2Fail -gt 0) { "FAIL" } elseif ($tc2Warn -gt 0 -or $tc2Skip -gt 0) { "WARN" } elseif ($tc2Manual -gt 0 -and $tc2Pass -eq 0) { "MANUAL" } else { "PASS" }
    $tc2VerdictColor = switch ($tc2Verdict) { "PASS" { "Green" } "FAIL" { "Red" } "WARN" { "Yellow" } "MANUAL" { "DarkYellow" } default { "DarkGray" } }
    Write-Host "         ─────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "         TC2 Result: [$tc2Verdict] — ✓ $tc2Pass | ✗ $tc2Fail | ⚠ $tc2Warn | ↷ $tc2Skip skipped | ✋ $tc2Manual manual" -ForegroundColor $tc2VerdictColor
    Write-Host ""
    switch ($tc2Verdict) { "PASS" { $passCount++ } "FAIL" { $failCount++ } "WARN" { $warnCount++ } "MANUAL" { $manualCount++ } }
    Add-TestResult -TestId "TC2" -ControlGroup "CE+ v3.2 Spec" -TestName "TC2: Patching / Authenticated Scan" -Status $tc2Verdict `
        -Details "$tc2Pass passed | $tc2Fail failed | $tc2Warn warnings | $tc2Skip skipped | 🤚 $tc2Manual manual subtests"
    
    # ═══════════════════════════════════════════════════════
    # TC3: Malware Protection (Test Case 3)
    # ═══════════════════════════════════════════════════════
    $testNumber++
    Write-Host "   ─── TC3: MALWARE PROTECTION ───" -ForegroundColor Cyan
    Write-Host "   TEST $testNumber : TC3 — Malware Protection" -ForegroundColor White
    Write-Progress -Activity "CE+ v3.2 Tests" -Status "TC3: Malware Protection..." -PercentComplete 45 -Id 21
    
    $tc3Pass = 0; $tc3Fail = 0; $tc3Warn = 0; $tc3Manual = 0
    
    # --- TC3.1: Verify endpoint protection is installed and running ---
    Write-Host "         3.1 Endpoint Protection Installed & Running" -ForegroundColor White -NoNewline
    $tc31Status = 'WARN'; $tc31Details = 'The Azure Resource Graph query did not complete.'
    try {
        $epQuery = @"
securityresources
| where type == 'microsoft.security/assessments'
| where properties.displayName has_any ('endpoint protection', 'antimalware', 'anti-malware', 'Defender for Endpoint', 'endpoint agent')
| extend statusCode = tostring(properties.status.code)
| summarize TotalAssessments = count(),
            Healthy = countif(statusCode == 'Healthy'),
            Unhealthy = countif(statusCode == 'Unhealthy'),
            NotApplicable = countif(statusCode == 'NotApplicable')
"@
        $epResults = @(Search-AzGraph -Query $epQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
        if ($epResults.Count -gt 0 -and $epResults[0].TotalAssessments -gt 0) {
            $unhealthy = $epResults[0].Unhealthy
            $healthy = $epResults[0].Healthy
            if ($unhealthy -gt 0) {
                Write-Host " [FAIL]" -ForegroundColor Red
                Write-Host "           $unhealthy endpoint protection findings unhealthy ($healthy healthy)" -ForegroundColor Red
                Write-Host "           All machines must have anti-malware installed and active" -ForegroundColor DarkRed
                $tc31Status = 'FAIL'; $tc31Details = "$unhealthy endpoint protection assessments are unhealthy; $healthy are healthy."
                $tc3Fail++
            } else {
                Write-Host " [PASS]" -ForegroundColor Green
                Write-Host "           All $healthy endpoint protection assessments are healthy" -ForegroundColor DarkGray
                $tc31Status = 'PASS'; $tc31Details = "All $healthy returned endpoint protection assessments are healthy."
                $tc3Pass++
            }
        } else {
            Write-Host " [WARN]" -ForegroundColor Yellow
            Write-Host "           No endpoint protection assessments found — ensure Defender for Cloud is enabled" -ForegroundColor Yellow
            $tc31Details = 'No endpoint protection assessments were returned; Defender for Cloud coverage must be verified.'
            $tc3Warn++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query endpoint protection: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc31Details = "Endpoint protection query failed: $($_.Exception.Message)"
        $tc3Warn++
    }
    Add-TestResult -TestId 'TC3.1' -ControlGroup 'TC3: Malware' -TestName 'Endpoint Protection Installed and Running' -Status $tc31Status -Details $tc31Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: securityresources/assessments' -Query $epQuery
    
    # --- TC3.2: Check Microsoft Defender for Servers is enabled ---
    Write-Host "         3.2 Defender for Servers / Cloud Workload Protection" -ForegroundColor White -NoNewline
    $tc32Status = 'WARN'; $tc32Details = 'The Azure Resource Graph query did not complete.'
    try {
        $defenderQuery = @"
securityresources
| where type == 'microsoft.security/pricings'
| extend pricingTier = tostring(properties.pricingTier),
         subPlan = tostring(properties.subPlan),
         resourceName = name
| where resourceName in ('VirtualMachines', 'SqlServers', 'AppServices', 'StorageAccounts', 'KeyVaults', 'Arm', 'Containers')
| summarize TotalPlans = count(),
            EnabledPlans = countif(pricingTier == 'Standard'),
            FreePlans = countif(pricingTier == 'Free')
"@
        $defenderResults = @(Search-AzGraph -Query $defenderQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
        if ($defenderResults.Count -gt 0 -and $defenderResults[0].TotalPlans -gt 0) {
            $enabled = $defenderResults[0].EnabledPlans
            $free = $defenderResults[0].FreePlans
            $total = $defenderResults[0].TotalPlans
            if ($free -gt 0) {
                Write-Host " [WARN]" -ForegroundColor Yellow
                Write-Host "           $enabled/$total Defender plans enabled, $free on Free tier (limited protection)" -ForegroundColor Yellow
                $tc32Details = "$enabled of $total Defender plans use the Standard tier; $free remain on the Free tier."
                $tc3Warn++
            } else {
                Write-Host " [PASS]" -ForegroundColor Green
                Write-Host "           All $enabled/$total Defender for Cloud plans enabled (Standard)" -ForegroundColor DarkGray
                $tc32Status = 'PASS'; $tc32Details = "All $enabled returned Defender for Cloud plans use the Standard tier."
                $tc3Pass++
            }
        } else {
            Write-Host " [WARN]" -ForegroundColor Yellow
            Write-Host "           Could not determine Defender for Cloud pricing tier" -ForegroundColor Yellow
            $tc32Details = 'No applicable Defender for Cloud pricing records were returned.'
            $tc3Warn++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query Defender plans: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc32Details = "Defender plan query failed: $($_.Exception.Message)"
        $tc3Warn++
    }
    Add-TestResult -TestId 'TC3.2' -ControlGroup 'TC3: Malware' -TestName 'Defender for Cloud Workload Protection' -Status $tc32Status -Details $tc32Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: securityresources/pricings' -Query $defenderQuery
    
    # --- TC3.3: Anti-malware signature currency ---
    Write-Host "         3.3 Anti-Malware Signature Currency" -ForegroundColor White -NoNewline
    $tc33Status = 'WARN'; $tc33Details = 'The Azure Resource Graph query did not complete.'
    try {
        $sigQuery = @"
securityresources
| where type == 'microsoft.security/assessments'
| where properties.displayName has_any ('antimalware signatures', 'definition update', 'signature', 'protection update')
| extend statusCode = tostring(properties.status.code)
| summarize TotalChecks = count(),
            OutOfDate = countif(statusCode == 'Unhealthy')
"@
        $sigResults = @(Search-AzGraph -Query $sigQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
        if ($sigResults.Count -gt 0 -and $sigResults[0].OutOfDate -gt 0) {
            Write-Host " [FAIL]" -ForegroundColor Red
            Write-Host "           $($sigResults[0].OutOfDate) machines have out-of-date anti-malware signatures" -ForegroundColor Red
            $tc33Status = 'FAIL'; $tc33Details = "$($sigResults[0].OutOfDate) anti-malware signature assessments are unhealthy."
            $tc3Fail++
        } elseif ($sigResults.Count -gt 0 -and $sigResults[0].TotalChecks -gt 0) {
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "           All anti-malware signatures are up to date" -ForegroundColor DarkGray
            $tc33Status = 'PASS'; $tc33Details = "All $($sigResults[0].TotalChecks) returned anti-malware signature assessments are healthy."
            $tc3Pass++
        } else {
            Write-Host " [SKIP]" -ForegroundColor DarkGray
            Write-Host "           No anti-malware signature assessments found" -ForegroundColor DarkGray
            $tc33Status = 'SKIP'; $tc33Details = 'No anti-malware signature assessments were returned.'
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query signature status: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc33Details = "Anti-malware signature query failed: $($_.Exception.Message)"
        $tc3Warn++
    }
    Add-TestResult -TestId 'TC3.3' -ControlGroup 'TC3: Malware' -TestName 'Anti-Malware Signature Currency' -Status $tc33Status -Details $tc33Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: securityresources/assessments' -Query $sigQuery
    
    # --- TC3.4: Email malware test (Manual) ---
    Write-Host "         3.4 Email Malware Test (Subtest 3.1.1)" -ForegroundColor White -NoNewline
    Write-Host " [MANUAL]" -ForegroundColor DarkYellow
    Write-Host "           ☐ Send a baseline test email to verify delivery" -ForegroundColor DarkGray
    Write-Host "           ☐ Send test emails with EICAR/standard test files attached" -ForegroundColor DarkGray
    Write-Host "           ☐ Observe delivery — FAIL if malware file is accessible to user" -ForegroundColor DarkGray
    Write-Host "           ☐ FAIL if executable attachment runs without prompt/block" -ForegroundColor DarkGray
    $tc3Manual++
    $manualCount++
    Add-TestResult -TestId "TC3.4" -ControlGroup "TC3: Malware" -TestName "Email Malware Test (Subtest 3.1.1)" -Status "MANUAL" -Details "Send EICAR test emails, verify malware attachment is blocked"
    
    # --- TC3.5: Browser/download malware test (Manual) ---
    Write-Host "         3.5 Browser/Download Malware Test (Subtest 3.1.2)" -ForegroundColor White -NoNewline
    Write-Host " [MANUAL]" -ForegroundColor DarkYellow
    Write-Host "           ☐ Verify internet access from sampled device" -ForegroundColor DarkGray
    Write-Host "           ☐ Attempt download of EICAR/standard test files via browser" -ForegroundColor DarkGray
    Write-Host "           ☐ FAIL if malware test file downloads and opens successfully" -ForegroundColor DarkGray
    Write-Host "           ☐ FAIL if downloaded executable runs without prompt/block" -ForegroundColor DarkGray
    $tc3Manual++
    $manualCount++
    Add-TestResult -TestId "TC3.5" -ControlGroup "TC3: Malware" -TestName "Browser/Download Malware Test (Subtest 3.1.2)" -Status "MANUAL" -Details "Download EICAR test files via browser, verify blocked"
    
    # --- TC3.6: Application allowlisting / code-signing (Manual) ---
    Write-Host "         3.6 Application Allowlisting / Code Signing (Subtest 3.2)" -ForegroundColor White -NoNewline
    Write-Host " [MANUAL]" -ForegroundColor DarkYellow
    Write-Host "           ☐ Verify trusted root certificates — no unapproved CAs installed" -ForegroundColor DarkGray
    Write-Host "           ☐ Verify unsigned executables are blocked from running" -ForegroundColor DarkGray
    Write-Host "           ☐ Verify executables signed by untrusted certificates are blocked" -ForegroundColor DarkGray
    Write-Host "           ☐ Verify code-signing policy is enforced (AppLocker/WDAC)" -ForegroundColor DarkGray
    $tc3Manual++
    $manualCount++
    Add-TestResult -TestId "TC3.6" -ControlGroup "TC3: Malware" -TestName "Application Allowlisting / Code Signing (Subtest 3.2)" -Status "MANUAL" -Details "Verify unsigned/untrusted executables blocked, AppLocker/WDAC enforced"
    
    # TC3 Verdict
    $tc3Verdict = if ($tc3Fail -gt 0) { "FAIL" } elseif ($tc3Warn -gt 0) { "WARN" } elseif ($tc3Manual -gt 0 -and $tc3Pass -eq 0) { "MANUAL" } else { "PASS" }
    $tc3VerdictColor = switch ($tc3Verdict) { "PASS" { "Green" } "FAIL" { "Red" } "WARN" { "Yellow" } "MANUAL" { "DarkYellow" } default { "DarkGray" } }
    Write-Host "         ─────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "         TC3 Result: [$tc3Verdict] — ✓ $tc3Pass | ✗ $tc3Fail | ⚠ $tc3Warn | ✋ $tc3Manual manual" -ForegroundColor $tc3VerdictColor
    Write-Host ""
    switch ($tc3Verdict) { "PASS" { $passCount++ } "FAIL" { $failCount++ } "WARN" { $warnCount++ } "MANUAL" { $manualCount++ } }
    Add-TestResult -TestId "TC3" -ControlGroup "CE+ v3.2 Spec" -TestName "TC3: Malware Protection" -Status $tc3Verdict `
        -Details "$tc3Pass passed | $tc3Fail failed | $tc3Warn warnings | 🤚 $tc3Manual manual subtests"
    
    # ═══════════════════════════════════════════════════════
    # TC4: MFA Configuration (Test Case 4)
    # ═══════════════════════════════════════════════════════
    $testNumber++
    Write-Host "   ─── TC4: MFA CONFIGURATION ───" -ForegroundColor Cyan
    Write-Host "   TEST $testNumber : TC4 — Multi-Factor Authentication Configuration" -ForegroundColor White
    Write-Progress -Activity "CE+ v3.2 Tests" -Status "TC4: MFA Configuration..." -PercentComplete 65 -Id 21
    
    $tc4Pass = 0; $tc4Fail = 0; $tc4Warn = 0; $tc4Manual = 0
    
    # --- TC4.1: MFA enforcement via Azure Policy compliance ---
    Write-Host "         4.1 MFA Enforcement Policies" -ForegroundColor White -NoNewline
    $tc41Status = 'WARN'; $tc41Details = 'The Azure Resource Graph query did not complete.'
    try {
        $mfaQuery = @"
securityresources
| where type == 'microsoft.security/assessments'
| where properties.displayName has_any ('MFA', 'multi-factor', 'multifactor')
| extend statusCode = tostring(properties.status.code),
         displayName = tostring(properties.displayName)
| summarize TotalMfaChecks = count(),
            MfaHealthy = countif(statusCode == 'Healthy'),
            MfaUnhealthy = countif(statusCode == 'Unhealthy')
"@
        $mfaResults = @(Search-AzGraph -Query $mfaQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
        if ($mfaResults.Count -gt 0 -and $mfaResults[0].TotalMfaChecks -gt 0) {
            $mfaUnhealthy = $mfaResults[0].MfaUnhealthy
            $mfaHealthy = $mfaResults[0].MfaHealthy
            if ($mfaUnhealthy -gt 0) {
                Write-Host " [FAIL]" -ForegroundColor Red
                Write-Host "           $mfaUnhealthy MFA-related Defender assessments are unhealthy ($mfaHealthy healthy)" -ForegroundColor Red
                Write-Host "           MFA must be enforced for all users accessing cloud services" -ForegroundColor DarkRed
                $tc41Status = 'FAIL'; $tc41Details = "$mfaUnhealthy MFA-related assessments are unhealthy; $mfaHealthy are healthy."
                $tc4Fail++
            } else {
                Write-Host " [PASS]" -ForegroundColor Green
                Write-Host "           All $mfaHealthy MFA-related Defender assessments are healthy" -ForegroundColor DarkGray
                $tc41Status = 'PASS'; $tc41Details = "All $mfaHealthy returned MFA-related assessments are healthy."
                $tc4Pass++
            }
        } else {
            Write-Host " [WARN]" -ForegroundColor Yellow
            Write-Host "           No MFA-related security assessments found — ensure MFA policies are configured" -ForegroundColor Yellow
            $tc41Details = 'No MFA-related security assessments were returned; MFA configuration must be verified.'
            $tc4Warn++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query MFA assessments: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc41Details = "MFA assessment query failed: $($_.Exception.Message)"
        $tc4Warn++
    }
    Add-TestResult -TestId 'TC4.1' -ControlGroup 'TC4: MFA' -TestName 'MFA Security Assessments' -Status $tc41Status -Details $tc41Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: securityresources/assessments' -Query $mfaQuery
    
    # --- TC4.2: Check for Conditional Access policies enforcing MFA ---
    Write-Host "         4.2 Conditional Access MFA Policies" -ForegroundColor White -NoNewline
    $tc42Status = 'WARN'; $tc42Details = 'The assignment inventory filter did not complete.'
    $mfaPolicyQuery = "PolicyAssignments | Where-Object { displayName or policyDefinitionId matches 'MFA|multi.factor|multifactor|conditional.access' }"
    try {
        # Check if MFA-related policies are assigned (from the policy assignments data)
        $mfaPolicies = @($PolicyAssignments | Where-Object {
            $_.displayName -match 'MFA|multi.factor|multifactor|conditional.access' -or
            $_.policyDefinitionId -match 'MFA|multi.factor|multifactor'
        })
        if ($mfaPolicies.Count -gt 0) {
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "           $($mfaPolicies.Count) MFA / Conditional Access policy assignments found" -ForegroundColor DarkGray
            foreach ($mp in $mfaPolicies | Select-Object -First 3) {
                Write-Host "           • $($mp.displayName)" -ForegroundColor DarkGray
            }
            if ($mfaPolicies.Count -gt 3) { Write-Host "           • ... and $($mfaPolicies.Count - 3) more" -ForegroundColor DarkGray }
            $tc42Status = 'PASS'; $tc42Details = "$($mfaPolicies.Count) MFA or Conditional Access policy assignments were found in the collected inventory."
            $tc4Pass++
        } else {
            Write-Host " [WARN]" -ForegroundColor Yellow
            Write-Host "           No MFA-related policy assignments detected in current scope" -ForegroundColor Yellow
            Write-Host "           Verify Conditional Access policies in Entra ID > Protection > Conditional Access" -ForegroundColor DarkGray
            $tc42Details = 'No MFA-related policy assignments were detected in the collected Azure Policy inventory; Entra Conditional Access requires separate verification.'
            $tc4Warn++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not check MFA policies: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc42Details = "MFA assignment inventory filter failed: $($_.Exception.Message)"
        $tc4Warn++
    }
    Add-TestResult -TestId 'TC4.2' -ControlGroup 'TC4: MFA' -TestName 'Conditional Access and MFA Policy Inventory' -Status $tc42Status -Details $tc42Details -EvidenceType 'Automated' -Source 'Collected Azure Policy assignment inventory; Entra Conditional Access is not queried' -Query $mfaPolicyQuery
    
    # --- TC4.3: Interactive MFA verification (Manual) ---
    Write-Host "         4.3 Interactive MFA Verification" -ForegroundColor White -NoNewline
    Write-Host " [MANUAL]" -ForegroundColor DarkYellow
    Write-Host "           ☐ Attempt cloud login as a standard user from untrusted device/incognito" -ForegroundColor DarkGray
    Write-Host "           ☐ Attempt cloud login as an admin user from untrusted device/incognito" -ForegroundColor DarkGray
    Write-Host "           ☐ Verify MFA prompt appears BEFORE access is granted" -ForegroundColor DarkGray
    Write-Host "           ☐ Confirm MFA is required, not optional, for all cloud services" -ForegroundColor DarkGray
    $tc4Manual++
    $manualCount++
    Add-TestResult -TestId "TC4.3" -ControlGroup "TC4: MFA" -TestName "Interactive MFA Verification" -Status "MANUAL" -Details "Test MFA prompt for standard and admin users from untrusted device"
    
    # TC4 Verdict
    $tc4Verdict = if ($tc4Fail -gt 0) { "FAIL" } elseif ($tc4Warn -gt 0) { "WARN" } elseif ($tc4Manual -gt 0 -and $tc4Pass -eq 0) { "MANUAL" } else { "PASS" }
    $tc4VerdictColor = switch ($tc4Verdict) { "PASS" { "Green" } "FAIL" { "Red" } "WARN" { "Yellow" } "MANUAL" { "DarkYellow" } default { "DarkGray" } }
    Write-Host "         ─────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "         TC4 Result: [$tc4Verdict] — ✓ $tc4Pass | ✗ $tc4Fail | ⚠ $tc4Warn | ✋ $tc4Manual manual" -ForegroundColor $tc4VerdictColor
    Write-Host ""
    switch ($tc4Verdict) { "PASS" { $passCount++ } "FAIL" { $failCount++ } "WARN" { $warnCount++ } "MANUAL" { $manualCount++ } }
    Add-TestResult -TestId "TC4" -ControlGroup "CE+ v3.2 Spec" -TestName "TC4: MFA Configuration" -Status $tc4Verdict `
        -Details "$tc4Pass passed | $tc4Fail failed | $tc4Warn warnings | 🤚 $tc4Manual manual subtests"
    
    # ═══════════════════════════════════════════════════════
    # TC5: Account Separation (Test Case 5)
    # ═══════════════════════════════════════════════════════
    $testNumber++
    Write-Host "   ─── TC5: ACCOUNT SEPARATION ───" -ForegroundColor Cyan
    Write-Host "   TEST $testNumber : TC5 — Account Separation (Admin vs Standard User)" -ForegroundColor White
    Write-Progress -Activity "CE+ v3.2 Tests" -Status "TC5: Account Separation..." -PercentComplete 85 -Id 21
    
    $tc5Pass = 0; $tc5Fail = 0; $tc5Warn = 0; $tc5Manual = 0
    
    # --- TC5.1: Check for excessive Owner/Contributor role assignments ---
    Write-Host "         5.1 Excessive Privileged Role Assignments" -ForegroundColor White -NoNewline
    $tc51Status = 'WARN'; $tc51Details = 'The Azure Resource Graph query did not complete.'
    try {
        $rbacQuery = @"
authorizationresources
| where type == 'microsoft.authorization/roleassignments'
| extend roleDefinitionId = tostring(properties.roleDefinitionId),
         principalType = tostring(properties.principalType),
         scope = tostring(properties.scope)
| where roleDefinitionId has_any (
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
    'b24988ac-6180-42a0-ab88-20f7382dd24c',
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
  )
| summarize TotalPrivileged = count(),
            Owners = countif(roleDefinitionId has '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'),
            Contributors = countif(roleDefinitionId has 'b24988ac-6180-42a0-ab88-20f7382dd24c'),
            UserAccessAdmins = countif(roleDefinitionId has '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'),
            UserPrincipals = countif(principalType == 'User'),
            ServicePrincipals = countif(principalType == 'ServicePrincipal'),
            GroupPrincipals = countif(principalType == 'Group')
"@
        $rbacResults = @(Search-AzGraph -Query $rbacQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
        if ($rbacResults.Count -gt 0 -and $rbacResults[0].TotalPrivileged -gt 0) {
            $owners = $rbacResults[0].Owners
            $contributors = $rbacResults[0].Contributors
            $uaa = $rbacResults[0].UserAccessAdmins
            $userPrincipals = $rbacResults[0].UserPrincipals
            Write-Host "" # newline for multi-line output
            Write-Host "           Owner: $owners | Contributor: $contributors | User Access Admin: $uaa" -ForegroundColor DarkGray
            Write-Host "           User principals with privileged roles: $userPrincipals" -ForegroundColor DarkGray
            # Flag as WARN if many user principals have Owner
            if ($owners -gt 5) {
                Write-Host "         [WARN]" -ForegroundColor Yellow
                Write-Host "           High number of Owner role assignments ($owners) — review for least-privilege" -ForegroundColor Yellow
                $tc51Details = "$owners Owner assignments exceed the review threshold of 5; $contributors Contributor and $uaa User Access Administrator assignments were also found."
                $tc5Warn++
            } else {
                Write-Host "         [PASS]" -ForegroundColor Green
                Write-Host "           Privileged role counts appear reasonable" -ForegroundColor DarkGray
                $tc51Status = 'PASS'; $tc51Details = "$owners Owner, $contributors Contributor, and $uaa User Access Administrator assignments were found; Owner count does not exceed 5."
                $tc5Pass++
            }
        } else {
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "           No Owner/Contributor/User Access Admin role assignments found" -ForegroundColor DarkGray
            $tc51Status = 'PASS'; $tc51Details = 'No Owner, Contributor, or User Access Administrator assignments were returned.'
            $tc5Pass++
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query RBAC assignments: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc51Details = "Privileged role assignment query failed: $($_.Exception.Message)"
        $tc5Warn++
    }
    Add-TestResult -TestId 'TC5.1' -ControlGroup 'TC5: Accounts' -TestName 'Privileged Role Assignment Review' -Status $tc51Status -Details $tc51Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: authorizationresources/role assignments' -Query $rbacQuery
    
    # --- TC5.2: Check Defender recommendation for admin account controls ---
    Write-Host "         5.2 Admin Account Security Recommendations" -ForegroundColor White -NoNewline
    $tc52Status = 'WARN'; $tc52Details = 'The Azure Resource Graph query did not complete.'
    try {
        $adminQuery = @"
securityresources
| where type == 'microsoft.security/assessments'
| where properties.displayName has_any ('admin', 'owner', 'privileged', 'least privilege', 'role assignment', 'excessive permissions')
| extend statusCode = tostring(properties.status.code)
| summarize TotalAdminChecks = count(),
            Unhealthy = countif(statusCode == 'Unhealthy'),
            Healthy = countif(statusCode == 'Healthy')
"@
        $adminResults = @(Search-AzGraph -Query $adminQuery -First 1 -UseTenantScope | Expand-AzGraphResult)
        if ($adminResults.Count -gt 0 -and $adminResults[0].Unhealthy -gt 0) {
            Write-Host " [WARN]" -ForegroundColor Yellow
            Write-Host "           $($adminResults[0].Unhealthy) admin/privilege-related Defender findings need attention" -ForegroundColor Yellow
            $tc52Details = "$($adminResults[0].Unhealthy) admin or privilege-related Defender assessments are unhealthy."
            $tc5Warn++
        } elseif ($adminResults.Count -gt 0 -and $adminResults[0].TotalAdminChecks -gt 0) {
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "           All $($adminResults[0].Healthy) admin/privilege assessments are healthy" -ForegroundColor DarkGray
            $tc52Status = 'PASS'; $tc52Details = "All $($adminResults[0].Healthy) returned admin or privilege-related assessments are healthy."
            $tc5Pass++
        } else {
            Write-Host " [SKIP]" -ForegroundColor DarkGray
            Write-Host "           No admin-related security assessments found" -ForegroundColor DarkGray
            $tc52Status = 'SKIP'; $tc52Details = 'No admin or privilege-related Defender assessments were returned.'
        }
    } catch {
        Write-Host " [WARN]" -ForegroundColor Yellow
        Write-Host "           Could not query admin assessments: $($_.Exception.Message)" -ForegroundColor Yellow
        $tc52Details = "Admin security assessment query failed: $($_.Exception.Message)"
        $tc5Warn++
    }
    Add-TestResult -TestId 'TC5.2' -ControlGroup 'TC5: Accounts' -TestName 'Admin Account Security Recommendations' -Status $tc52Status -Details $tc52Details -EvidenceType 'Automated' -Source 'Azure Resource Graph: securityresources/assessments' -Query $adminQuery
    
    # --- TC5.3: Interactive admin/standard user separation (Manual) ---
    Write-Host "         5.3 Interactive Account Separation Test" -ForegroundColor White -NoNewline
    Write-Host " [MANUAL]" -ForegroundColor DarkYellow
    Write-Host "           ☐ Log in with a standard (non-admin) user account" -ForegroundColor DarkGray
    Write-Host "           ☐ Attempt to run an administrative process or install software" -ForegroundColor DarkGray
    Write-Host "           ☐ Verify an admin credential prompt is required (UAC or equivalent)" -ForegroundColor DarkGray
    Write-Host "           ☐ Verify the process does NOT run under the standard user's privileges" -ForegroundColor DarkGray
    Write-Host "           ☐ Confirm admin and standard accounts are separate identities" -ForegroundColor DarkGray
    $tc5Manual++
    $manualCount++
    Add-TestResult -TestId "TC5.3" -ControlGroup "TC5: Accounts" -TestName "Interactive Account Separation Test" -Status "MANUAL" -Details "Verify standard user cannot run admin processes without credential prompt"
    
    # TC5 Verdict
    $tc5Verdict = if ($tc5Fail -gt 0) { "FAIL" } elseif ($tc5Warn -gt 0) { "WARN" } elseif ($tc5Manual -gt 0 -and $tc5Pass -eq 0) { "MANUAL" } else { "PASS" }
    $tc5VerdictColor = switch ($tc5Verdict) { "PASS" { "Green" } "FAIL" { "Red" } "WARN" { "Yellow" } "MANUAL" { "DarkYellow" } default { "DarkGray" } }
    Write-Host "         ─────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "         TC5 Result: [$tc5Verdict] — ✓ $tc5Pass | ✗ $tc5Fail | ⚠ $tc5Warn | ✋ $tc5Manual manual" -ForegroundColor $tc5VerdictColor
    Write-Host ""
    switch ($tc5Verdict) { "PASS" { $passCount++ } "FAIL" { $failCount++ } "WARN" { $warnCount++ } "MANUAL" { $manualCount++ } }
    Add-TestResult -TestId "TC5" -ControlGroup "CE+ v3.2 Spec" -TestName "TC5: Account Separation" -Status $tc5Verdict `
        -Details "$tc5Pass passed | $tc5Fail failed | $tc5Warn warnings | 🤚 $tc5Manual manual subtests"
    
    Write-Progress -Activity "CE+ v3.2 Tests" -Status "Complete" -PercentComplete 100 -Id 21
    Write-Progress -Activity "CE+ v3.2 Tests" -Completed -Id 21
    
    Write-Progress -Activity "CE Compliance Tests" -Status "Complete" -PercentComplete 100 -Id 20
    Write-Progress -Activity "CE Compliance Tests" -Completed -Id 20

    $technicalStatuses = @($testResults | ForEach-Object { $_.Status })
    $technicalState = if ('FAIL' -in $technicalStatuses -or 'WARN' -in $technicalStatuses -or 'SKIP' -in $technicalStatuses -or 'MANUAL' -in $technicalStatuses) { 'PartiallyEvaluated' } else { 'Evaluated' }

    return @{
        Assessment = New-CEPAssessment -Requested $true -State $technicalState -MappingState NotRequested -TestState $technicalState
        TestResults = $testResults
        NextTestNumber = $testNumber
    }
}

function Invoke-CEPComplianceTests {
    param(
        [Parameter(Mandatory)][object[]]$PolicyAssignments,
        [switch]$TriggerScan,
        [switch]$ExportResults,
        [string]$DefinitionId = '',
        [ValidateNotNullOrEmpty()][string]$DefinitionVersion = '3.1'
    )

    $initiativeResult = Invoke-CEPInitiativeAssessment -PolicyAssignments $PolicyAssignments -TriggerScan:$TriggerScan -ExportResults:$ExportResults -DefinitionId $DefinitionId -DefinitionVersion $DefinitionVersion
    $technicalResult = Invoke-CEPPlusTechnicalAssessment -PolicyAssignments $PolicyAssignments -StartTestNumber $initiativeResult.NextTestNumber

    $combinedResults = [System.Collections.ArrayList]@()
    foreach ($result in @($initiativeResult.TestResults) + @($technicalResult.TestResults)) {
        [void]$combinedResults.Add($result)
    }

    $technicalStatuses = @($technicalResult.TestResults | ForEach-Object { $_.Status })
    $technicalState = if ('FAIL' -in $technicalStatuses -or 'WARN' -in $technicalStatuses -or 'SKIP' -in $technicalStatuses -or 'MANUAL' -in $technicalStatuses) { 'PartiallyEvaluated' } else { 'Evaluated' }
    $mappingUnavailable = $initiativeResult.Assessment.MappingState -ne 'Available'
    $assessmentState = if ($initiativeResult.Assessment.State -eq 'EvaluationFailed') { 'EvaluationFailed' } elseif ($mappingUnavailable) { 'PrerequisiteUnavailable' } elseif ($initiativeResult.Assessment.State -eq 'PartiallyEvaluated' -or $technicalState -eq 'PartiallyEvaluated') { 'PartiallyEvaluated' } else { 'Evaluated' }

    $scoreResult = Get-CEPScore -TestResults $technicalResult.TestResults -MeasurementBlocked:$mappingUnavailable

    $assessment = New-CEPAssessment `
        -Requested $true `
        -State $assessmentState `
        -MappingState $(if ($mappingUnavailable) { 'Unavailable' } else { $initiativeResult.Assessment.MappingState }) `
        -TestState $technicalState `
        -ScoreState $scoreResult.ScoreState `
        -Score $scoreResult.Score `
        -PrerequisiteReason $initiativeResult.Assessment.PrerequisiteReason `
        -MappingSourceState $initiativeResult.Assessment.MappingSourceState `
        -DefinitionId $initiativeResult.Assessment.DefinitionId `
        -DefinitionVersion $initiativeResult.Assessment.DefinitionVersion `
        -DefinitionDisplayName $initiativeResult.Assessment.DefinitionDisplayName `
        -SelectionMethod $initiativeResult.Assessment.SelectionMethod `
        -CandidateDefinitions $initiativeResult.Assessment.CandidateDefinitions `
        -DataQuality ([PSCustomObject][ordered]@{
            State = if ($mappingUnavailable -or $technicalState -eq 'PartiallyEvaluated') { 'Partial' } else { 'Complete' }
            EvidenceCount = $combinedResults.Count
            Limitations = @(
                if ($mappingUnavailable) { $initiativeResult.Assessment.PrerequisiteReason }
                if ('SKIP' -in $technicalStatuses) { 'One or more technical checks lacked query evidence.' }
                if ('MANUAL' -in $technicalStatuses) { 'One or more controls require manual verification.' }
            )
        })

    return @{
        Assessment = $assessment
        TestResults = $combinedResults
        PerScopeData = $initiativeResult.PerScopeData
        PerScopeGroupData = $initiativeResult.PerScopeGroupData
        PerScopeGroupRaw = $initiativeResult.PerScopeGroupRaw
        RefIdToGroupDisplay = $initiativeResult.RefIdToGroupDisplay
    }
}

#endregion CE/CE+ Test Functions

Write-Host "`nInitializing Azure Resource Graph queries..." -ForegroundColor Cyan

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
    Write-Host "✓ Az.ResourceGraph module loaded successfully (Version: $($argModule.Version))" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to load Az.ResourceGraph module: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

Write-Host "" # Blank line

# Create list to store results (List<T> for O(1) append vs array += O(n) copy)
$results = [System.Collections.Generic.List[object]]::new()

Write-Host "`nQuerying Azure Resource Graph for policy assignments..." -ForegroundColor Cyan
Write-Host "(Using Azure Resource Graph for optimal performance)" -ForegroundColor DarkGray
Write-Host "" # Blank line

# Build ARG query — always includes MG + Subscriptions + Resource Groups
# Apply optional filters for specific MG or Subscription
$scopeFilter = ""
if ($ManagementGroup) {
    # Filter to a specific management group (and its children)
    $mgFilter = $ManagementGroup -replace "'", "''"
    $scopeFilter = "| where properties.scope contains '/managementGroups/$mgFilter'"
    Write-Host "Scope: Filtered to Management Group '$ManagementGroup' (incl. children)" -ForegroundColor Gray
} elseif ($Subscription) {
    # Filter to a specific subscription
    $subFilter = $Subscription -replace "'", "''"
    $scopeFilter = "| where properties.scope contains '/subscriptions/$subFilter'"
    Write-Host "Scope: Filtered to Subscription '$Subscription'" -ForegroundColor Gray
} else {
    Write-Host "Scope: All (Management Groups, Subscriptions, and Resource Groups)" -ForegroundColor Gray
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
    definitionVersion = tostring(properties.definitionVersion),
    scope = properties.scope,
    scopeType,
    enforcementMode,
    parameters = properties.parameters,
    notScopes = properties.notScopes,
    resourceSelectors = properties.resourceSelectors,
    overrides = properties.overrides,
    createdOn = coalesce(tostring(properties.metadata.createdOn), tostring(properties.createdOn), ''),
    identityType = tostring(identity.type),
    identityPrincipalId = tostring(identity.principalId),
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
        $allArgResults = [System.Collections.Generic.List[object]]::new(1024)
        $allArgResults.AddRange(@($argResults))
        $skipToken = $argResults.SkipToken
        $pageCount = 1
        
        while ($skipToken) {
            $pageCount++
            Write-Progress -Activity "Querying Azure Resource Graph" -Status "Retrieving page $pageCount (total: $($allArgResults.Count) assignments)..." -PercentComplete ([math]::Min(25 + ($pageCount * 10), 90)) -Id 10
            $moreResults = Search-AzGraph -Query $policyQuery -First 1000 -SkipToken $skipToken -UseTenantScope
            $allArgResults.AddRange(@($moreResults))
            $skipToken = $moreResults.SkipToken
            Write-Host "  Retrieved $($allArgResults.Count) assignments..." -ForegroundColor Gray
        }
        $argResults = $allArgResults.ToArray()
    }
    
    Write-Progress -Activity "Querying Azure Resource Graph" -Status "Completed" -PercentComplete 100 -Id 10
    Write-Progress -Activity "Querying Azure Resource Graph" -Completed -Id 10
    Write-Host "  ✓ Found $($argResults.Count) policy assignments" -ForegroundColor Green
    Write-Host "" # Blank line
} catch {
    Write-Progress -Activity "Querying Azure Resource Graph" -Completed -Id 10
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
| extend policyAssignmentId = tolower(tostring(properties.policyAssignmentId))
| summarize 
    TotalResources = dcount(tostring(properties.resourceId)),
    CompliantResources = dcountif(tostring(properties.resourceId), properties.complianceState =~ 'Compliant'),
    NonCompliantResources = dcountif(tostring(properties.resourceId), properties.complianceState =~ 'NonCompliant'),
    NonCompliantPolicyDefs = dcountif(tostring(properties.policyDefinitionId), properties.complianceState =~ 'NonCompliant'),
    LastEvaluation = max(todatetime(properties.timestamp))
    by policyAssignmentId
"@

$complianceData = @{}
$complianceQuerySucceeded = $false
$complianceQueryError = ''
$complianceQueryTimestamp = [datetime]::UtcNow
$complianceQueryRecordCount = 0
try {
    Write-Progress -Activity "Querying Compliance Data" -Status "Retrieving non-compliant resources..." -PercentComplete 0 -Id 11
    
    $complianceResults = Search-AzGraph -Query $complianceQuery -First 1000 -UseTenantScope
    $complianceQuerySucceeded = $true
    
    if ($complianceResults) {
        # Handle pagination if needed
        if ($complianceResults.Count -eq 1000) {
            $allComplianceResults = [System.Collections.Generic.List[object]]::new(1024)
            $allComplianceResults.AddRange(@($complianceResults))
            $skipToken = $complianceResults.SkipToken
            $pageCount = 1
            
            while ($skipToken) {
                $pageCount++
                Write-Progress -Activity "Querying Compliance Data" -Status "Retrieving page $pageCount..." -PercentComplete ([math]::Min(25 + ($pageCount * 10), 70)) -Id 11
                $moreResults = Search-AzGraph -Query $complianceQuery -First 1000 -SkipToken $skipToken -UseTenantScope
                $allComplianceResults.AddRange(@($moreResults))
                $skipToken = $moreResults.SkipToken
            }
            $complianceResults = $allComplianceResults.ToArray()
        }
        $complianceQueryRecordCount = @($complianceResults).Count
        
        Write-Progress -Activity "Querying Compliance Data" -Status "Processing results..." -PercentComplete 75 -Id 11
        
        # Build lookup dictionary
        foreach ($item in $complianceResults) {
            $complianceData[$item.policyAssignmentId] = @{
                ComplianceState = (Resolve-ComplianceAssessmentState `
                    -QuerySucceeded $true `
                    -QueryRecordCount 1 `
                    -EvaluatedResources $item.TotalResources `
                    -CompliantResources $item.CompliantResources `
                    -NonCompliantResources $item.NonCompliantResources `
                    -Timestamp $complianceQueryTimestamp).State
                CompliantResources = $item.CompliantResources
                NonCompliantResources = $item.NonCompliantResources
                NonCompliantPolicyDefs = $item.NonCompliantPolicyDefs
                TotalResources = $item.TotalResources
                ApplicableResources = $item.TotalResources
                LastEvaluation = if ($item.LastEvaluation) { ([datetime]$item.LastEvaluation).ToUniversalTime().ToString('o') } else { '' }
            }
        }
        Write-Progress -Activity "Querying Compliance Data" -Completed -Id 11
        $noComplianceCount = $argResults.Count - $complianceData.Count
        Write-Host "  ✓ Retrieved compliance data for $($complianceData.Count) of $($argResults.Count) assignments" -ForegroundColor Green
        if ($noComplianceCount -gt 0) {
            Write-Host "    ($noComplianceCount assignments have no evaluated resources — shown as Not evaluated)" -ForegroundColor Yellow
        }
    } else {
        Write-Progress -Activity "Querying Compliance Data" -Completed -Id 11
        Write-Host "  Not evaluated: 0 of $($argResults.Count) assignments have policy state data" -ForegroundColor Yellow
    }
} catch {
    $complianceQueryError = $_.Exception.Message
    Write-Progress -Activity "Querying Compliance Data" -Completed -Id 11
    Write-Host "  Warning: Could not retrieve compliance data: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Continuing without compliance information..." -ForegroundColor Gray
}

$totalEvaluatedResources = ($complianceData.Values | Measure-Object -Property TotalResources -Sum).Sum
$totalCompliantResources = ($complianceData.Values | Measure-Object -Property CompliantResources -Sum).Sum
$totalNonCompliantEvaluations = ($complianceData.Values | Measure-Object -Property NonCompliantResources -Sum).Sum
$complianceAssessment = Resolve-ComplianceAssessmentState `
    -QuerySucceeded $complianceQuerySucceeded `
    -QueryRecordCount $complianceQueryRecordCount `
    -EvaluatedResources $totalEvaluatedResources `
    -CompliantResources $totalCompliantResources `
    -NonCompliantResources $totalNonCompliantEvaluations `
    -Timestamp $complianceQueryTimestamp `
    -ErrorMessage $complianceQueryError
$dataQuality = $complianceAssessment.DataQuality
$dataQuality | Add-Member -NotePropertyName AssessmentState -NotePropertyValue $complianceAssessment.State
$dataQuality | Add-Member -NotePropertyName EvaluatedResources -NotePropertyValue $complianceAssessment.EvaluatedResources
$dataQuality | Add-Member -NotePropertyName CompliantResources -NotePropertyValue $complianceAssessment.CompliantResources
$dataQuality | Add-Member -NotePropertyName NonCompliantResources -NotePropertyValue $complianceAssessment.NonCompliantResources

Write-Host "" # Blank line

# ═══════════════════════════════════════════════════════════════════════════
# POLICY EXEMPTIONS — query all exemptions across all scopes
# ═══════════════════════════════════════════════════════════════════════════
Write-Host "Querying policy exemptions from Azure Resource Graph..." -ForegroundColor Cyan

# Build exemption-specific scope filter (exemptions don't have properties.scope; scope is derived from id)
$exemptionScopeFilter = ""
if ($ManagementGroup) {
    $exemptionScopeFilter = "| where tolower(id) contains '/managementgroups/$($mgFilter.ToLower())'"
} elseif ($Subscription) {
    $exemptionScopeFilter = "| where tolower(id) contains '/subscriptions/$($subFilter.ToLower())'"
}

$exemptionQuery = @"
policyresources
| where type == 'microsoft.authorization/policyexemptions'
$exemptionScopeFilter
| extend
    lowerid            = tolower(id),
    exemptionName      = name,
    displayName        = coalesce(tostring(properties.displayName), name),
    description        = tostring(properties.description),
    exemptionCategory  = tostring(properties.exemptionCategory),
    policyAssignmentId = tolower(tostring(properties.policyAssignmentId)),
    policyDefRefIds    = properties.policyDefinitionReferenceIds,
    expiresOn          = tostring(properties.expiresOn),
    createdOn          = coalesce(tostring(properties.metadata.createdOn), tostring(properties.createdOn), '')
| extend
    scope = substring(id, 0, indexof(lowerid, '/providers/microsoft.authorization/policyexemptions/'))
| extend
    scopeType = case(
        scope contains 'resourceGroups' and scope contains 'providers/', 'Resource',
        scope contains 'resourceGroups', 'Resource Group',
        scope contains '/subscriptions/' and scope !contains 'resourceGroups', 'Subscription',
        'Management Group'
    )
| project
    exemptionId        = id,
    exemptionName,
    displayName,
    description,
    exemptionCategory,
    policyAssignmentId,
    policyDefRefIds,
    expiresOn,
    createdOn,
    scope,
    scopeType,
    subscriptionId
| order by scopeType asc, exemptionName asc
"@

$exemptionData = [System.Collections.Generic.List[object]]::new()
$exemptionLookup = @{}  # keyed by policyAssignmentId (lowercase) → array of exemptions
try {
    Write-Progress -Activity "Querying Policy Exemptions" -Status "Retrieving exemptions..." -PercentComplete 0 -Id 14

    $exemptionResults = Search-AzGraph -Query $exemptionQuery -First 1000 -UseTenantScope

    if ($exemptionResults -and $exemptionResults.Count -gt 0) {
        # Handle pagination
        if ($exemptionResults.Count -eq 1000) {
            $allExemptionResults = [System.Collections.Generic.List[object]]::new(1024)
            $allExemptionResults.AddRange(@($exemptionResults))
            $skipToken = $exemptionResults.SkipToken
            $pageCount = 1
            while ($skipToken) {
                $pageCount++
                Write-Progress -Activity "Querying Policy Exemptions" -Status "Retrieving page $pageCount..." -PercentComplete ([math]::Min(25 + ($pageCount * 10), 90)) -Id 14
                $moreResults = Search-AzGraph -Query $exemptionQuery -First 1000 -SkipToken $skipToken -UseTenantScope
                $allExemptionResults.AddRange(@($moreResults))
                $skipToken = $moreResults.SkipToken
            }
            $exemptionResults = $allExemptionResults.ToArray()
        }

        # Process exemption results
        foreach ($ex in $exemptionResults) {
            # Determine if expired
            $isExpired = $false
            $expiryDate = $null
            if ($ex.expiresOn) {
                try {
                    $expiryDate = [datetime]$ex.expiresOn
                    $isExpired = $expiryDate -lt (Get-Date)
                } catch { }
            }

            # Resolve scope name
            $exScopeName = 'Unknown'
            if ($ex.scopeType -eq 'Management Group' -and $ex.scope -match '/managementGroups/([^/]+)$') {
                $exMgId = $Matches[1]
                $exScopeName = if ($mgLookup -and $mgLookup[$exMgId]) { $mgLookup[$exMgId] } else { $exMgId }
            } elseif ($ex.scopeType -eq 'Subscription' -and $ex.scope -match '/subscriptions/([^/]+)$') {
                $exSubId = $Matches[1]
                try { $exSub = Get-AzSubscription -SubscriptionId $exSubId -ErrorAction SilentlyContinue; $exScopeName = if ($exSub) { $exSub.Name } else { $exSubId } } catch { $exScopeName = $exSubId }
            } elseif ($ex.scopeType -eq 'Resource Group' -and $ex.scope -match '/resourceGroups/([^/]+)') {
                $exScopeName = $Matches[1]
            } elseif ($ex.scopeType -eq 'Resource' -and $ex.scope -match '/([^/]+)$') {
                $exScopeName = $Matches[1]
            }

            # Resolve assignment name from assignment ID
            $assignmentName = if ($ex.policyAssignmentId -match '/([^/]+)$') { $Matches[1] } else { $ex.policyAssignmentId }

            # Count policy definition reference IDs (for initiative partial exemptions)
            $refIdCount = 0
            if ($ex.policyDefRefIds -and $ex.policyDefRefIds.Count -gt 0) {
                $refIdCount = $ex.policyDefRefIds.Count
            }

            $exObj = [PSCustomObject]@{
                'Exemption Name'        = $ex.exemptionName
                'Display Name'          = $ex.displayName
                'Description'           = $ex.description
                'Category'              = $ex.exemptionCategory   # Waiver or Mitigated
                'Policy Assignment'     = $assignmentName
                'Policy Assignment ID'  = $ex.policyAssignmentId
                'Scope Type'            = $ex.scopeType
                'Scope Name'            = $exScopeName
                'Scope'                 = $ex.scope
                'Expires On'            = if ($expiryDate) { $expiryDate.ToString('yyyy-MM-dd') } else { 'Never' }
                'Is Expired'            = $isExpired
                'Created On'            = $ex.createdOn
                'Partial Exemption'     = ($refIdCount -gt 0)
                'Exempted Policies'     = $refIdCount
                'Exemption ID'          = $ex.exemptionId
            }
            [void]$exemptionData.Add($exObj)

            # Build lookup by assignment ID
            $aIdLower = $ex.policyAssignmentId
            if (-not $exemptionLookup.ContainsKey($aIdLower)) {
                $exemptionLookup[$aIdLower] = @()
            }
            $exemptionLookup[$aIdLower] += $exObj
        }

        Write-Progress -Activity "Querying Policy Exemptions" -Completed -Id 14
        $activeCount = @($exemptionData | Where-Object { -not $_.'Is Expired' }).Count
        $expiredCount = @($exemptionData | Where-Object { $_.'Is Expired' }).Count
        $waiverCount = @($exemptionData | Where-Object { $_.'Category' -eq 'Waiver' }).Count
        $mitigatedCount = @($exemptionData | Where-Object { $_.'Category' -eq 'Mitigated' }).Count
        Write-Host "  ✓ Found $($exemptionData.Count) policy exemptions ($activeCount active, $expiredCount expired)" -ForegroundColor Green
        Write-Host "    Categories: $waiverCount Waiver | $mitigatedCount Mitigated" -ForegroundColor Gray
    } else {
        Write-Progress -Activity "Querying Policy Exemptions" -Completed -Id 14
        Write-Host "  ✓ No policy exemptions found" -ForegroundColor Green
    }
} catch {
    Write-Progress -Activity "Querying Policy Exemptions" -Completed -Id 14
    Write-Host "  Warning: Could not retrieve policy exemptions: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Continuing without exemption information..." -ForegroundColor Gray
}

Write-Host "" # Blank line

Write-Host "Querying remediation tasks and managed identity roles from Azure Resource Graph..." -ForegroundColor Cyan
$remediationTaskLookup = @{}
$remediationTaskQuerySucceeded = $false
$remediationTaskQueryError = ''
$remediationTaskQueryTimestamp = [datetime]::UtcNow
$remediationTaskQuery = @"
resources
| where type =~ 'microsoft.policyinsights/remediations'
| extend
    assignmentId = tolower(tostring(properties.policyAssignmentId)),
    taskState = coalesce(tostring(properties.provisioningState), tostring(properties.status)),
    taskError = coalesce(tostring(properties.statusMessage), tostring(properties.error.message), tostring(properties.deploymentStatus.error)),
    failedDeployments = toint(properties.deploymentStatus.failedDeployments),
    successfulDeployments = toint(properties.deploymentStatus.successfulDeployments),
    totalDeployments = toint(properties.deploymentStatus.totalDeployments),
    createdOn = coalesce(tostring(systemData.createdAt), tostring(properties.createdOn)),
    lastUpdated = coalesce(tostring(systemData.lastModifiedAt), tostring(properties.lastUpdatedOn), tostring(properties.createdOn))
| project taskId = id, taskName = name, assignmentId, taskState, taskError,
          failedDeployments, successfulDeployments, totalDeployments, createdOn, lastUpdated,
          policyDefinitionReferenceId = tostring(properties.policyDefinitionReferenceId),
          resourceDiscoveryMode = tostring(properties.resourceDiscoveryMode),
          filters = properties.filters
"@
try {
    $remediationTaskResults = [System.Collections.Generic.List[object]]::new()
    $remediationTaskPage = Search-AzGraph -Query $remediationTaskQuery -First 1000 -UseTenantScope
    $remediationTaskResults.AddRange(@($remediationTaskPage | Expand-AzGraphResult))
    while ($remediationTaskPage.Count -eq 1000 -and $remediationTaskPage.SkipToken) {
        $remediationTaskPage = Search-AzGraph -Query $remediationTaskQuery -First 1000 -SkipToken $remediationTaskPage.SkipToken -UseTenantScope
        $remediationTaskResults.AddRange(@($remediationTaskPage | Expand-AzGraphResult))
    }
    $remediationTaskQuerySucceeded = $true
    foreach ($task in $remediationTaskResults) {
        $assignmentKey = [string]$task.assignmentId
        if (-not $assignmentKey) { continue }
        if (-not $remediationTaskLookup.ContainsKey($assignmentKey)) { $remediationTaskLookup[$assignmentKey] = @() }
        $remediationTaskLookup[$assignmentKey] += [PSCustomObject][ordered]@{
            TaskId = [string]$task.taskId
            TaskName = [string]$task.taskName
            State = [string]$task.taskState
            Error = [string]$task.taskError
            FailedDeployments = [int]($task.failedDeployments ?? 0)
            SuccessfulDeployments = [int]($task.successfulDeployments ?? 0)
            TotalDeployments = [int]($task.totalDeployments ?? 0)
            CreatedOn = [string]$task.createdOn
            LastUpdated = [string]$task.lastUpdated
            PolicyDefinitionReferenceId = [string]$task.policyDefinitionReferenceId
            ResourceDiscoveryMode = [string]$task.resourceDiscoveryMode
            Filters = $task.filters
        }
    }
    Write-Host "  Retrieved $($remediationTaskResults.Count) remediation task records" -ForegroundColor Gray
} catch {
    $remediationTaskQueryError = $_.Exception.Message
    Write-Host "  Remediation task evidence unavailable: $remediationTaskQueryError" -ForegroundColor Yellow
}

$roleAssignmentLookup = @{}
$roleAssignmentQuerySucceeded = $false
$roleAssignmentQueryError = ''
$managedIdentityPrincipalIds = @($argResults | ForEach-Object { [string]$_.identityPrincipalId } | Where-Object { $_ } | Select-Object -Unique)
if ($managedIdentityPrincipalIds.Count -eq 0) {
    $roleAssignmentQuerySucceeded = $true
} else {
    $principalFilter = ($managedIdentityPrincipalIds | ForEach-Object { "'$(($_ -replace "'", "''").ToLowerInvariant())'" }) -join ', '
    $roleAssignmentQuery = @"
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend principalId = tolower(tostring(properties.principalId))
| where principalId in~ ($principalFilter)
| extend lowerId = tolower(id), roleMarker = '/providers/microsoft.authorization/roleassignments/'
| extend roleScope = substring(id, 0, indexof(lowerId, roleMarker))
| project principalId, roleDefinitionId = tostring(properties.roleDefinitionId), roleScope
"@
    try {
        $roleAssignmentResults = [System.Collections.Generic.List[object]]::new()
        $roleAssignmentPage = Search-AzGraph -Query $roleAssignmentQuery -First 1000 -UseTenantScope
        $roleAssignmentResults.AddRange(@($roleAssignmentPage | Expand-AzGraphResult))
        while ($roleAssignmentPage.Count -eq 1000 -and $roleAssignmentPage.SkipToken) {
            $roleAssignmentPage = Search-AzGraph -Query $roleAssignmentQuery -First 1000 -SkipToken $roleAssignmentPage.SkipToken -UseTenantScope
            $roleAssignmentResults.AddRange(@($roleAssignmentPage | Expand-AzGraphResult))
        }
        $roleAssignmentQuerySucceeded = $true
        foreach ($role in $roleAssignmentResults) {
            $principalKey = [string]$role.principalId
            if (-not $roleAssignmentLookup.ContainsKey($principalKey)) { $roleAssignmentLookup[$principalKey] = @() }
            $roleAssignmentLookup[$principalKey] += [PSCustomObject]@{
                PrincipalId = $principalKey
                RoleDefinitionId = [string]$role.roleDefinitionId
                Scope = [string]$role.roleScope
            }
        }
        Write-Host "  Retrieved $($roleAssignmentResults.Count) relevant role assignments" -ForegroundColor Gray
    } catch {
        $roleAssignmentQueryError = $_.Exception.Message
        Write-Host "  Managed identity role evidence unavailable: $roleAssignmentQueryError" -ForegroundColor Yellow
    }
}

Write-Host "" # Blank line

# Identify regulatory compliance initiatives (by resolving initiative definitions)
Write-Host "Identifying regulatory compliance initiatives..." -ForegroundColor Cyan
$regulatoryInitiativeGuids = [System.Collections.Generic.HashSet[string]]::new()
try {
    $initiativeAssignments = @($argResults | Where-Object { $_.policyType -eq 'Initiative' })
    if ($initiativeAssignments.Count -gt 0) {
        $initiativeGuids = @($initiativeAssignments | ForEach-Object {
            if ($_.policyDefinitionId -match '/([^/]+)$') { $Matches[1].ToLower() }
        } | Select-Object -Unique)
        
        foreach ($iGuid in $initiativeGuids) {
            try {
                $setDef = Get-AzPolicySetDefinition -Name $iGuid -ErrorAction SilentlyContinue
                if ($setDef) {
                    $category = if ($setDef.Metadata -and $setDef.Metadata.category) { $setDef.Metadata.category }
                                elseif ($setDef.Properties.Metadata.category) { $setDef.Properties.Metadata.category }
                                else { $null }
                    if ($category -eq 'Regulatory Compliance') {
                        [void]$regulatoryInitiativeGuids.Add($iGuid)
                    }
                }
            } catch { }
        }
        Write-Host "  ✓ Found $($regulatoryInitiativeGuids.Count) regulatory compliance initiative(s) out of $($initiativeGuids.Count) total" -ForegroundColor Green
    } else {
        Write-Host "  No initiative assignments found" -ForegroundColor Gray
    }
} catch {
    Write-Host "  Warning: Could not classify initiatives: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "" # Blank line

# ── Batch-resolve policy definition metadata (effect, category, display name) via ARG ──
# This replaces individual Get-AzPolicyDefinition calls with a single ARG query — 10-100x faster.
Write-Host "Resolving policy definition metadata via Azure Resource Graph..." -ForegroundColor Cyan
Write-Progress -Activity "Resolving Policy Definitions" -Status "Querying policy definitions..." -PercentComplete 0 -Id 13

$policyDefMetadata = @{}   # key: lowercased GUID → { Effect, Category, DisplayName }
$initDefMetadata = @{}     # key: lowercased initiative GUID → { Category, DisplayName }

try {
    # Query individual policy definitions
    $policyDefQuery = @"
policyresources
| where type == 'microsoft.authorization/policydefinitions'
| project
    defName = name,
    displayName = tostring(properties.displayName),
    effect = tostring(properties.policyRule.then.effect),
    roleDefinitionIds = properties.policyRule.then.details.roleDefinitionIds,
    category = tostring(properties.metadata.category),
    policyType = tostring(properties.policyType)
"@

    $policyDefResults = [System.Collections.Generic.List[object]]::new(1024)
    $policyDefPage = Search-AzGraph -Query $policyDefQuery -First 1000 -UseTenantScope
    $policyDefResults.AddRange(@($policyDefPage | Expand-AzGraphResult))
    $defPageCount = 1

    while ($policyDefPage.Count -eq 1000 -and $policyDefPage.SkipToken) {
        $defPageCount++
        Write-Progress -Activity "Resolving Policy Definitions" -Status "Retrieving page $defPageCount ($($policyDefResults.Count) definitions)..." -PercentComplete ([math]::Min($defPageCount * 15, 70)) -Id 13
        $policyDefPage = Search-AzGraph -Query $policyDefQuery -First 1000 -SkipToken $policyDefPage.SkipToken -UseTenantScope
        $policyDefResults.AddRange(@($policyDefPage | Expand-AzGraphResult))
    }

    foreach ($def in $policyDefResults) {
        $defKey = "$($def.defName)".ToLower()
        if ($defKey) {
            $policyDefMetadata[$defKey] = @{
                Effect = "$($def.effect)"
                Category = "$($def.category)"
                DisplayName = "$($def.displayName)"
                RoleDefinitionIds = @($def.roleDefinitionIds)
            }
        }
    }
    Write-Host "  ✓ Resolved metadata for $($policyDefMetadata.Count) policy definitions" -ForegroundColor Green

    # Also query initiative (policy set) definitions for category
    $initDefQuery = @"
policyresources
| where type == 'microsoft.authorization/policysetdefinitions'
| project
    definitionId = id,
    defName = name,
    displayName = tostring(properties.displayName),
    version = tostring(properties.version),
    category = tostring(properties.metadata.category),
    policyType = tostring(properties.policyType),
    policyDefinitions = properties.policyDefinitions
"@

    $initDefResults = [System.Collections.Generic.List[object]]::new(256)
    $initDefPage = Search-AzGraph -Query $initDefQuery -First 1000 -UseTenantScope
    $initDefResults.AddRange(@($initDefPage | Expand-AzGraphResult))

    while ($initDefPage.Count -eq 1000 -and $initDefPage.SkipToken) {
        $initDefPage = Search-AzGraph -Query $initDefQuery -First 1000 -SkipToken $initDefPage.SkipToken -UseTenantScope
        $initDefResults.AddRange(@($initDefPage | Expand-AzGraphResult))
    }

    foreach ($iDef in $initDefResults) {
        $iKey = "$($iDef.defName)".ToLower()
        if ($iKey) {
            # Build effect summary by cross-referencing member policies with $policyDefMetadata
            $effectCounts = [ordered]@{}
            $initiativeRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $memberCount = 0
            if ($iDef.policyDefinitions) {
                foreach ($memberPol in $iDef.policyDefinitions) {
                    $memberDefId = if ($memberPol.policyDefinitionId) { $memberPol.policyDefinitionId } else { '' }
                    $memberGuid = if ($memberDefId -match '/([^/]+)$') { $Matches[1].ToLower() } else { '' }
                    $memberCount++
                    if ($memberGuid -and $policyDefMetadata.ContainsKey($memberGuid)) {
                        $memberEffect = $policyDefMetadata[$memberGuid].Effect
                        # Normalise parameterised effects
                        if ($memberEffect -match '^\[parameters') { $memberEffect = 'Parameterised' }
                        if (-not $memberEffect) { $memberEffect = 'Unknown' }
                        if (-not $effectCounts.Contains($memberEffect)) { $effectCounts[$memberEffect] = 0 }
                        $effectCounts[$memberEffect]++
                        foreach ($roleId in @($policyDefMetadata[$memberGuid].RoleDefinitionIds)) {
                            if ($roleId) { [void]$initiativeRoleIds.Add([string]$roleId) }
                        }
                    }
                }
            }

            # Format: single effect if uniform, or "Audit(5), Deny(3)" if mixed
            $effectSummary = if ($effectCounts.Count -eq 0) {
                "Multiple ($memberCount policies)"
            } elseif ($effectCounts.Count -eq 1) {
                $effectCounts.Keys | Select-Object -First 1
            } else {
                $sorted = $effectCounts.GetEnumerator() | Sort-Object Value -Descending
                ($sorted | ForEach-Object { "$($_.Key)($($_.Value))" }) -join ', '
            }

            $initDefMetadata[$iKey] = @{
                DefinitionId = "$($iDef.definitionId)"
                Category = "$($iDef.category)"
                DisplayName = "$($iDef.displayName)"
                Version = "$($iDef.version)"
                EffectSummary = $effectSummary
                MemberCount = $memberCount
                RoleDefinitionIds = @($initiativeRoleIds)
            }
        }
    }
    Write-Host "  ✓ Resolved metadata for $($initDefMetadata.Count) initiative definitions (with effect summaries)" -ForegroundColor Green

    Write-Progress -Activity "Resolving Policy Definitions" -Completed -Id 13
} catch {
    Write-Progress -Activity "Resolving Policy Definitions" -Completed -Id 13
    Write-Host "  Warning: Could not batch-resolve policy definitions: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Classifications will fall back to effect-type-only logic." -ForegroundColor Gray
}

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
    Write-Host "  ✓ Loaded $($mgLookup.Count) management group names" -ForegroundColor Green
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
    
    # ── Resolve effect type and category from batch-queried metadata ──
    $defKey = $policyDefName.ToLower()
    $policyCategory = ''
    
    if ($assignment.policyType -eq 'Initiative') {
        # Resolve the actual effects of member policies within this initiative
        if ($initDefMetadata.ContainsKey($defKey)) {
            $rawEffect = $initDefMetadata[$defKey].EffectSummary
            $policyCategory = $initDefMetadata[$defKey].Category
        } else {
            $rawEffect = 'Multiple'
        }
    } elseif ($policyDefMetadata.ContainsKey($defKey)) {
        # Use actual effect from policy definition metadata
        $rawEffect = $policyDefMetadata[$defKey].Effect
        $policyCategory = $policyDefMetadata[$defKey].Category
    } else {
        # Fallback: infer from definition name (legacy behaviour for custom/unavailable definitions)
        $rawEffect = switch -Regex ($policyDefName) {
            'Deny' { 'Deny' }
            'Audit' { 'Audit' }
            'DeployIfNotExists|DINE' { 'DeployIfNotExists' }
            'Modify' { 'Modify' }
            'Disabled' { 'Disabled' }
            default { 'Audit' }
        }
    }

    $effectivePolicyEffects = Resolve-EffectivePolicyEffects `
        -Effect $rawEffect `
        -AssignmentParameters $assignment.parameters
    $effectType = $effectivePolicyEffects.PrimaryEffect
    
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
    
    # Resolve display name for accurate keyword-based scoring
    # ($policyDefName is a GUID — keyword detectors need the human-readable name)
    $policyDisplayName = if ($assignment.policyType -eq 'Initiative' -and $initDefMetadata.ContainsKey($defKey) -and $initDefMetadata[$defKey].DisplayName) {
        $initDefMetadata[$defKey].DisplayName
    } elseif ($policyDefMetadata.ContainsKey($defKey) -and $policyDefMetadata[$defKey].DisplayName) {
        $policyDefMetadata[$defKey].DisplayName
    } else {
        $policyDefName   # fallback to GUID if no metadata available
    }

    # Get recommendations (now using real category metadata and display name)
    $recommendationObj = Get-PolicyRecommendation -PolicyName $policyDisplayName -EffectType ($effectivePolicyEffects.EffectiveEffects -join ', ') `
        -EnforcementMode $assignment.enforcementMode -PolicyType $assignment.policyType -Category $policyCategory
    
    # Get compliance data for this assignment
    $assignmentIdLower = $assignment.assignmentId.ToLower()
    $nonCompliantResources = 0
    $nonCompliantPolicies = 0
    $totalResources = 0
    $compliantResources = 0
    
    if ($complianceData.ContainsKey($assignmentIdLower)) {
        $nonCompliantResources = $complianceData[$assignmentIdLower].NonCompliantResources
        $nonCompliantPolicies = $complianceData[$assignmentIdLower].NonCompliantPolicyDefs
        $totalResources = if ($complianceData[$assignmentIdLower].TotalResources) { $complianceData[$assignmentIdLower].TotalResources } else { 0 }
        $compliantResources = if ($complianceData[$assignmentIdLower].CompliantResources) { $complianceData[$assignmentIdLower].CompliantResources } else { 0 }
    }

    $assignmentComplianceState = (Resolve-ComplianceAssessmentState `
        -QuerySucceeded $complianceQuerySucceeded `
        -QueryRecordCount $(if ($complianceData.ContainsKey($assignmentIdLower)) { 1 } else { 0 }) `
        -EvaluatedResources $totalResources `
        -CompliantResources $compliantResources `
        -NonCompliantResources $nonCompliantResources `
        -Timestamp $complianceQueryTimestamp `
        -ErrorMessage $complianceQueryError).State
    
    # For single policies, non-compliant policies is 0 or 1
    if ($assignment.policyType -eq 'Policy' -and $nonCompliantResources -gt 0) {
        $nonCompliantPolicies = 1
    }
    
    # Determine sub-type for initiatives (regulatory compliance vs classic)
    $policyTypeDisplay = $assignment.policyType
    if ($assignment.policyType -eq 'Initiative') {
        $initGuid = if ($assignment.policyDefinitionId -match '/([^/]+)$') { $Matches[1].ToLower() } else { '' }
        if ($regulatoryInitiativeGuids.Contains($initGuid)) {
            $policyTypeDisplay = 'Initiative (Regulatory)'
        }
    }

    # Create result object
    # Get exemption count for this assignment
    $exemptionCount = 0
    if ($exemptionLookup.ContainsKey($assignmentIdLower)) {
        $exemptionCount = @($exemptionLookup[$assignmentIdLower] | Where-Object { -not $_.'Is Expired' }).Count
    }

    $requiredRoleIds = if ($assignment.policyType -eq 'Initiative' -and $initDefMetadata.ContainsKey($defKey)) {
        @($initDefMetadata[$defKey].RoleDefinitionIds)
    } elseif ($policyDefMetadata.ContainsKey($defKey)) {
        @($policyDefMetadata[$defKey].RoleDefinitionIds)
    } else { @() }
    $principalKey = ([string]$assignment.identityPrincipalId).ToLowerInvariant()
    $availableRoleAssignments = if ($principalKey -and $roleAssignmentLookup.ContainsKey($principalKey)) { @($roleAssignmentLookup[$principalKey]) } else { @() }
    $remediationTasks = if ($remediationTaskLookup.ContainsKey($assignmentIdLower)) { @($remediationTaskLookup[$assignmentIdLower]) } else { @() }
    $activeAssignmentExemptions = if ($exemptionLookup.ContainsKey($assignmentIdLower)) {
        @($exemptionLookup[$assignmentIdLower] | Where-Object { -not $_.'Is Expired' } | ForEach-Object { $_.'Exemption ID' })
    } else { @() }
    $applicableResourceCount = if ($complianceData.ContainsKey($assignmentIdLower)) { [Nullable[int]][int]$complianceData[$assignmentIdLower].ApplicableResources } else { $null }
    $lastEvaluation = if ($complianceData.ContainsKey($assignmentIdLower)) { [string]$complianceData[$assignmentIdLower].LastEvaluation } else { '' }
    $remediationEvidence = if ($effectivePolicyEffects.IsRemediating) {
        New-RemediationEvidence `
            -AssignmentId $assignment.assignmentId -Scope $assignment.scope `
            -IdentityType $(if ($assignment.identityType) { $assignment.identityType } else { 'None' }) `
            -PrincipalId $assignment.identityPrincipalId -RequiredRoles $requiredRoleIds `
            -RoleAssignments $availableRoleAssignments -TaskRecords $remediationTasks `
            -TaskQuerySucceeded $remediationTaskQuerySucceeded -RoleQuerySucceeded $roleAssignmentQuerySucceeded `
            -TaskQueryError $remediationTaskQueryError -RoleQueryError $roleAssignmentQueryError `
            -EvidenceTimestamp $remediationTaskQueryTimestamp `
            -ApplicableResourceCount $applicableResourceCount -LastEvaluation $lastEvaluation `
            -Exemptions $activeAssignmentExemptions -NotScopes @($assignment.notScopes) `
            -ResourceSelectors @($assignment.resourceSelectors) -Overrides @($assignment.overrides)
    } else { $null }

    $policyResult = [PSCustomObject]@{
        'Assignment ID'       = $assignment.assignmentId
        'Assignment Name'     = $assignment.assignmentName
        'Display Name'        = $assignment.displayName
        'Policy Type'         = $policyTypeDisplay
        'Category'            = $policyCategory
        'Effect Type'         = $effectType
        'Effective Effects'   = @($effectivePolicyEffects.EffectiveEffects)
        'Primary Effect'      = $effectivePolicyEffects.PrimaryEffect
        'Is Preventive'       = $effectivePolicyEffects.IsPreventive
        'Is Detective'        = $effectivePolicyEffects.IsDetective
        'Is Remediating'      = $effectivePolicyEffects.IsRemediating
        'Is Parameterised'    = $effectivePolicyEffects.IsParameterised
        'Is Disabled'         = $effectivePolicyEffects.IsDisabled
        'Enforcement Mode'    = $assignment.enforcementMode
        'Compliance State'    = $assignmentComplianceState
        'Compliant Resources' = $compliantResources
        'Non-Compliant Resources' = $nonCompliantResources
        'Non-Compliant Policies' = $nonCompliantPolicies
        'Total Resources'     = $totalResources
        'Exemptions'          = $exemptionCount
        'Security Impact'     = $recommendationObj.SecurityImpact
        'Cost Exposure'       = $recommendationObj.CostImpact
        'Compliance Impact'   = $recommendationObj.ComplianceImpact
        'Operational Overhead'= $recommendationObj.OperationalOverhead
        'Risk Level'          = $recommendationObj.RiskLevel
        'Scope Type'          = $assignment.scopeType
        'Scope Name'          = $scopeName
        'Management Group ID' = $mgId
        'Policy Name'         = $policyDefName
        'Policy Definition ID'= $assignment.policyDefinitionId
        'Definition Version'   = $assignment.definitionVersion
        'Assignment Created On'= $assignment.createdOn
        'Identity Type'        = if ($assignment.identityType) { $assignment.identityType } else { 'None' }
        'Identity Principal ID'= $assignment.identityPrincipalId
        'Required Role IDs'    = @($requiredRoleIds)
        'Available Role IDs'   = if ($remediationEvidence) { @($remediationEvidence.AvailableRoles) } else { @() }
        'Missing Role IDs'     = if ($remediationEvidence) { @($remediationEvidence.MissingRoles) } else { @() }
        'Remediation State'    = if ($remediationEvidence) { $remediationEvidence.State } else { 'NotApplicable' }
        'Remediation Evidence' = $remediationEvidence
        'Applicable Resources' = $applicableResourceCount
        'Last Evaluation'      = $lastEvaluation
        'Excluded Scopes'      = @($assignment.notScopes).Count
        'Resource Selectors'   = @($assignment.resourceSelectors).Count
        'Overrides'            = @($assignment.overrides).Count
        'Not Scopes'           = @($assignment.notScopes)
        'Selector Details'     = @($assignment.resourceSelectors)
        'Override Details'     = @($assignment.overrides)
        'Parameters'          = $parametersString
        'Recommendation'      = $recommendationObj.Recommendation
        'Scope'               = $assignment.scope
    }
    
    [void]$results.Add($policyResult)
}

Write-Progress -Activity "Processing Policy Assignments" -Completed -Id 1
Write-Host "`nProcessing complete!" -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════
# EXECUTIVE SUMMARY — Concise console output
# ═══════════════════════════════════════════════════════════════

# Pre-compute summary statistics (used by both console and HTML)
$policyCount = ($results | Where-Object { $_.'Policy Type' -eq 'Policy' }).Count
$classicInitCount = ($results | Where-Object { $_.'Policy Type' -eq 'Initiative' }).Count
$regulatoryInitCount = ($results | Where-Object { $_.'Policy Type' -eq 'Initiative (Regulatory)' }).Count
$enforcedCount = ($results | Where-Object { $_.'Enforcement Mode' -eq 'Default' }).Count
$auditOnlyCount = ($results | Where-Object { $_.'Enforcement Mode' -eq 'DoNotEnforce' }).Count
$totalNCResources = ($results | ForEach-Object { if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 } } | Measure-Object -Sum).Sum
$assignmentsWithNC = ($results | Where-Object { ($_.'Non-Compliant Resources' -match '^\d+$') -and ([int]$_.'Non-Compliant Resources' -gt 0) }).Count
$mgAssignments = ($results | Where-Object { $_.'Scope Type' -eq 'Management Group' }).Count
$subAssignments = ($results | Where-Object { $_.'Scope Type' -eq 'Subscription' }).Count
$rgAssignments = ($results | Where-Object { $_.'Scope Type' -eq 'Resource Group' }).Count
$totalExemptions = $exemptionData.Count
$activeExemptions = @($exemptionData | Where-Object { -not $_.'Is Expired' }).Count
$assignmentsWithExemptions = ($results | Where-Object { ($_.'Exemptions' -match '^\d+$') -and ([int]$_.'Exemptions' -gt 0) }).Count
$assessmentFindings = @(New-AssessmentFindings -PolicyResults @($results))
$assessmentActions = @(ConvertTo-AssessmentActions -AssessmentFindings $assessmentFindings)

Write-Host ""
Write-Host "┌─────────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│  EXECUTIVE SUMMARY                                                          │" -ForegroundColor Cyan
Write-Host "├─────────────────────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
Write-Host "│  Assignments  : " -NoNewline -ForegroundColor Cyan
Write-Host "$($results.Count)" -NoNewline -ForegroundColor White
Write-Host "  (" -NoNewline -ForegroundColor DarkGray
Write-Host "$policyCount Policy" -NoNewline -ForegroundColor White
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host "$classicInitCount Initiative" -NoNewline -ForegroundColor Yellow
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host "$regulatoryInitCount Regulatory" -NoNewline -ForegroundColor Magenta
$padding1 = 77 - ("│  Assignments  : $($results.Count)  ($policyCount Policy | $classicInitCount Initiative | $regulatoryInitCount Regulatory)│").Length
if ($padding1 -lt 0) { $padding1 = 0 }
Write-Host ")" -NoNewline -ForegroundColor DarkGray
Write-Host (" " * $padding1) -NoNewline
Write-Host "│" -ForegroundColor Cyan
Write-Host "│  Non-Compliant: " -NoNewline -ForegroundColor Cyan
$ncSummary = switch ($complianceAssessment.State) {
    'NotEvaluated' { 'Not evaluated' }
    'DataUnavailable' { 'Data unavailable' }
    default { "$totalNCResources assignment-resource observations across $assignmentsWithNC assignments" }
}
$ncColor = switch ($complianceAssessment.State) {
    'EvaluatedNonCompliant' { 'Red' }
    'EvaluatedCompliant' { 'Green' }
    default { 'Yellow' }
}
Write-Host $ncSummary -NoNewline -ForegroundColor $ncColor
$ncLine = "│  Non-Compliant: $ncSummary│"
$padding2 = 77 - $ncLine.Length
if ($padding2 -lt 0) { $padding2 = 0 }
Write-Host (" " * $padding2) -NoNewline
Write-Host "│" -ForegroundColor Cyan
Write-Host "│  Enforcement  : " -NoNewline -ForegroundColor Cyan
Write-Host "$enforcedCount enforced" -NoNewline -ForegroundColor Green
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host "$auditOnlyCount enforcement disabled" -NoNewline -ForegroundColor Yellow
$enfLine = "│  Enforcement  : $enforcedCount enforced | $auditOnlyCount enforcement disabled│"
$padding3 = 77 - $enfLine.Length
if ($padding3 -lt 0) { $padding3 = 0 }
Write-Host (" " * $padding3) -NoNewline
Write-Host "│" -ForegroundColor Cyan
Write-Host "│  Scope        : " -NoNewline -ForegroundColor Cyan
Write-Host "MG: $mgAssignments" -NoNewline -ForegroundColor White
if ($subAssignments -gt 0) { Write-Host " | Sub: $subAssignments" -NoNewline -ForegroundColor White }
if ($rgAssignments -gt 0) { Write-Host " | RG: $rgAssignments" -NoNewline -ForegroundColor White }
$scopeText = "MG: $mgAssignments"
if ($subAssignments -gt 0) { $scopeText += " | Sub: $subAssignments" }
if ($rgAssignments -gt 0) { $scopeText += " | RG: $rgAssignments" }
$scopeLine = "│  Scope        : $scopeText│"
$padding4 = 77 - $scopeLine.Length
if ($padding4 -lt 0) { $padding4 = 0 }
Write-Host (" " * $padding4) -NoNewline
Write-Host "│" -ForegroundColor Cyan
if ($totalExemptions -gt 0) {
    Write-Host "│  Exemptions   : " -NoNewline -ForegroundColor Cyan
    Write-Host "$activeExemptions active" -NoNewline -ForegroundColor Yellow
    Write-Host " across $assignmentsWithExemptions assignments" -NoNewline -ForegroundColor DarkGray
    $expiredEx = $totalExemptions - $activeExemptions
    if ($expiredEx -gt 0) { Write-Host " ($expiredEx expired)" -NoNewline -ForegroundColor DarkGray }
    $exLine = "│  Exemptions   : $activeExemptions active across $assignmentsWithExemptions assignments│"
    $padding5 = 77 - $exLine.Length
    if ($padding5 -lt 0) { $padding5 = 0 }
    Write-Host (" " * $padding5) -NoNewline
    Write-Host "│" -ForegroundColor Cyan
}
Write-Host "└─────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

# Findings requiring attention
if ($assessmentFindings.Count -gt 0) {
    Write-Host ""
    Write-Host "  Preliminary Assignment Findings (ALZ comparison follows later):" -ForegroundColor Red
    foreach ($finding in ($assessmentFindings | Select-Object -First 10)) {
        Write-Host "    [$($finding.Id)] $($finding.Severity) | $($finding.Category) | $($finding.Title)" -ForegroundColor Yellow
    }
}

# ═══════════════════════════════════════════════════════════════
# QUICK ASSESSMENT MODE — one-page summary for fast review
# ═══════════════════════════════════════════════════════════════
if ($QuickAssess) {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  ⚡ QUICK ASSESSMENT" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    # Overall posture verdict
    $highSecDNE = @($assessmentFindings | Where-Object { $_.Category -eq 'Enforcement Gap' -and $_.Severity -eq 'Critical' })
    $highRiskPolicies = @($results | Where-Object { $_.'Risk Level' -eq 'High' })
    $verdict = Resolve-QuickAssessmentPosture `
        -ComplianceState $complianceAssessment.State `
        -HighRiskPolicyCount $highRiskPolicies.Count `
        -HighSecurityDoNotEnforceCount $highSecDNE.Count `
        -NonCompliantObservationCount $totalNCResources `
        -AuditOnlyCount $auditOnlyCount
    Write-Host "  Posture: $verdict" -ForegroundColor White
    Write-Host "  Enforcement Rate: $([math]::Round(($enforcedCount / [math]::Max($results.Count,1)) * 100))%" -ForegroundColor White
    if ($complianceAssessment.State -eq 'DataUnavailable') {
        Write-Host "  Non-Compliant Resources: Data unavailable" -ForegroundColor Yellow
    } elseif ($complianceAssessment.State -eq 'NotEvaluated') {
        Write-Host "  Non-Compliant Resources: Not evaluated" -ForegroundColor Yellow
    } elseif ($totalNCResources -gt 0) {
        Write-Host "  Non-Compliant Observations: $totalNCResources across $assignmentsWithNC assignments" -ForegroundColor Red
    } else {
        Write-Host "  Non-Compliant Resources: 0 ✓" -ForegroundColor Green
    }

    # Top 5 enforcement gaps from central findings
    if ($highSecDNE.Count -gt 0) {
        Write-Host "`n  ⚠️  Top Enforcement Gaps (high-security, not enforced):" -ForegroundColor Yellow
        $highSecDNE | Select-Object -First 5 | ForEach-Object {
            Write-Host "    • [$($_.Id)] $($_.Title)" -ForegroundColor DarkYellow
        }
    }

    # Top 5 non-compliance findings
    $topNCQuick = $assessmentFindings | Where-Object Category -eq 'Non-Compliance' | Sort-Object { $_.Evidence.NonCompliantResources } -Descending | Select-Object -First 5
    if ($topNCQuick.Count -gt 0) {
        Write-Host "`n  🔴 Top Non-Compliant Assignments:" -ForegroundColor Red
        foreach ($nc in $topNCQuick) {
            Write-Host "    $($nc.Evidence.NonCompliantResources) NC | [$($nc.Id)] $($nc.Title)" -ForegroundColor Yellow
        }
    }

    # Category breakdown
    $categoryGroups = $results | Where-Object { $_.'Category' -and $_.'Category' -ne '' } | Group-Object 'Category' | Sort-Object Count -Descending | Select-Object -First 8
    if ($categoryGroups.Count -gt 0) {
        Write-Host "`n  📂 Policy Categories:" -ForegroundColor Cyan
        foreach ($cg in $categoryGroups) {
            $cgNC = ($cg.Group | ForEach-Object { if ($_.'Non-Compliant Resources' -match '^\d+$') { [int]$_.'Non-Compliant Resources' } else { 0 } } | Measure-Object -Sum).Sum
            $ncInfo = if ($cgNC -gt 0) { " ($cgNC NC)" } else { "" }
            Write-Host "    $($cg.Name): $($cg.Count) assignments$ncInfo" -ForegroundColor Gray
        }
    }

    # Quick recommendations
    Write-Host "`n  💡 Key Actions:" -ForegroundColor Cyan
    $quickActions = @($assessmentActions | Select-Object -First 5)
    for ($actionIndex = 0; $actionIndex -lt $quickActions.Count; $actionIndex++) {
        $action = $quickActions[$actionIndex]
        Write-Host "    $($actionIndex + 1). [$(@($action.FindingIds) -join ', ')] $($action.Action)" -ForegroundColor White
    }
    if ($quickActions.Count -eq 0) { Write-Host "    No critical actions needed. Continue monitoring." -ForegroundColor Green }

    Write-Host ""
    Write-Host "  Use -Full for a comprehensive report or -ExportHTML for the full HTML report." -ForegroundColor DarkGray
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

# Generate overall assessment & recommendations (always runs)
Write-Host "`nOVERALL ASSESSMENT & RECOMMENDATIONS" -ForegroundColor Cyan

# Summary statistics (reuse pre-computed where available)
$totalPolicies = $results.Count
$totalInitiatives = $classicInitCount
$totalSinglePolicies = $policyCount
$highSecurityPolicies = ($results | Where-Object { $_.'Security Impact' -eq 'High' }).Count
$highCostPolicies = @($assessmentFindings | Where-Object Category -eq 'Cost Exposure').Count
$doNotEnforcePolicies = $auditOnlyCount
$defaultEnforcePolicies = $enforcedCount
$highRiskPolicies = ($results | Where-Object { $_.'Risk Level' -eq 'High' }).Count

# Count effect types
$effectTypeCounts = (Get-EffectivePolicyEffectCounts -PolicyResults @($results)).Breakdown | Sort-Object Count -Descending

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
    $effectName = $effect.Effect
    Write-Host "    • $($effectName): $($effect.Count)" -ForegroundColor Gray
}

Write-Host "`n  Impact Analysis:" -ForegroundColor White
Write-Host "    • High Security Impact: $highSecurityPolicies" -ForegroundColor Gray
Write-Host "    • Cost exposure: High: $highCostPolicies" -ForegroundColor Gray
Write-Host "    • High Risk Level: $highRiskPolicies" -ForegroundColor Gray

# Get recommended Azure Landing Zone policies (dynamically from GitHub or fallback)
$recommendedALZPolicies = Get-ALZRecommendedPolicies -ALZVersion 'latest'

Write-Host "`nAzure Landing Zone Policy Coverage Analysis:" -ForegroundColor Yellow
Write-Host "(Based on official Azure Landing Zone Bicep repository)" -ForegroundColor Gray
Write-Host "Source: $($script:ALZSourceVersion) | Retrieved: $($script:ALZSourceRetrievedAt)" -ForegroundColor Gray

$missingCriticalPolicies = [System.Collections.Generic.List[object]]::new()
$doNotEnforceALZPolicies = [System.Collections.Generic.List[object]]::new()
$matchedALZPolicies = [System.Collections.Generic.List[object]]::new()
$alzAssetAssessments = [System.Collections.Generic.List[object]]::new()
$consumedALZAssignmentKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$assignedPoliciesWithEnforcement = $results | Select-Object 'Assignment ID', 'Assignment Name', 'Policy Name', 'Policy Definition ID', 'Display Name', 'Enforcement Mode', 'Parameters', 'Scope', 'Scope Name'
$structuredALZAssets = @($script:ALZAssets)

foreach ($category in $recommendedALZPolicies.Keys) {
    if ($recommendedALZPolicies[$category].Count -eq 0) { continue }
    
    Write-Host "`n  $category" -ForegroundColor Cyan
    foreach ($policy in $recommendedALZPolicies[$category]) {
        $asset = $structuredALZAssets | Where-Object AssetName -EQ $policy | Select-Object -First 1
        $officialDefinitionId = if ($asset) { $asset.DefinitionId } else { $script:ALZPolicyDefinitionIds[$policy] }
        $sharedDefinitionIdCount = if ($officialDefinitionId) {
            @($structuredALZAssets | Where-Object DefinitionId -EQ $officialDefinitionId).Count
        } else { 1 }
        $matchingPolicies = Find-ALZMatchingAssignments -AssetName $policy `
            -OfficialDefinitionId $officialDefinitionId `
            -AssetParameters $(if ($asset) { $asset.Parameters } else { $null }) `
            -Archetype $(if ($asset) { $asset.Archetype } else { '' }) `
            -SharedDefinitionIdCount $sharedDefinitionIdCount `
            -ConsumedAssignmentKeys $consumedALZAssignmentKeys `
            -Assignments @($assignedPoliciesWithEnforcement)
        
        $matchState = Resolve-ALZPolicyMatchState -MatchingAssignments @($matchingPolicies)
        $selectedMatch = @($matchingPolicies | Sort-Object @{ Expression = { if ($_.'Enforcement Mode' -eq 'Default') { 0 } else { 1 } } }, 'Assignment Name' | Select-Object -First 1)
        if ($selectedMatch.Count -gt 0) {
            $assignmentKey = if ($selectedMatch[0].'Assignment ID') { [string]$selectedMatch[0].'Assignment ID' } else { "$($selectedMatch[0].'Assignment Name')|$($selectedMatch[0].Scope)" }
            [void]$consumedALZAssignmentKeys.Add($assignmentKey)
            $matchingPolicies = @($selectedMatch)
            $matchState = Resolve-ALZPolicyMatchState -MatchingAssignments $matchingPolicies
        }
        $applicabilityAssessed = $asset -and $asset.PSObject.Properties['Applicable']
        $applicable = if ($applicabilityAssessed) { [Nullable[bool]]$asset.Applicable } else { $null }
        $assetState = Resolve-ALZAssetState -MatchState $matchState -Applicable $applicable -ApplicabilityAssessed:$applicabilityAssessed
        [void]$alzAssetAssessments.Add([PSCustomObject][ordered]@{
            Category = $category
            AssetName = $policy
            DefinitionId = $officialDefinitionId
            Archetype = if ($asset) { $asset.Archetype } else { '' }
            ParameterSignature = if ($asset) { $asset.ParameterSignature } else { '' }
            State = $assetState
            MatchState = $matchState
            AssignmentId = if ($selectedMatch.Count -gt 0) { $selectedMatch[0].'Assignment ID' } else { '' }
            AssignmentName = if ($selectedMatch.Count -gt 0) { $selectedMatch[0].'Assignment Name' } else { '' }
        })
        if ($matchState -ne 'Missing') {
            if ($matchState -eq 'DoNotEnforce') {
                $doNotEnforceMatch = $matchingPolicies | Where-Object { $_.'Enforcement Mode' -eq 'DoNotEnforce' } | Select-Object -First 1
                Write-Host "    ⚠️  $policy (DoNotEnforce)" -ForegroundColor Yellow
                [void]$doNotEnforceALZPolicies.Add([PSCustomObject]@{
                    Category = $category
                    PolicyName = $policy
                    ActualName = $doNotEnforceMatch.'Policy Name'
                })
            } else {
                Write-Host "    ✓ $policy" -ForegroundColor Green
                [void]$matchedALZPolicies.Add([PSCustomObject]@{
                    Category = $category
                    PolicyName = $policy
                })
            }
        } elseif ($assetState -eq 'Applicable gap') {
            Write-Host "    ✗ $policy (APPLICABLE GAP)" -ForegroundColor Red
            [void]$missingCriticalPolicies.Add([PSCustomObject]@{ Category = $category; PolicyPattern = $policy; State = $assetState })
        } elseif ($assetState -eq 'Not applicable') {
            Write-Host "    − $policy (NOT APPLICABLE)" -ForegroundColor DarkGray
        } else {
            Write-Host "    ? $policy ($($assetState.ToUpperInvariant()))" -ForegroundColor DarkGray
        }
    }
}

# Build ALZ data hashtable for HTML report
$alzTotalRecommended = $alzAssetAssessments.Count
$alzData = @{
    RecommendedPolicies    = $recommendedALZPolicies
    MatchedPolicies        = $matchedALZPolicies
    MissingPolicies        = $missingCriticalPolicies
    DoNotEnforcePolicies   = $doNotEnforceALZPolicies
    TotalRecommended       = $alzTotalRecommended
    TotalMatched           = $matchedALZPolicies.Count
    TotalMissing           = $missingCriticalPolicies.Count
    TotalDoNotEnforce      = $doNotEnforceALZPolicies.Count
    AssetAssessments       = @($alzAssetAssessments)
    TotalNotDetected       = @($alzAssetAssessments | Where-Object MatchState -eq 'Missing').Count
    TotalApplicabilityNotAssessed = @($alzAssetAssessments | Where-Object State -eq 'Applicability not assessed').Count
    TotalNotApplicable     = @($alzAssetAssessments | Where-Object State -eq 'Not applicable').Count
    CoveragePercent        = if ($alzTotalRecommended -gt 0) { [math]::Round((($matchedALZPolicies.Count + $doNotEnforceALZPolicies.Count) / $alzTotalRecommended) * 100) } else { 0 }
    EnforcedCoveragePercent = if ($alzTotalRecommended -gt 0) { [math]::Round(($matchedALZPolicies.Count / $alzTotalRecommended) * 100) } else { 0 }
    SourceVersion          = $script:ALZSourceVersion
    SourceRetrievedAt      = $script:ALZSourceRetrievedAt
}

$assessmentFindings = @(New-AssessmentFindings -PolicyResults @($results) -ALZData $alzData)
$assessmentActions = @(ConvertTo-AssessmentActions -AssessmentFindings $assessmentFindings)

# CEP state exists for every run and is resolved before report consumers use assessment evidence.
$cepAssessment = if ($CEP -eq 'Off') {
    New-CEPAssessment -Requested $false -State NotRequested
} else {
    New-CEPAssessment `
        -Requested $true `
        -State PartiallyEvaluated `
        -MappingState $(if ($ShowCEPCompliance) { 'Pending' } else { 'NotRequested' }) `
        -TestState $(if ($RunCEPTests) { 'Pending' } else { 'NotRequested' })
}

if ($RunCEPTests) {
    $cepResult = Invoke-CEPComplianceTests -PolicyAssignments $argResults -DefinitionId $CEPDefinitionId -DefinitionVersion $CEPDefinitionVersion
    $cepAssessment = $cepResult.Assessment
    $cepTestResults = if ($cepResult.TestResults) { $cepResult.TestResults } else { @() }
    $cepPerScopeData = if ($cepResult.PerScopeData) { $cepResult.PerScopeData } else { @() }
    $cepPerScopeGroupData = if ($cepResult.PerScopeGroupData) { $cepResult.PerScopeGroupData } else { @{} }
    $cepPerScopeGroupRaw = if ($cepResult.PerScopeGroupRaw) { $cepResult.PerScopeGroupRaw } else { @{} }
    $cepRefIdToGroupDisplay = if ($cepResult.RefIdToGroupDisplay) { $cepResult.RefIdToGroupDisplay } else { @{} }

    if ($ExportCEPCompliance -and $cepTestResults -and $cepTestResults.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $testFileName = "CEP_TestResults_$timestamp.csv"
        $testFilePath = Join-Path -Path (Get-Location) -ChildPath $testFileName
        $cepTestResults | Export-Csv -Path $testFilePath -NoTypeInformation -Encoding UTF8
        Write-Host "`n✓ CE/CE+ test results exported to: $testFilePath" -ForegroundColor Green
    }
}

$cepFindings = @(New-CEPAssessmentFindings -CEPAssessment $cepAssessment -CEPTestResults $(if ($cepTestResults) { $cepTestResults } else { @() }))
if ($cepFindings.Count -gt 0) {
    $assessmentFindings = @($assessmentFindings + $cepFindings | Sort-Object Id -Unique)
    $assessmentActions = @(ConvertTo-AssessmentActions -AssessmentFindings $assessmentFindings)
}

$costEvidenceRecords = @()
if ($CostEvidence -in @('RetailPrices', 'All')) {
    if (-not $CostRegion -or @($CostServiceName).Count -eq 0) {
        Write-Host 'Retail Prices evidence skipped: specify -CostRegion and -CostServiceName.' -ForegroundColor Yellow
    } else {
        try {
            $costEvidenceRecords += @(Get-AzureRetailPriceEvidence -Region $CostRegion -Currency $CostCurrency -ServiceNames $CostServiceName)
        } catch {
            Write-Host "Retail Prices evidence unavailable: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
if ($CostEvidence -in @('CostManagement', 'All')) {
    if (-not $resolvedSubscription -or -not $resolvedSubscription.Id) {
        Write-Host 'Cost Management evidence skipped: no resolved subscription is available.' -ForegroundColor Yellow
    } else {
        try {
            $costEvidenceRecords += @(Get-AzureCostManagementEvidence -SubscriptionId $resolvedSubscription.Id -LookbackDays $CostLookbackDays)
        } catch {
            Write-Host "Cost Management evidence unavailable: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
$costEvidenceRecords = @($costEvidenceRecords | Where-Object { Test-CostEvidenceRecord -Record $_ })
if ($CostEvidence -ne 'Off') {
    Write-Host "Official cost evidence records collected: $($costEvidenceRecords.Count)" -ForegroundColor Gray
}

# Overall recommendations from central findings
Write-Host "`nKEY RECOMMENDATIONS:" -ForegroundColor Yellow
if ($assessmentActions.Count -gt 0) {
    for ($actionIndex = 0; $actionIndex -lt $assessmentActions.Count; $actionIndex++) {
        $action = $assessmentActions[$actionIndex]
        Write-Host "   $($actionIndex + 1). [$(@($action.FindingIds) -join ', ')] $($action.Action)" -ForegroundColor White
    }
} else {
    Write-Host "   No finding-linked actions were identified." -ForegroundColor Green
}

# Security posture assessment
Write-Host "`n🔒 SECURITY POSTURE:" -ForegroundColor Yellow

# Combine security assessment with ALZ gap analysis
$alzGapCount = $missingCriticalPolicies.Count

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

# Cyber Essentials Compliance Analysis (dedicated switch)
if ($ShowCEPCompliance) {
    # ══════════════════════════════════════════════════════════════════
    # Cyber Essentials v3.1 Compliance Report
    # Uses the same proven logic as Get-CEComplianceReport.ps1
    # ══════════════════════════════════════════════════════════════════
    Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  🇬🇧 Cyber Essentials v3.1 — Compliance Report" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Using built-in 'UK NCSC Cyber Essentials v3.1' Azure Policy Initiative" -ForegroundColor White
    Write-Host "   This does NOT provide official CE certification. Use for guidance only." -ForegroundColor Gray
    Write-Host ""

    # Data structures for export
    $cepExportData = [System.Collections.Generic.List[object]]::new()

    # ── Step 1: Resolve the configured CE initiative source ──
    Write-Progress -Activity "CE Compliance" -Status "Resolving CE mapping source..." -PercentComplete 5 -Id 30
    Write-Host "   Resolving Cyber Essentials v$CEPDefinitionVersion initiative definition..." -ForegroundColor Gray
    $sourceResolution = Resolve-CEPMappingSource -DefinitionId $CEPDefinitionId -DefinitionVersion $CEPDefinitionVersion
    $ceInitiative = $sourceResolution.Definition

    if (-not $ceInitiative) {
        Write-Progress -Activity "CE Compliance" -Completed -Id 30
        Write-Host "   ⚠️  $($sourceResolution.Message)" -ForegroundColor Yellow
        if ($sourceResolution.Candidates.Count -gt 0) {
            Write-Host "   Candidate definitions:" -ForegroundColor Gray
            $sourceResolution.Candidates | ForEach-Object { Write-Host "     • $($_.DisplayName) [$($_.Name)]" -ForegroundColor Gray }
        }
        Write-Host "   This discovery result does not imply incorrect tenant configuration." -ForegroundColor Gray
    } else {
        $ceInitiativeName = $ceInitiative.Name
        $ceInitiativeDisplayName = $ceInitiative.DisplayName

        Write-Progress -Activity "CE Compliance" -Status "Found initiative: $ceInitiativeDisplayName" -PercentComplete 10 -Id 30
        Write-Host "   ✓ Found: $ceInitiativeDisplayName" -ForegroundColor Green

        # Parse policy definitions & groups from the initiative
        $cePolicyDefinitions = @()
        try {
            if ($ceInitiative.PolicyDefinition -is [string]) {
                $cePolicyDefinitions = $ceInitiative.PolicyDefinition | ConvertFrom-Json
            } else {
                $cePolicyDefinitions = @($ceInitiative.PolicyDefinition)
            }
        } catch {
            Write-Host "   ⚠️  Could not parse initiative policy definitions" -ForegroundColor Yellow
        }

        $ceGroupDefinitions = @()
        try {
            if ($ceInitiative.PolicyDefinitionGroup -is [string]) {
                $ceGroupDefinitions = $ceInitiative.PolicyDefinitionGroup | ConvertFrom-Json
            } else {
                $ceGroupDefinitions = @($ceInitiative.PolicyDefinitionGroup)
            }
        } catch {
            Write-Host "   ⚠️  Could not parse initiative group definitions" -ForegroundColor Yellow
        }

        Write-Host "   Policies in initiative: $($cePolicyDefinitions.Count)" -ForegroundColor Gray
        Write-Host "   Control groups: $($ceGroupDefinitions.Count)" -ForegroundColor Gray

        # Build refId → defGuid mapping and refId → groupNames mapping
        $ceRefIdToDefGuid = @{}
        $ceRefIdToGroups  = @{}
        foreach ($p in $cePolicyDefinitions) {
            $refId = if ($p.policyDefinitionReferenceId) { $p.policyDefinitionReferenceId } elseif ($p.PolicyDefinitionReferenceId) { $p.PolicyDefinitionReferenceId } else { $null }
            $defId = if ($p.policyDefinitionId) { $p.policyDefinitionId } elseif ($p.PolicyDefinitionId) { $p.PolicyDefinitionId } else { $null }
            $groups = if ($p.groupNames) { @($p.groupNames) } elseif ($p.GroupNames) { @($p.GroupNames) } else { @() }
            if ($refId -and $defId) {
                $guid = if ($defId -match '/([^/]+)$') { $Matches[1].ToLower() } else { $defId.ToLower() }
                $ceRefIdToDefGuid[$refId] = $guid
                $ceRefIdToGroups[$refId]  = $groups
            }
        }

        # ── Step 2: Check initiative assignments via ARG ──
        Write-Progress -Activity "CE Compliance" -Status "Checking initiative assignments..." -PercentComplete 15 -Id 30
        Write-Host "`n   Checking initiative assignments..." -ForegroundColor Gray

        $ceAssignQuery = @"
policyresources
| where type =~ 'microsoft.authorization/policyassignments'
| extend policyDefinitionId = tolower(tostring(properties.policyDefinitionId)),
         assignmentId = tolower(tostring(id)),
         displayName = tostring(properties.displayName),
         enforcementMode = tostring(properties.enforcementMode)
| where policyDefinitionId contains '$($ceInitiativeName.ToLower())'
| project assignmentId, displayName, enforcementMode
"@

        $ceAssignments = @()
        try {
            $ceAssignments = @(Search-AzGraph -Query $ceAssignQuery -First 100 -UseTenantScope | Expand-AzGraphResult)
        } catch {
            # Fallback: check the already-retrieved $argResults
            $ceAssignments = @($argResults | Where-Object {
                $_.policyDefinitionId -like "*$ceInitiativeName*"
            } | ForEach-Object {
                [PSCustomObject]@{
                    assignmentId    = "$($_.assignmentId)".ToLower()
                    displayName     = $_.displayName
                    enforcementMode = $_.enforcementMode
                }
            })
        }

        if ($ceAssignments.Count -eq 0) {
            # ── Initiative NOT assigned: show individual policy coverage analysis ──
            Write-Host "   ⚠️  Initiative '$ceInitiativeDisplayName' is NOT directly assigned in this tenant." -ForegroundColor Yellow
            Write-Host "   For full CE compliance assessment, assign this initiative at a management group or subscription scope." -ForegroundColor White
            Write-Host "   Azure Portal > Policy > Assignments > Assign Initiative > Search 'Cyber Essentials'" -ForegroundColor Gray
            Write-Host ""

            # Cross-reference individually assigned policies against CE initiative definitions
            Write-Progress -Activity "CE Compliance" -Status "Cross-referencing individual policy assignments..." -PercentComplete 20 -Id 30
            Write-Host "   Checking if individually assigned policies cover CE initiative requirements..." -ForegroundColor Cyan

            $ceDefIdToRef = @{}
            foreach ($policyRef in $cePolicyDefinitions) {
                $defId = if ($policyRef.policyDefinitionId) { $policyRef.policyDefinitionId } elseif ($policyRef.PolicyDefinitionId) { $policyRef.PolicyDefinitionId } else { $null }
                $refId = if ($policyRef.policyDefinitionReferenceId) { $policyRef.policyDefinitionReferenceId } elseif ($policyRef.PolicyDefinitionReferenceId) { $policyRef.PolicyDefinitionReferenceId } else { $null }
                $groups = if ($policyRef.groupNames) { @($policyRef.groupNames) } elseif ($policyRef.GroupNames) { @($policyRef.GroupNames) } else { @() }
                if ($defId) {
                    $defGuid = if ($defId -match '/([^/]+)$') { $Matches[1].ToLower() } else { $defId.ToLower() }
                    $ceDefIdToRef[$defGuid] = @{ FullDefinitionId = $defId; ReferenceId = $refId; GroupNames = $groups }
                    $ceDefIdToRef[$defId.ToLower()] = @{ FullDefinitionId = $defId; ReferenceId = $refId; GroupNames = $groups }
                }
            }

            $matchedCEPolicies = @{}
            $matchedCEAssignments = [System.Collections.Generic.List[object]]::new()
            foreach ($assignment in $argResults) {
                if ($assignment.policyType -eq 'Initiative') { continue }
                $assignedDefId = $assignment.policyDefinitionId
                if (-not $assignedDefId) { continue }
                $assignedGuid = if ($assignedDefId -match '/([^/]+)$') { $Matches[1].ToLower() } else { $assignedDefId.ToLower() }
                if ($ceDefIdToRef.ContainsKey($assignedGuid)) {
                    $ceRef = $ceDefIdToRef[$assignedGuid]
                    if (-not $matchedCEPolicies.ContainsKey($assignedGuid)) {
                        $matchedCEPolicies[$assignedGuid] = @{
                            ReferenceId = $ceRef.ReferenceId; GroupNames = $ceRef.GroupNames
                            FullDefinitionId = $ceRef.FullDefinitionId; Assignments = [System.Collections.ArrayList]@()
                        }
                    }
                    [void]$matchedCEPolicies[$assignedGuid].Assignments.Add(@{
                        AssignmentName = $assignment.assignmentName; DisplayName = $assignment.displayName
                        EnforcementMode = $assignment.enforcementMode; Scope = $assignment.scope
                        ScopeType = $assignment.scopeType; AssignmentId = $assignment.assignmentId
                    })
                    [void]$matchedCEAssignments.Add($assignment)
                }
            }

            $matchedCount = $matchedCEPolicies.Count
            $totalCEPolicies = $cePolicyDefinitions.Count
            $coveragePercent = if ($totalCEPolicies -gt 0) { [math]::Round(($matchedCount / $totalCEPolicies) * 100, 1) } else { 0 }

            Write-Host "`n   📊 CE POLICY COVERAGE (via individual assignments):" -ForegroundColor Cyan
            Write-Host "      Policies in CE initiative: $totalCEPolicies" -ForegroundColor White
            Write-Host "      Covered by individual assignments: $matchedCount" -ForegroundColor $(if ($matchedCount -gt 0) { 'Green' } else { 'Yellow' })
            Write-Host "      Not covered: $($totalCEPolicies - $matchedCount)" -ForegroundColor $(if (($totalCEPolicies - $matchedCount) -gt 0) { 'Red' } else { 'Green' })
            Write-Host "      Coverage: $coveragePercent%" -ForegroundColor $(if ($coveragePercent -ge 80) { 'Green' } elseif ($coveragePercent -ge 50) { 'Yellow' } else { 'Red' })

            # Resolve display names — use batch-resolved metadata cache (fast), fallback to individual calls
            $policyDefDisplayNames = @{}
            $allGuidsToResolve = @($ceRefIdToDefGuid.Values | Select-Object -Unique)
            Write-Host "   Resolving $($allGuidsToResolve.Count) policy display names..." -ForegroundColor Gray
            $unresolvedGuids = [System.Collections.Generic.List[string]]::new()
            foreach ($guid in $allGuidsToResolve) {
                if ($policyDefMetadata.ContainsKey($guid) -and $policyDefMetadata[$guid].DisplayName) {
                    $policyDefDisplayNames[$guid] = $policyDefMetadata[$guid].DisplayName
                } else {
                    [void]$unresolvedGuids.Add($guid)
                }
            }
            # Fallback: resolve any remaining via individual API calls
            if ($unresolvedGuids.Count -gt 0) {
                Write-Host "   Resolving $($unresolvedGuids.Count) remaining names via API..." -ForegroundColor Gray
                $resolveIdx = 0
                foreach ($guid in $unresolvedGuids) {
                    $resolveIdx++
                    Write-Progress -Activity "CE Compliance" -Status "Resolving policy names ($resolveIdx/$($unresolvedGuids.Count))..." -PercentComplete ([math]::Min(20 + ([math]::Round($resolveIdx / [math]::Max($unresolvedGuids.Count,1) * 70)), 90)) -Id 30
                    try {
                        $policyDef = Get-AzPolicyDefinition -Name $guid -ErrorAction SilentlyContinue
                        if ($policyDef -and $policyDef.DisplayName) { $policyDefDisplayNames[$guid] = $policyDef.DisplayName }
                    } catch { }
                }
            }
            Write-Host "   ✓ Resolved $($policyDefDisplayNames.Count) / $($allGuidsToResolve.Count) display names" -ForegroundColor Green
            $Script:CachedPolicyDisplayNames = $policyDefDisplayNames

            # Query compliance for individually matched assignments
            $ceIndividualComplianceData = @{}
            $validAssignments = @($matchedCEAssignments | Where-Object { $_.assignmentId -and $_.assignmentId -ne '' })
            if ($validAssignments.Count -gt 0) {
                Write-Progress -Activity "CE Compliance" -Status "Querying compliance data for matched assignments..." -PercentComplete 91 -Id 30
                Write-Host "   Querying compliance for $($validAssignments.Count) matched individual assignments..." -ForegroundColor Gray
                $matchedAssignmentIds = ($validAssignments | ForEach-Object {
                    $aid = "$($_.assignmentId)".Trim().ToLower()
                    if ($aid) { "'$aid'" }
                } | Where-Object { $_ }) -join ', '

                if ($matchedAssignmentIds) {
                    $ceIndCompQuery = @"
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| extend assignmentId = tolower(tostring(properties.policyAssignmentId))
| where assignmentId in~ ($matchedAssignmentIds)
| extend complianceState = tostring(properties.complianceState), resourceId = tostring(properties.resourceId)
| extend stateRank = case(complianceState == 'NonCompliant', 1, complianceState == 'Unknown', 2, complianceState == 'Exempt', 3, complianceState == 'Compliant', 4, 5)
| summarize arg_min(stateRank, complianceState) by resourceId, assignmentId
| summarize TotalResources = dcount(resourceId), CompliantCount = dcountif(resourceId, complianceState == 'Compliant'),
    NonCompliantCount = dcountif(resourceId, complianceState == 'NonCompliant'), ExemptCount = dcountif(resourceId, complianceState == 'Exempt')
    by assignmentId
"@
                    try {
                        $ceIndResults = @(Search-AzGraph -Query $ceIndCompQuery -First 1000 -UseTenantScope | Expand-AzGraphResult)
                        foreach ($item in $ceIndResults) {
                            $ceIndividualComplianceData[$item.assignmentId] = @{
                                NonCompliantCount = $item.NonCompliantCount; CompliantCount = $item.CompliantCount
                                ExemptCount = $item.ExemptCount; TotalResources = $item.TotalResources
                            }
                        }
                        Write-Host "   ✓ Retrieved compliance data for $($ceIndResults.Count) matched assignments" -ForegroundColor Green
                    } catch {
                        Write-Host "   ⚠️  Could not query individual compliance: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }

            # Display per-group coverage
            if ($ceGroupDefinitions.Count -gt 0) {
                Write-Progress -Activity "CE Compliance" -Status "Evaluating per-control group coverage..." -PercentComplete 93 -Id 30
                $uniqueCoveredGuids = [System.Collections.Generic.HashSet[string]]::new()
                $uniqueMissingGuids = [System.Collections.Generic.HashSet[string]]::new()
                $uniqueNonCompliantGuids = [System.Collections.Generic.HashSet[string]]::new()

                foreach ($group in ($ceGroupDefinitions | Sort-Object { if ($_.name) { $_.name } else { $_.Name } })) {
                    $gName = if ($group.name) { $group.name } elseif ($group.Name) { $group.Name } else { '' }
                    $gDisplay = if ($Global:CEPGroupFriendlyNames[$gName]) { $Global:CEPGroupFriendlyNames[$gName] }
                                elseif ($group.displayName -and $group.displayName -ne $gName) { $group.displayName } else { $gName }

                    # Collect policies in this group
                    $groupPolicies = @()
                    foreach ($refId in $ceRefIdToGroups.Keys) {
                        if ($ceRefIdToGroups[$refId] -contains $gName) {
                            $groupPolicies += @{ RefId = $refId; DefGuid = $ceRefIdToDefGuid[$refId] }
                        }
                    }
                    if ($groupPolicies.Count -eq 0) { continue }

                    $groupCovered = 0; $groupMissing = 0; $groupNonCompliant = 0
                    Write-Host "`n   ┌─ $gDisplay ($($groupPolicies.Count) policies)" -ForegroundColor Yellow

                    foreach ($gp in ($groupPolicies | Sort-Object { $policyDefDisplayNames[$_.DefGuid] ?? $_.RefId })) {
                        $displayName = if ($policyDefDisplayNames[$gp.DefGuid]) { $policyDefDisplayNames[$gp.DefGuid] } else { $gp.RefId }

                        if ($matchedCEPolicies.ContainsKey($gp.DefGuid)) {
                            $matched = $matchedCEPolicies[$gp.DefGuid]
                            $firstAssignment = $matched.Assignments[0]
                            $enfInfo = if ($firstAssignment.EnforcementMode -eq 'DoNotEnforce') { " (DoNotEnforce)" } else { "" }
                            $assignCount = $matched.Assignments.Count
                            $assignInfo = if ($assignCount -gt 1) { " [$assignCount assignments]" } else { "" }

                            $compInfo = ""
                            $aidLower = $firstAssignment.AssignmentId.ToLower()
                            if ($ceIndividualComplianceData.ContainsKey($aidLower)) {
                                $compData = $ceIndividualComplianceData[$aidLower]
                                if ($compData.NonCompliantCount -gt 0) {
                                    $compInfo = "Non-Compliant: $($compData.NonCompliantCount)"
                                    $groupNonCompliant++
                                }
                            }

                            if ($compInfo) {
                                Write-Host "   │  ✗ $displayName$enfInfo$assignInfo" -ForegroundColor Red
                                Write-Host "   │      $compInfo" -ForegroundColor DarkGray
                            } else {
                                Write-Host "   │  ✓ $displayName$enfInfo$assignInfo" -ForegroundColor Green
                            }
                            $groupCovered++
                            [void]$uniqueCoveredGuids.Add($gp.DefGuid)
                            if ($compInfo) { [void]$uniqueNonCompliantGuids.Add($gp.DefGuid) }

                            $status = if ($compInfo) { 'Assigned - Non-Compliant' } else { 'Assigned - Compliant' }
                            $nc = if ($ceIndividualComplianceData.ContainsKey($aidLower)) { $ceIndividualComplianceData[$aidLower].NonCompliantCount } else { 'N/A' }
                            $c  = if ($ceIndividualComplianceData.ContainsKey($aidLower)) { $ceIndividualComplianceData[$aidLower].CompliantCount } else { 'N/A' }
                            $ex = if ($ceIndividualComplianceData.ContainsKey($aidLower)) { $ceIndividualComplianceData[$aidLower].ExemptCount } else { 'N/A' }
                            $t  = if ($ceIndividualComplianceData.ContainsKey($aidLower)) { $ceIndividualComplianceData[$aidLower].TotalResources } else { 'N/A' }
                            [void]$cepExportData.Add([PSCustomObject]@{
                                'CE Control Group' = $gDisplay; 'Policy Reference' = $gp.RefId
                                'Policy Display Name' = $displayName; 'Status' = $status
                                'Non-Compliant Resources' = $nc; 'Compliant Resources' = $c
                                'Exempt Resources' = $ex; 'Total Resources' = $t
                                'Recommendation' = if ($firstAssignment.EnforcementMode -eq 'DoNotEnforce') { 'Enable enforcement' } elseif ($compInfo) { 'Remediate non-compliant resources' } else { 'Monitor compliance' }
                            })
                        } else {
                            Write-Host "   │  ✗ $displayName (NOT ASSIGNED)" -ForegroundColor Red
                            $groupMissing++
                            [void]$uniqueMissingGuids.Add($gp.DefGuid)
                            [void]$cepExportData.Add([PSCustomObject]@{
                                'CE Control Group' = $gDisplay; 'Policy Reference' = $gp.RefId
                                'Policy Display Name' = $displayName; 'Status' = 'Not Assigned'
                                'Non-Compliant Resources' = 'N/A'; 'Compliant Resources' = 'N/A'
                                'Exempt Resources' = 'N/A'; 'Total Resources' = 'N/A'
                                'Recommendation' = 'Assign this policy or assign the full CE initiative'
                            })
                        }
                    }

                    $color = if ($groupMissing -gt 0) { 'Red' } elseif ($groupNonCompliant -gt 0) { 'Yellow' } else { 'Green' }
                    Write-Host "   └─ Summary: ✓ $groupCovered assigned | ✗ $groupMissing missing$(if ($groupNonCompliant -gt 0) { " | ⚠ $groupNonCompliant non-compliant" })" -ForegroundColor $color
                }

                $uniqueMissingGuids.ExceptWith($uniqueCoveredGuids)
                Write-Progress -Activity "CE Compliance" -Status "Generating summary..." -PercentComplete 99 -Id 30
                Write-Host "`n   📊 OVERALL CE COVERAGE (individual assignments):" -ForegroundColor Cyan
                Write-Host "      Unique Policies in Initiative: $totalCEPolicies" -ForegroundColor White
                Write-Host "      Unique Policies Covered: $($uniqueCoveredGuids.Count) ($coveragePercent%)" -ForegroundColor $(if ($uniqueCoveredGuids.Count -gt 0) { 'Green' } else { 'Yellow' })
                Write-Host "      Unique Policies Not Covered: $($uniqueMissingGuids.Count)" -ForegroundColor $(if ($uniqueMissingGuids.Count -gt 0) { 'Red' } else { 'Green' })
                if ($uniqueNonCompliantGuids.Count -gt 0) {
                    Write-Host "      Policies with Non-Compliant Resources: $($uniqueNonCompliantGuids.Count)" -ForegroundColor Red
                }

                if ($uniqueMissingGuids.Count -gt 0) {
                    Write-Host "`n   💡 RECOMMENDATION:" -ForegroundColor Yellow
                    Write-Host "      Assign the full '$ceInitiativeDisplayName' initiative instead of individual policies." -ForegroundColor White
                    Write-Host "      $($uniqueMissingGuids.Count) unique CE policies are currently not covered by any assignment." -ForegroundColor White
                }
            }
        } else {
            # ══════════════════════════════════════════════════════════════
            # Initiative IS assigned — full compliance report
            # (proven logic from Get-CEComplianceReport.ps1)
            # ══════════════════════════════════════════════════════════════
            foreach ($a in $ceAssignments) {
                $enf = if ($a.enforcementMode -eq 'DoNotEnforce') { " (DoNotEnforce)" } else { "" }
                Write-Host "   ✓ $($a.displayName)$enf" -ForegroundColor Green
            }

            # ── Step 3: Query per-policy compliance via ARG ──
            Write-Progress -Activity "CE Compliance" -Status "Querying per-policy compliance..." -PercentComplete 25 -Id 30
            Write-Host "`n   Querying per-policy compliance..." -ForegroundColor Gray

            $ceAssignmentIdList = ($ceAssignments | ForEach-Object { "'$($_.assignmentId)'" }) -join ', '

            $ceComplianceQuery = @"
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| extend assignmentId = tolower(tostring(properties.policyAssignmentId))
| where assignmentId in~ ($ceAssignmentIdList)
| extend
    policyDefinitionReferenceId = tostring(properties.policyDefinitionReferenceId),
    policyDefinitionName        = tostring(properties.policyDefinitionName),
    complianceState = tostring(properties.complianceState),
    resourceId = tostring(properties.resourceId)
| where isnotempty(policyDefinitionReferenceId)
| summarize
    TotalResources   = dcount(resourceId),
    CompliantCount   = dcountif(resourceId, complianceState == 'Compliant'),
    NonCompliantCount = dcountif(resourceId, complianceState == 'NonCompliant'),
    ExemptCount      = dcountif(resourceId, complianceState == 'Exempt')
    by policyDefinitionReferenceId, policyDefinitionName
"@

            $ceComplianceResults = @()
            try {
                $ceComplianceResults = @(Search-AzGraph -Query $ceComplianceQuery -First 1000 -UseTenantScope | Expand-AzGraphResult)
                Write-Host "   ✓ Compliance data for $($ceComplianceResults.Count) evaluated policies" -ForegroundColor Green
            } catch {
                Write-Host "   ⚠️  Could not query compliance via ARG: $($_.Exception.Message)" -ForegroundColor Yellow
                try {
                    $ceComplianceResults = @(Search-AzGraph -Query $ceComplianceQuery -First 1000 | Expand-AzGraphResult)
                    Write-Host "   ✓ Fallback: Compliance data for $($ceComplianceResults.Count) evaluated policies" -ForegroundColor Green
                } catch {
                    Write-Host "   ⚠️  Fallback also failed: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }

            # Build dual hashtables: refId → compliance row AND policyGuid → compliance row
            $ceCompByRefId   = @{}
            $ceCompByDefName = @{}
            foreach ($r in $ceComplianceResults) {
                if ($r.policyDefinitionReferenceId) {
                    $ceCompByRefId[$r.policyDefinitionReferenceId] = $r
                }
                if ($r.policyDefinitionName) {
                    $ceCompByDefName[$r.policyDefinitionName.ToLower()] = $r
                }
            }

            # ── Step 4: Resolve policy display names — use batch cache, fallback to individual ──
            $allGuids = @($ceRefIdToDefGuid.Values | Select-Object -Unique)
            Write-Host "   Resolving $($allGuids.Count) policy display names..." -ForegroundColor Gray
            $policyDefDisplayNames = @{}
            $unresolvedGuids = [System.Collections.Generic.List[string]]::new()
            foreach ($guid in $allGuids) {
                if ($policyDefMetadata.ContainsKey($guid) -and $policyDefMetadata[$guid].DisplayName) {
                    $policyDefDisplayNames[$guid] = $policyDefMetadata[$guid].DisplayName
                } else {
                    [void]$unresolvedGuids.Add($guid)
                }
            }
            if ($unresolvedGuids.Count -gt 0) {
                Write-Host "   Resolving $($unresolvedGuids.Count) remaining names via API..." -ForegroundColor Gray
                $resolveIdx = 0
                foreach ($guid in $unresolvedGuids) {
                    $resolveIdx++
                    Write-Progress -Activity "CE Compliance" -Status "Resolving policy names ($resolveIdx/$($unresolvedGuids.Count))..." `
                        -PercentComplete ([math]::Min(30 + ([math]::Round($resolveIdx / [math]::Max($unresolvedGuids.Count,1) * 60)), 90)) -Id 30
                    try {
                        $def = Get-AzPolicyDefinition -Name $guid -ErrorAction SilentlyContinue
                        if ($def -and $def.DisplayName) { $policyDefDisplayNames[$guid] = $def.DisplayName }
                    } catch { }
                }
            }
            Write-Host "   ✓ Resolved $($policyDefDisplayNames.Count) / $($allGuids.Count) display names" -ForegroundColor Green

            # Cache resolved names for reuse by Invoke-CEPComplianceTests
            $Script:CachedPolicyDisplayNames = $policyDefDisplayNames

            # ── Step 5: Display compliance report grouped by control area ──
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host "  COMPLIANCE REPORT" -ForegroundColor Cyan
            Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

            $grandCompliant     = 0
            $grandNonCompliant  = 0
            $grandNotEvaluated  = 0
            $grandTotalPolicies = 0

            $sortedGroups = $ceGroupDefinitions | Sort-Object { if ($_.name) { $_.name } else { $_.Name } }

            foreach ($group in $sortedGroups) {
                $gName = if ($group.name) { $group.name } elseif ($group.Name) { $group.Name } else { '' }
                $gDisplay = if ($Global:CEPGroupFriendlyNames[$gName]) { $Global:CEPGroupFriendlyNames[$gName] }
                            elseif ($group.displayName -and $group.displayName -ne $gName) { $group.displayName } else { $gName }

                # Collect policies in this group
                $groupPolicies = @()
                foreach ($refId in $ceRefIdToGroups.Keys) {
                    if ($ceRefIdToGroups[$refId] -contains $gName) {
                        $groupPolicies += @{ RefId = $refId; DefGuid = $ceRefIdToDefGuid[$refId] }
                    }
                }
                if ($groupPolicies.Count -eq 0) { continue }

                $groupCompliant    = 0
                $groupNonCompliant = 0
                $groupNotEvaluated = 0
                $groupNonCompliantPolicies = 0

                Write-Host "`n   ┌─ $gDisplay ($($groupPolicies.Count) policies)" -ForegroundColor Yellow

                foreach ($gp in ($groupPolicies | Sort-Object { $policyDefDisplayNames[$_.DefGuid] ?? $_.RefId })) {
                    $name = if ($policyDefDisplayNames[$gp.DefGuid]) { $policyDefDisplayNames[$gp.DefGuid] } else { $gp.RefId }

                    # Primary lookup by refId, fallback to policy definition GUID
                    $comp = $null
                    if ($ceCompByRefId.ContainsKey($gp.RefId)) {
                        $comp = $ceCompByRefId[$gp.RefId]
                    } elseif ($ceCompByDefName.ContainsKey($gp.DefGuid)) {
                        $comp = $ceCompByDefName[$gp.DefGuid]
                    }

                    if ($comp) {
                        $nc    = [int]$comp.NonCompliantCount
                        $c     = [int]$comp.CompliantCount
                        $ex    = [int]$comp.ExemptCount
                        $total = [int]$comp.TotalResources

                        if ($nc -gt 0) {
                            Write-Host "   │  ✗ $name" -ForegroundColor Red
                            Write-Host "   │      Non-Compliant: $nc | Compliant: $c | Exempt: $ex | Total: $total" -ForegroundColor DarkGray
                            $groupNonCompliant += $nc
                            $groupCompliant += $c
                            $groupNonCompliantPolicies++
                            $state = 'Non-Compliant'
                        } else {
                            Write-Host "   │  ✓ $name" -ForegroundColor Green
                            Write-Host "   │      Compliant: $c | Exempt: $ex | Total: $total" -ForegroundColor DarkGray
                            $groupCompliant += $c
                            $state = 'Compliant'
                        }

                        [void]$cepExportData.Add([PSCustomObject]@{
                            'CE Control Group'          = $gDisplay
                            'Policy Reference'          = $gp.RefId
                            'Policy Display Name'       = $name
                            'Status'                    = $state
                            'Non-Compliant Resources'   = $nc
                            'Compliant Resources'       = $c
                            'Exempt Resources'          = $ex
                            'Total Resources'           = $total
                            'Recommendation'            = if ($nc -gt 0) { 'Remediate non-compliant resources' } else { 'Monitor compliance' }
                        })
                    } else {
                        # No ARG data — if evaluation has run, treat as compliant with 0 applicable resources
                        if ($ceComplianceResults.Count -gt 0) {
                            Write-Host "   │  ✓ $name" -ForegroundColor Green
                            Write-Host "   │      Compliant: 0 (No applicable resources)" -ForegroundColor DarkGray
                            $state = 'Compliant'
                        } else {
                            Write-Host "   │  ― $name (Not yet evaluated)" -ForegroundColor DarkGray
                            $groupNotEvaluated++
                            $state = 'Not Evaluated'
                        }

                        [void]$cepExportData.Add([PSCustomObject]@{
                            'CE Control Group'          = $gDisplay
                            'Policy Reference'          = $gp.RefId
                            'Policy Display Name'       = $name
                            'Status'                    = $state
                            'Non-Compliant Resources'   = 0
                            'Compliant Resources'       = 0
                            'Exempt Resources'          = 0
                            'Total Resources'           = 0
                            'Recommendation'            = if ($state -eq 'Not Evaluated') { 'Wait for policy evaluation or trigger a compliance scan' } else { 'No applicable resources — monitor for new deployments' }
                        })
                    }
                }

                # Group summary
                $color = if ($groupNonCompliantPolicies -gt 0) { 'Red' } elseif ($groupNotEvaluated -gt 0) { 'Yellow' } else { 'Green' }
                $ncPoliciesText = if ($groupNonCompliantPolicies -gt 0) { "$groupNonCompliantPolicies non-compliant policies" } else { "all compliant" }
                Write-Host "   └─ Summary: $ncPoliciesText | Resources — ✓ $groupCompliant  ✗ $groupNonCompliant  ― $groupNotEvaluated not evaluated" -ForegroundColor $color

                $grandCompliant    += $groupCompliant
                $grandNonCompliant += $groupNonCompliant
                $grandNotEvaluated += $groupNotEvaluated
                $grandTotalPolicies += $groupPolicies.Count
            }

            # ── Overall summary ──
            $totalEvaluated = $grandCompliant + $grandNonCompliant
            $ceComplianceScore = if ($totalEvaluated -gt 0) { [math]::Round(($grandCompliant / $totalEvaluated) * 100, 1) } else { 'N/A' }

            Write-Progress -Activity "CE Compliance" -Status "Generating compliance summary..." -PercentComplete 99 -Id 30
            Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host "  OVERALL SUMMARY" -ForegroundColor Cyan
            Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            $uniquePolicyCount = $ceRefIdToDefGuid.Keys.Count
            Write-Host "   Initiative          : $ceInitiativeDisplayName" -ForegroundColor White
            Write-Host "   Unique Policies     : $uniquePolicyCount" -ForegroundColor White
            Write-Host "   Policy-Group Entries: $grandTotalPolicies (policies appear in multiple control groups)" -ForegroundColor DarkGray
            Write-Host "   Compliant Resources : $grandCompliant" -ForegroundColor Green
            Write-Host "   Non-Compliant       : $grandNonCompliant" -ForegroundColor $(if ($grandNonCompliant -gt 0) { 'Red' } else { 'Green' })
            Write-Host "   Compliance Score    : $ceComplianceScore%" -ForegroundColor $(if ($ceComplianceScore -eq 'N/A') { 'Yellow' } elseif ([double]$ceComplianceScore -ge 90) { 'Green' } elseif ([double]$ceComplianceScore -ge 70) { 'Yellow' } else { 'Red' })

            if ($grandNonCompliant -gt 0) {
                Write-Host "`n   ⚠️  RECOMMENDED ACTIONS:" -ForegroundColor Yellow
                Write-Host "      1. Review non-compliant resources in Azure Policy compliance dashboard" -ForegroundColor White
                Write-Host "      2. Create remediation tasks for DeployIfNotExists/Modify policies" -ForegroundColor White
                Write-Host "      3. Update resource configurations to meet compliant state" -ForegroundColor White
                Write-Host "      4. Use policy exemptions for documented exceptions only" -ForegroundColor White
                Write-Host "      5. Reference: https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-uk-cyber-essentials-plus" -ForegroundColor White
            }

            if ($grandNotEvaluated -gt 0) {
                Write-Host "`n   ℹ️  Some policies have not been evaluated yet." -ForegroundColor Gray
                Write-Host "      Policy evaluation can take up to 24 hours for new assignments." -ForegroundColor Gray
                Write-Host "      Trigger an on-demand scan: Start-AzPolicyComplianceScan" -ForegroundColor Gray
            }
        }
    }

    Write-Progress -Activity "CE Compliance" -Status "Complete" -PercentComplete 100 -Id 30
    Write-Progress -Activity "CE Compliance" -Completed -Id 30

    # Export CE compliance to CSV if requested
    if ($ExportCEPCompliance) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $cepFileName = "CyberEssentialsPlus_Compliance_$timestamp.csv"
        $cepPath = Join-Path -Path (Get-Location) -ChildPath $cepFileName

        Write-Host "`n   📊 Exporting Cyber Essentials compliance report..." -ForegroundColor Cyan

        if ($cepExportData.Count -gt 0) {
            $cepExportData | Export-Csv -Path $cepPath -NoTypeInformation -Encoding UTF8
            Write-Host "   ✓ CE compliance report exported to: $cepPath" -ForegroundColor Green
            Write-Host "   Total records: $($cepExportData.Count)" -ForegroundColor Gray
        } else {
            Write-Host "   ⚠️  No compliance data to export." -ForegroundColor Yellow
            Write-Host "   Ensure the Cyber Essentials v3.1 initiative is assigned and evaluated." -ForegroundColor Gray
        }
    }
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
    
    Write-Progress -Activity "Exporting to CSV" -Status "Complete" -PercentComplete 100 -Id 2
    Write-Progress -Activity "Exporting to CSV" -Completed -Id 2
    
    Write-Host "✓ Policy assignments exported to: $csvPath" -ForegroundColor Green
} else {
    Write-Host "`nTo export results to CSV, use -Output CSV" -ForegroundColor Gray
}

# Export non-compliant resources if requested
if ($ExportNonCompliant) {
    Write-Host "`nQuerying non-compliant resources from Azure Resource Graph..." -ForegroundColor Cyan
    Write-Progress -Activity "Exporting Non-Compliant Resources" -Status "Querying ARG..." -PercentComplete 10 -Id 15

    # Build NC scope filter matching the main policy query filter
    $ncScopeFilter = ""
    if ($ManagementGroup) {
        $ncMg = $ManagementGroup -replace "'", "''"
        $ncScopeFilter = "| where policyAssignmentId contains '/providers/microsoft.management/managementgroups/$ncMg'"
    } elseif ($Subscription) {
        $ncSub = $Subscription -replace "'", "''"
        $ncScopeFilter = "| where resourceId contains '/subscriptions/$ncSub'"
    }

    $ncQuery = @"
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| extend
    complianceState = tostring(properties.complianceState),
    resourceId = tostring(properties.resourceId),
    policyAssignmentId = tolower(tostring(properties.policyAssignmentId)),
    policyAssignmentName = tostring(properties.policyAssignmentName),
    policyDefinitionId = tostring(properties.policyDefinitionId),
    policyDefinitionName = tostring(properties.policyDefinitionName),
    policyDefinitionReferenceId = tostring(properties.policyDefinitionReferenceId),
    policySetDefinitionId = tostring(properties.policySetDefinitionId)
| where complianceState == 'NonCompliant'
$ncScopeFilter
| project
    resourceId,
    resourceType = tostring(split(resourceId, '/')[6]) ,
    resourceName = tostring(split(resourceId, '/')[-1]),
    resourceGroup = tostring(split(resourceId, '/')[4]),
    subscriptionId = tostring(split(resourceId, '/')[2]),
    policyAssignmentId,
    policyAssignmentName,
    policyDefinitionId,
    policyDefinitionName,
    policyDefinitionReferenceId,
    policySetDefinitionId,
    complianceState
"@

    $ncResults = [System.Collections.Generic.List[object]]::new(1024)
    try {
        $ncRaw = @(Search-AzGraph -Query $ncQuery -First 1000 -UseTenantScope | Expand-AzGraphResult)
        $ncResults.AddRange($ncRaw)

        # Paginate if needed
        if ($ncRaw.Count -eq 1000) {
            Write-Host "  Paginating (>1000 results)..." -ForegroundColor Gray
            $skipToken = $ncRaw.SkipToken
            $ncPageCount = 1
            while ($skipToken) {
                $ncPageCount++
                Write-Progress -Activity "Exporting Non-Compliant Resources" -Status "Retrieving page $ncPageCount ($($ncResults.Count) entries so far)..." -PercentComplete ([math]::Min(10 + ($ncPageCount * 5), 35)) -Id 15
                $morePage = Search-AzGraph -Query $ncQuery -First 1000 -SkipToken $skipToken -UseTenantScope
                $pageRows = @($morePage | Expand-AzGraphResult)
                $ncResults.AddRange($pageRows)
                $skipToken = $morePage.SkipToken
                Write-Host "  Retrieved $($ncResults.Count) non-compliant resource entries..." -ForegroundColor Gray
            }
        }
        Write-Host "  ✓ Found $($ncResults.Count) non-compliant resource entries" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠️  Could not query non-compliant resources: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    if ($ncResults.Count -gt 0) {
        Write-Progress -Activity "Exporting Non-Compliant Resources" -Status "Resolving policy display names..." -PercentComplete 40 -Id 15

        # Resolve unique policy definition GUIDs to display names — use batch cache first
        $ncPolicyGuids = @($ncResults | ForEach-Object { $_.policyDefinitionName } | Select-Object -Unique)
        $ncDisplayNames = @{}
        $ncUnresolved = [System.Collections.Generic.List[string]]::new()
        foreach ($guid in $ncPolicyGuids) {
            $gLower = "$guid".ToLower()
            if ($policyDefMetadata.ContainsKey($gLower) -and $policyDefMetadata[$gLower].DisplayName) {
                $ncDisplayNames[$guid] = $policyDefMetadata[$gLower].DisplayName
            } else {
                [void]$ncUnresolved.Add($guid)
            }
        }
        if ($ncUnresolved.Count -gt 0) {
            $resolveIdx = 0
            $ncResolveTotal = $ncUnresolved.Count
            foreach ($guid in $ncUnresolved) {
                $resolveIdx++
                Write-Progress -Activity "Exporting Non-Compliant Resources" -Status "Resolving policy names ($resolveIdx/$ncResolveTotal)..." `
                    -PercentComplete ([math]::Min(40 + ([math]::Round($resolveIdx / [math]::Max($ncResolveTotal,1) * 40)), 80)) -Id 15
                try {
                    $def = Get-AzPolicyDefinition -Name $guid -ErrorAction SilentlyContinue
                    if ($def -and $def.DisplayName) { $ncDisplayNames[$guid] = $def.DisplayName }
                } catch { }
            }
        }

        # Also resolve initiative (policy set) display names — use batch cache first
        $ncSetGuids = @($ncResults | ForEach-Object {
            if ($_.policySetDefinitionId -match '/([^/]+)$') { $Matches[1] }
        } | Where-Object { $_ } | Select-Object -Unique)
        $ncSetDisplayNames = @{}
        $ncSetUnresolved = [System.Collections.Generic.List[string]]::new()
        foreach ($sGuid in $ncSetGuids) {
            $sLower = "$sGuid".ToLower()
            if ($initDefMetadata.ContainsKey($sLower) -and $initDefMetadata[$sLower].DisplayName) {
                $ncSetDisplayNames[$sGuid] = $initDefMetadata[$sLower].DisplayName
            } else {
                [void]$ncSetUnresolved.Add($sGuid)
            }
        }
        if ($ncSetUnresolved.Count -gt 0) {
            $setResolveIdx = 0
            $ncSetResolveTotal = $ncSetUnresolved.Count
            foreach ($sGuid in $ncSetUnresolved) {
                $setResolveIdx++
                Write-Progress -Activity "Exporting Non-Compliant Resources" -Status "Resolving initiative names ($setResolveIdx/$ncSetResolveTotal)..." `
                    -PercentComplete ([math]::Min(80 + ([math]::Round($setResolveIdx / [math]::Max($ncSetResolveTotal,1) * 15)), 95)) -Id 15
                try {
                    $setDef = Get-AzPolicySetDefinition -Name $sGuid -ErrorAction SilentlyContinue
                    if ($setDef -and $setDef.DisplayName) { $ncSetDisplayNames[$sGuid] = $setDef.DisplayName }
                } catch { }
            }
        }

        Write-Progress -Activity "Exporting Non-Compliant Resources" -Status "Building export data..." -PercentComplete 96 -Id 15

        # Build export rows
        $ncExportData = [System.Collections.Generic.List[object]]::new($ncResults.Count)
        foreach ($nc in $ncResults) {
            $policyDisplayName = if ($ncDisplayNames[$nc.policyDefinitionName]) { $ncDisplayNames[$nc.policyDefinitionName] } else { $nc.policyDefinitionName }
            $setGuid = if ($nc.policySetDefinitionId -match '/([^/]+)$') { $Matches[1] } else { '' }
            $initiativeDisplayName = if ($setGuid -and $ncSetDisplayNames[$setGuid]) { $ncSetDisplayNames[$setGuid] } elseif ($setGuid) { $setGuid } else { 'N/A (individual policy)' }

            [void]$ncExportData.Add([PSCustomObject]@{
                'Resource ID'            = $nc.resourceId
                'Resource Name'          = $nc.resourceName
                'Resource Type'          = $nc.resourceType
                'Resource Group'         = $nc.resourceGroup
                'Subscription ID'        = $nc.subscriptionId
                'Policy Name'            = $policyDisplayName
                'Policy Definition ID'   = $nc.policyDefinitionName
                'Initiative Name'        = $initiativeDisplayName
                'Policy Assignment Name' = $nc.policyAssignmentName
                'Policy Assignment ID'   = $nc.policyAssignmentId
            })
        }

        $ncTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $ncFileName = "NonCompliant_Resources_$ncTimestamp.csv"
        $ncPath = Join-Path -Path (Get-Location) -ChildPath $ncFileName
        $ncExportData | Export-Csv -Path $ncPath -NoTypeInformation -Encoding UTF8

        Write-Progress -Activity "Exporting Non-Compliant Resources" -Status "Complete" -PercentComplete 100 -Id 15
        Write-Progress -Activity "Exporting Non-Compliant Resources" -Completed -Id 15
        Write-Host "✓ Non-compliant resources exported to: $ncPath" -ForegroundColor Green
        Write-Host "  Total entries: $($ncExportData.Count) (a resource may appear multiple times if flagged by multiple policies)" -ForegroundColor Gray
    } else {
        Write-Progress -Activity "Exporting Non-Compliant Resources" -Status "Complete" -PercentComplete 100 -Id 15
        Write-Progress -Activity "Exporting Non-Compliant Resources" -Completed -Id 15
        Write-Host "  ✓ No non-compliant resources found — nothing to export." -ForegroundColor Green
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# YAML DELTA — compute delta data early so HTML report can use it
# ═══════════════════════════════════════════════════════════════════════════
$yamlDeltaData = $null
if ($DeltaYAML) {
    # Build scope filter for delta comparison — when running with -ManagementGroup or -Subscription,
    # filter previous YAML data to only include entries matching the current scope
    $deltaScope = ''
    if ($ManagementGroup) {
        $deltaScope = "/managementGroups/$ManagementGroup"
    } elseif ($Subscription) {
        $deltaScope = "/subscriptions/$Subscription"
    }
    $deltaExemptions = if ($exemptionData -and $exemptionData.Count -gt 0) { $exemptionData } else { @() }
    $yamlDeltaData = Get-YAMLDeltaData -PreviousYAMLPath $DeltaYAML -CurrentResults $(if ($results) { $results } else { @() }) -CurrentExemptions $deltaExemptions -ScopeFilter $deltaScope
}

# Generate HTML Report if requested
if ($ExportHTML) {
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Generating HTML Report..." -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    Write-Progress -Activity "Generating HTML Report" -Status "Preparing data..." -PercentComplete 10 -Id 40

    # Auto-query non-compliant resources if not already gathered
    if (-not $ncExportData -or $ncExportData.Count -eq 0) {
        Write-Progress -Activity "Generating HTML Report" -Status "Querying non-compliant resources..." -PercentComplete 20 -Id 40
        Write-Host "  Querying non-compliant resources for HTML report..." -ForegroundColor Gray

        # Build NC scope filter for HTML report query
        $ncHtmlFilter = ""
        if ($ManagementGroup) {
            $ncHtmlMg = $ManagementGroup -replace "'", "''"
            $ncHtmlFilter = "| where tolower(tostring(properties.policyAssignmentId)) contains '/providers/microsoft.management/managementgroups/$($ncHtmlMg.ToLower())'"
        } elseif ($Subscription) {
            $ncHtmlSub = $Subscription -replace "'", "''"
            $ncHtmlFilter = "| where tostring(properties.resourceId) contains '/subscriptions/$ncHtmlSub'"
        }

        $ncQuery = @"
policyresources
| where type == 'microsoft.policyinsights/policystates'
| where properties.complianceState == 'NonCompliant'
$ncHtmlFilter
| extend resourceId = tostring(properties.resourceId)
| extend policyAssignmentId = tostring(properties.policyAssignmentId)
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| extend policyAssignmentName = tostring(properties.policyAssignmentName)
| extend policyDefinitionName = tostring(properties.policyDefinitionName)
| extend policySetDefinitionName = tostring(properties.policySetDefinitionName)
| extend resourceType = tostring(properties.resourceType)
| extend resourceGroup = tostring(properties.resourceGroup)
| extend subscriptionId = tostring(properties.subscriptionId)
| project resourceId, policyAssignmentId, policyDefinitionId, policyAssignmentName,
          policyDefinitionName, policySetDefinitionName, resourceType, resourceGroup, subscriptionId
"@

        $ncExportData = [System.Collections.Generic.List[object]]::new(1024)
        try {
            $ncPageResults = Search-AzGraph -Query $ncQuery -First 1000 -UseTenantScope
            $ncPageData = Expand-AzGraphResult $ncPageResults
            $pageCount = 1

            while ($ncPageData -and $ncPageData.Count -gt 0) {
                $pct = [math]::Min(20 + $pageCount * 10, 60)
                Write-Progress -Activity "Generating HTML Report" -Status "Querying NC resources (page $pageCount)..." -PercentComplete $pct -Id 40

                foreach ($ncRes in $ncPageData) {
                    $resIdParts = ($ncRes.resourceId -split '/')
                    $resName = $resIdParts[-1]

                    # Resolve policy display name from cache
                    $policyGuid = $ncRes.policyDefinitionName
                    $policyLower = "$policyGuid".ToLower()
                    $policyDisplayName = if ($policyDefMetadata.ContainsKey($policyLower) -and $policyDefMetadata[$policyLower].DisplayName) {
                        $policyDefMetadata[$policyLower].DisplayName
                    } else { $policyGuid }

                    # Resolve initiative display name from cache
                    $initGuid = $ncRes.policySetDefinitionName
                    $initLower = "$initGuid".ToLower()
                    $initiativeDisplayName = if ($initGuid -and $initDefMetadata.ContainsKey($initLower) -and $initDefMetadata[$initLower].DisplayName) {
                        $initDefMetadata[$initLower].DisplayName
                    } elseif ($initGuid) { $initGuid } else { 'N/A (individual policy)' }

                    [void]$ncExportData.Add([PSCustomObject]@{
                        'Resource ID'            = $ncRes.resourceId
                        'Resource Name'          = $resName
                        'Resource Type'          = $ncRes.resourceType
                        'Resource Group'         = $ncRes.resourceGroup
                        'Subscription ID'        = $ncRes.subscriptionId
                        'Policy Name'            = $policyDisplayName
                        'Policy Definition ID'   = $ncRes.policyDefinitionId
                        'Initiative Name'        = $initiativeDisplayName
                        'Policy Assignment Name' = $ncRes.policyAssignmentName
                        'Policy Assignment ID'   = $ncRes.policyAssignmentId
                    })
                }

                if ($ncPageData.Count -lt 1000) { break }
                $skipToken = $ncPageResults.SkipToken
                if (-not $skipToken) { break }
                $ncPageResults = Search-AzGraph -Query $ncQuery -First 1000 -SkipToken $skipToken -UseTenantScope
                $ncPageData = Expand-AzGraphResult $ncPageResults
                $pageCount++
            }
            Write-Host "  Found $($ncExportData.Count) non-compliant resource entries" -ForegroundColor Gray
        }
        catch {
            Write-Host "  ⚠ Could not query non-compliant resources: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Progress -Activity "Generating HTML Report" -Status "Resolving display names..." -PercentComplete 65 -Id 40

    # Resolve any remaining GUIDs in NC data to display names
    if ($ncExportData -and $ncExportData.Count -gt 0) {
        $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

        # Collect unresolved policy GUIDs
        $unresolvedPolicyGuids = @($ncExportData | ForEach-Object { $_.'Policy Name' } | Where-Object { $_ -match $guidPattern } | Select-Object -Unique)
        $unresolvedInitGuids = @($ncExportData | ForEach-Object { $_.'Initiative Name' } | Where-Object { $_ -match $guidPattern } | Select-Object -Unique)

        # Batch resolve unresolved policy definition names
        $resolvedPolicies = @{}
        if ($unresolvedPolicyGuids.Count -gt 0) {
            Write-Host "  Resolving $($unresolvedPolicyGuids.Count) policy display names..." -ForegroundColor Gray
            foreach ($guid in $unresolvedPolicyGuids) {
                $gLower = $guid.ToLower()
                if ($policyDefMetadata.ContainsKey($gLower) -and $policyDefMetadata[$gLower].DisplayName) {
                    $resolvedPolicies[$guid] = $policyDefMetadata[$gLower].DisplayName
                } else {
                    try {
                        $def = Get-AzPolicyDefinition -Name $guid -ErrorAction SilentlyContinue
                        if ($def -and $def.DisplayName) { $resolvedPolicies[$guid] = $def.DisplayName }
                    } catch {}
                }
            }
        }

        # Batch resolve unresolved initiative names
        $resolvedInitiatives = @{}
        if ($unresolvedInitGuids.Count -gt 0) {
            Write-Host "  Resolving $($unresolvedInitGuids.Count) initiative display names..." -ForegroundColor Gray
            foreach ($guid in $unresolvedInitGuids) {
                $gLower = $guid.ToLower()
                if ($initDefMetadata.ContainsKey($gLower) -and $initDefMetadata[$gLower].DisplayName) {
                    $resolvedInitiatives[$guid] = $initDefMetadata[$gLower].DisplayName
                } else {
                    try {
                        $setDef = Get-AzPolicySetDefinition -Name $guid -ErrorAction SilentlyContinue
                        if ($setDef -and $setDef.DisplayName) { $resolvedInitiatives[$guid] = $setDef.DisplayName }
                    } catch {}
                }
            }
        }

        # Apply resolved names back to NC data
        if ($resolvedPolicies.Count -gt 0 -or $resolvedInitiatives.Count -gt 0) {
            $ncExportData = $ncExportData | ForEach-Object {
                $pName = $_.'Policy Name'
                $iName = $_.'Initiative Name'
                if ($resolvedPolicies.ContainsKey($pName)) { $_.'Policy Name' = $resolvedPolicies[$pName] }
                if ($resolvedInitiatives.ContainsKey($iName)) { $_.'Initiative Name' = $resolvedInitiatives[$iName] }
                $_
            }
            $resolvedTotal = $resolvedPolicies.Count + $resolvedInitiatives.Count
            Write-Host "  ✓ Resolved $resolvedTotal GUID(s) to display names" -ForegroundColor Green
        }
    }

    Write-Progress -Activity "Generating HTML Report" -Status "Building report..." -PercentComplete 70 -Id 40

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $htmlPath = Join-Path -Path (Get-Location) -ChildPath "PolicyAssessment_$timestamp.html"

    # Get tenant name for report header
    $htmlTenantName = ''
    try { $htmlTenantName = (Get-AzContext).Tenant.Id } catch {}

    $htmlResults = if ($results -and $results.Count -gt 0) { $results } else { @() }
    $htmlCompliance = if ($complianceData) { $complianceData } else { @{} }

    Export-HTMLReport `
        -PolicyResults $htmlResults `
        -ComplianceData $htmlCompliance `
        -CEPAssessment $cepAssessment `
        -CEPExportData $(if ($cepExportData) { $cepExportData } else { @() }) `
        -CEPTestResults $(if ($cepTestResults) { $cepTestResults } else { @() }) `
        -CEPPerScopeData $(if ($cepPerScopeData) { $cepPerScopeData } else { @() }) `
        -CEPPerScopeGroupData $(if ($cepPerScopeGroupData) { $cepPerScopeGroupData } else { @{} }) `
        -CEPPerScopeGroupRaw $(if ($cepPerScopeGroupRaw) { $cepPerScopeGroupRaw } else { @{} }) `
        -CEPRefIdToGroupDisplay $(if ($cepRefIdToGroupDisplay) { $cepRefIdToGroupDisplay } else { @{} }) `
        -NCExportData $(if ($ncExportData) { $ncExportData } else { @() }) `
        -ExemptionData $(if ($exemptionData -and $exemptionData.Count -gt 0) { $exemptionData } else { @() }) `
        -TenantName $htmlTenantName `
        -FilterLabel $filterLabel `
        -PolicyCount $policyCount `
        -InitiativeCount $classicInitCount `
        -RegulatoryCount $regulatoryInitCount `
        -OutputPath $htmlPath `
        -DataQuality $dataQuality `
        -ALZData $(if ($alzData) { $alzData } else { $null }) `
        -AssessmentFindings $assessmentFindings `
        -YAMLDeltaData $(if ($yamlDeltaData) { $yamlDeltaData } else { $null }) `
        -CostEvidenceRecords $(if ($costEvidenceRecords) { $costEvidenceRecords } else { @() })

    Write-Progress -Activity "Generating HTML Report" -Status "Complete" -PercentComplete 100 -Id 40
    Write-Progress -Activity "Generating HTML Report" -Completed -Id 40

    Write-Host "  ✓ HTML report generated: $htmlPath" -ForegroundColor Green

    # Open in default browser
    try {
        Start-Process $htmlPath
        Write-Host "  ✓ Report opened in default browser" -ForegroundColor Green
    }
    catch {
        Write-Host "  Open the file manually: $htmlPath" -ForegroundColor Yellow
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# YAML DATABASE EXPORT — full assessment snapshot for offline & delta use
# ═══════════════════════════════════════════════════════════════════════════
if ($ExportYAML) {
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Generating YAML Assessment Database..." -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    Write-Progress -Activity "Generating YAML Database" -Status "Building snapshot..." -PercentComplete 30 -Id 50

    $yamlTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $yamlPath = Join-Path -Path (Get-Location) -ChildPath "PolicyAssessment_$yamlTimestamp.yaml"

    # Get tenant info for YAML metadata
    $yamlTenantId = ''
    $yamlTenantName = ''
    try {
        $ctx = Get-AzContext
        $yamlTenantId = $ctx.Tenant.Id
        $yamlTenantName = $ctx.Tenant.Id
    } catch {}

    Write-Progress -Activity "Generating YAML Database" -Status "Exporting data..." -PercentComplete 60 -Id 50

    $exportedPath = Export-AssessmentYAML `
        -OutputPath $yamlPath `
        -PolicyResults $(if ($results) { $results } else { @() }) `
        -ComplianceData $(if ($complianceData) { $complianceData } else { @{} }) `
        -CEPAssessment $cepAssessment `
        -CEPExportData $(if ($cepExportData) { $cepExportData } else { @() }) `
        -CEPTestResults $(if ($cepTestResults) { $cepTestResults } else { @() }) `
        -CEPPerScopeData $(if ($cepPerScopeData) { $cepPerScopeData } else { @() }) `
        -CEPPerScopeGroupData $(if ($cepPerScopeGroupData) { $cepPerScopeGroupData } else { @{} }) `
        -CEPPerScopeGroupRaw $(if ($cepPerScopeGroupRaw) { $cepPerScopeGroupRaw } else { @{} }) `
        -CEPRefIdToGroupDisplay $(if ($cepRefIdToGroupDisplay) { $cepRefIdToGroupDisplay } else { @{} }) `
        -NCExportData $(if ($ncExportData) { $ncExportData } else { @() }) `
        -ExemptionData $(if ($exemptionData -and $exemptionData.Count -gt 0) { $exemptionData } else { @() }) `
        -TenantId $yamlTenantId `
        -TenantName $yamlTenantName `
        -FilterLabel $filterLabel `
        -PolicyCount $policyCount `
        -InitiativeCount $classicInitCount `
        -RegulatoryCount $regulatoryInitCount `
        -EnforcedCount $enforcedCount `
        -AuditOnlyCount $auditOnlyCount `
        -TotalNCResources $totalNCResources `
        -DataQuality $dataQuality `
        -AssessmentFindings $assessmentFindings `
        -ScriptVersion $ScriptVersion

    Write-Progress -Activity "Generating YAML Database" -Status "Complete" -PercentComplete 100 -Id 50
    Write-Progress -Activity "Generating YAML Database" -Completed -Id 50

    if ($exportedPath) {
        $yamlSize = [math]::Round((Get-Item $exportedPath).Length / 1KB, 1)
        Write-Host "  ✓ YAML database exported to: $exportedPath" -ForegroundColor Green
        Write-Host "    File size: ${yamlSize} KB | Assignments: $($results.Count)" -ForegroundColor Gray
        if ($ncExportData -and $ncExportData.Count -gt 0) {
            Write-Host "    Includes: $($ncExportData.Count) non-compliant resource records" -ForegroundColor Gray
        }
        if ($cepExportData -and $cepExportData.Count -gt 0) {
            Write-Host "    Includes: $($cepExportData.Count) CE+ compliance records" -ForegroundColor Gray
        }
        if ($exemptionData -and $exemptionData.Count -gt 0) {
            Write-Host "    Includes: $($exemptionData.Count) policy exemptions" -ForegroundColor Gray
        }
        Write-Host "    Use -DeltaYAML `"$exportedPath`" on next run for delta comparison" -ForegroundColor DarkGray
    }
}

# YAML Delta Comparison — console display (runs if -DeltaYAML was specified and delta was computed)
if ($DeltaYAML -and $yamlDeltaData) {
    Show-YAMLDelta -DeltaInfo $yamlDeltaData
}
