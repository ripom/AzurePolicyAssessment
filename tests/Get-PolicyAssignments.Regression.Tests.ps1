#Requires -Version 7.0
#Requires -Module @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    $RepoRoot = Split-Path $PSScriptRoot -Parent
    $ScriptPath = Join-Path $RepoRoot 'Get-PolicyAssignments.ps1'
    $ManifestPath = Join-Path $RepoRoot 'VERSION.json'
    $ReadmePath = Join-Path $RepoRoot 'README.md'
    $FixturePath = Join-Path $PSScriptRoot 'fixtures'
    $SnapshotPath = Join-Path $PSScriptRoot 'snapshots/critical-messages.html'

    $parseTokens = $null
    $parseErrors = $null
    $ScriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath,
        [ref]$parseTokens,
        [ref]$parseErrors
    )
    $ScriptParseErrors = @($parseErrors)
    $ScriptText = Get-Content $ScriptPath -Raw
    $Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
    $ReadmeText = Get-Content $ReadmePath -Raw
    $Assignments = Get-Content (Join-Path $FixturePath 'assignments.json') -Raw | ConvertFrom-Json
    $ComplianceScenarios = (Get-Content (Join-Path $FixturePath 'compliance-states.json') -Raw | ConvertFrom-Json).scenarios
    $ALZFixture = Get-Content (Join-Path $FixturePath 'alz-assets.json') -Raw | ConvertFrom-Json
    $Remediations = Get-Content (Join-Path $FixturePath 'remediations.json') -Raw | ConvertFrom-Json
    $CriticalMessageSnapshot = Get-Content $SnapshotPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $TopLevelFunctions = @($ScriptAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Parent -isnot [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true))

    function Get-FunctionSource {
        param([Parameter(Mandatory)][string]$Name)

        $functionAst = $TopLevelFunctions | Where-Object Name -EQ $Name | Select-Object -First 1
        if (-not $functionAst) { throw "Function '$Name' was not found in the script." }
        return $functionAst.Extent.Text
    }

    foreach ($functionName in @(
        'Resolve-AzureTenantSubscriptionContext',
        'Get-FallbackALZPolicies',
        'Get-PolicyRecommendation',
        'New-DataQuality',
        'New-CEPAssessment',
        'Resolve-CEPMappingSource',
        'Get-CEPScore',
        'Resolve-ComplianceAssessmentState',
        'Resolve-QuickAssessmentPosture',
        'Resolve-EffectivePolicyEffects',
        'Get-EffectivePolicyEffectCounts',
        'New-AssessmentFinding',
        'Get-AssessmentFindingId',
        'Resolve-RemediationEvidenceState',
        'New-RemediationEvidence',
        'New-AssessmentFindings',
        'New-CEPAssessmentFindings',
        'ConvertTo-AssessmentActions',
        'Resolve-ALZPolicyMatchState',
        'Resolve-ALZAssetState',
        'Find-ALZMatchingAssignments',
        'ConvertTo-ALZParameterSignature',
        'Test-ALZParameterCompatibility',
        'Test-CostEvidenceRecord',
        'Get-AzureRetailPriceEvidence',
        'Get-AzureCostManagementEvidence',
        'Export-HTMLReport',
        'Invoke-CEPInitiativeAssessment',
        'Invoke-CEPPlusTechnicalAssessment',
        'Invoke-CEPComplianceTests'
    )) {
        Invoke-Expression (Get-FunctionSource -Name $functionName)
    }
}

Describe 'Script and release contract' {
    It 'parses without PowerShell syntax errors' {
        $ScriptParseErrors | Should -BeNullOrEmpty
    }

    It 'keeps script, manifest, history, and README versions aligned' {
        $ScriptText | Should -Match ('\$ScriptVersion\s*=\s*"{0}"' -f [regex]::Escape($Manifest.version))
        $Manifest.history[0].version | Should -Be $Manifest.version
        $ReadmeText | Should -Match ('\*\*Version {0}\*\*' -f [regex]::Escape($Manifest.version))
    }

    It 'keeps all current documentation aligned to the release and supported CLI' {
        $outputGuide = Get-Content (Join-Path $RepoRoot 'OUTPUT-OPTIONS.md') -Raw
        $cepGuide = Get-Content (Join-Path $RepoRoot 'CYBER-ESSENTIALS-PLUS.md') -Raw
        $changelog = Get-Content (Join-Path $RepoRoot 'CHANGELOG.md') -Raw
        $releaseNotes = Get-Content (Join-Path $RepoRoot 'WHATS-NEW-v4.0.md') -Raw

        $outputGuide | Should -Match ('\*\*Version {0}\*\*' -f [regex]::Escape($Manifest.version))
        $cepGuide | Should -Match ('\*\*Script Version\*\*: {0}' -f [regex]::Escape($Manifest.version))
        $cepGuide | Should -Not -Match '(?m)^\.\\Get-PolicyAssignments\.ps1 .*\-(ShowCEPCompliance|RunCEPTests|ExportCEPCompliance)'
        $changelog | Should -Match ('## \[{0}\] - {1}' -f [regex]::Escape($Manifest.version), [regex]::Escape($Manifest.releaseDate))
        $releaseNotes | Should -Match '# What''s New in v4\.0'
    }

    It 'retains the official-source functions' {
        $functionNames = @($TopLevelFunctions.Name)
        @(
            'Get-ALZRecommendedPolicies',
            'Get-FallbackALZPolicies',
            'Get-PolicyRecommendation',
            'Export-HTMLReport'
        ) | ForEach-Object { $functionNames | Should -Contain $_ }
    }

    It 'contains no GitHub access tokens in repository text files' {
        $tokenPatterns = @(
            'github_pat_[A-Za-z0-9_]{20,}',
            'gh[pousr]_[A-Za-z0-9]{20,}'
        )
        $textExtensions = @('.ps1', '.md', '.json', '.yaml', '.yml', '.csv', '.txt', '.output')
        $findings = [System.Collections.Generic.List[string]]::new()

        Get-ChildItem $RepoRoot -Recurse -File | Where-Object {
            $_.Extension -in $textExtensions -and $_.FullName -notmatch '[\\/]\.git[\\/]'
        } | ForEach-Object {
            $content = Get-Content $_.FullName -Raw -ErrorAction Stop
            foreach ($pattern in $tokenPatterns) {
                foreach ($match in [regex]::Matches($content, $pattern)) {
                    if ($match.Value -notmatch '^(github_pat_|gh[pousr]_)?x+$') {
                        $relativePath = [System.IO.Path]::GetRelativePath($RepoRoot, $_.FullName)
                        if ($relativePath -notin $findings) { $findings.Add($relativePath) }
                    }
                }
            }
        }

        @($findings) | Should -BeNullOrEmpty -Because 'tokens must never be stored in source, documentation, fixtures, or tests'
    }

    It 'contains no hard-coded monetary amounts in product code or documentation' {
        $pricingPattern = '(?i)(?:[$€£]\s*\d+(?:\.\d+)?\s*(?:/|per\s)|\b(?:USD|EUR|GBP)\s*\d+(?:\.\d+)?)'
        $files = @('Get-PolicyAssignments.ps1') + @(
            Get-ChildItem $RepoRoot -Recurse -File -Filter '*.md' |
                Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
                ForEach-Object { [System.IO.Path]::GetRelativePath($RepoRoot, $_.FullName) }
        )
        $findings = @($files | Where-Object {
            (Get-Content (Join-Path $RepoRoot $_) -Raw) -match $pricingPattern
        })

        $findings | Should -BeNullOrEmpty -Because 'monetary amounts require live official evidence and timestamps'
    }
}

Describe 'Azure tenant subscription context' {
    It 'selects a subscription that belongs to the requested tenant instead of retaining a foreign context' {
        $resolution = Resolve-AzureTenantSubscriptionContext -TenantId 'tenant-a' `
            -CurrentContext ([PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = 'foreign-sub' } }) `
            -TenantSubscriptions @([PSCustomObject]@{ Id = 'tenant-sub'; Name = 'Tenant Subscription'; State = 'Enabled' })

        $resolution.State | Should -Be 'Resolved'
        $resolution.Subscription.Id | Should -Be 'tenant-sub'
        $resolution.Message | Should -Match 'another tenant'
    }

    It 'rejects an explicitly requested subscription outside the selected tenant' {
        $resolution = Resolve-AzureTenantSubscriptionContext -TenantId 'tenant-a' -RequestedSubscription 'foreign-sub' `
            -CurrentContext ([PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = 'foreign-sub' } }) `
            -TenantSubscriptions @([PSCustomObject]@{ Id = 'tenant-sub'; Name = 'Tenant Subscription'; State = 'Enabled' })

        $resolution.State | Should -Be 'RequestedSubscriptionUnavailable'
        $resolution.Subscription | Should -BeNullOrEmpty
    }

    It 'suggests the owning tenant when the selected tenant has no compatible subscription' {
        Mock Get-AzSubscription {
            [PSCustomObject]@{ Id = 'sandbox-sub'; Name = 'Sandbox'; TenantId = 'owner-tenant'; State = 'Enabled' }
        } -ParameterFilter { $SubscriptionId -eq 'sandbox-sub' }

        $resolution = Resolve-AzureTenantSubscriptionContext -TenantId 'selected-tenant' `
            -CurrentContext ([PSCustomObject]@{
                Tenant = [PSCustomObject]@{ Id = 'selected-tenant' }
                Subscription = [PSCustomObject]@{ Id = 'sandbox-sub'; Name = 'Sandbox' }
            }) -TenantSubscriptions @()

        $resolution.State | Should -Be 'NoCompatibleSubscription'
        $resolution.SuggestedTenantId | Should -Be 'owner-tenant'
        $resolution.CurrentSubscriptionName | Should -Be 'Sandbox'
    }

}

Describe 'Official ALZ source contract' {
    BeforeAll {
        $AlzSource = Get-FunctionSource -Name 'Get-ALZRecommendedPolicies'
    }

    It 'resolves latest releases and downloads the release archive' {
        $AlzSource | Should -Match '/releases/latest'
        $AlzSource | Should -Match 'zipball_url'
        $AlzSource | Should -Not -Match 'raw\.githubusercontent\.com/.*/main/'
    }

    It 'reads ALZ assignment assets and captures immutable definition IDs' {
        $AlzSource | Should -Match '\.alz_policy_assignment\.json'
        $AlzSource | Should -Match 'properties\.policyDefinitionId'
        $AlzSource | Should -Match 'ALZPolicyDefinitionIds'
        $AlzSource | Should -Match 'ALZSourceVersion'
    }

    It 'provides a non-empty offline fallback by category' {
        $fallback = Get-FallbackALZPolicies

        $fallback | Should -BeOfType [hashtable]
        $fallback.Keys.Count | Should -BeGreaterThan 0
        foreach ($category in $fallback.Keys) {
            @($fallback[$category]).Count | Should -BeGreaterThan 0
        }
    }

    It 'matches assessment assignments using official definition IDs' {
        $ScriptText | Should -Match '\$officialDefinitionId\s*=\s*if\s*\(\$asset\)\s*\{\s*\$asset\.DefinitionId\s*\}\s*else\s*\{\s*\$script:ALZPolicyDefinitionIds'
        $ScriptText | Should -Match "'Policy Definition ID'"
    }
}

Describe 'Evidence semantics regressions' {
    It 'does not infer framework scores when initiatives are not assigned' {
        $exportSource = Get-FunctionSource -Name 'Export-HTMLReport'

        $exportSource | Should -Match 'Get-AvailableFrameworkInitiatives'
        $exportSource | Should -Match 'Not measured'
        $exportSource | Should -Match 'No corresponding initiative assignment detected'
        $exportSource | Should -Match 'initDefMetadata'
    }

    It 'labels CE+ percentages as tool indicators, not certification thresholds' {
        $ScriptText | Should -Match 'tool indicator'
        $ScriptText | Should -Match 'authorised certification body'
        $ScriptText | Should -Not -Match 'certification target|80% target|Target: 80'
    }

    It 'requires explicit remediation evidence instead of declaring health or failure' {
        (Get-FunctionSource -Name 'Resolve-RemediationEvidenceState') | Should -Match 'TaskQuerySucceeded|RoleQuerySucceeded|ApplicableResourceCount'
        $ScriptText | Should -Match 'NotAssessed.*not a healthy or failed conclusion'
    }

    It 'distinguishes Audit from Deny in DoNotEnforce mode' {
        $audit = Get-PolicyRecommendation -PolicyName 'Audit encryption' -EffectType Audit -EnforcementMode DoNotEnforce -PolicyType Policy -Category Encryption
        $deny = Get-PolicyRecommendation -PolicyName 'Deny public IP' -EffectType Deny -EnforcementMode DoNotEnforce -PolicyType Policy -Category Network

        $audit.Recommendation | Should -Match 'does not turn an Audit effect into Deny'
        $audit.Recommendation | Should -Not -Match 'block non-compliant deployments'
        $deny.Recommendation | Should -Match 'safe deployment practices'
    }
}

Describe 'Azure assignment metadata contract' {
    It 'keeps the fields needed to explain effective assignments' {
        @(
            'definitionVersion',
            'createdOn',
            'identityType',
            'notScopes',
            'resourceSelectors',
            'overrides'
        ) | ForEach-Object {
            $ScriptText | Should -Match ([regex]::Escape($_))
        }
    }

    It 'keeps policy definition IDs in assignment results' {
        $ScriptText | Should -Match 'policyDefinitionId\s*=\s*properties\.policyDefinitionId'
        $ScriptText | Should -Match '''Policy Definition ID''\s*=\s*\$assignment\.policyDefinitionId'
    }

    It 'queries the operational remediation evidence fields' {
        @(
            'identityPrincipalId', 'roleDefinitionIds', 'microsoft.policyinsights/remediations',
            'failedDeployments', 'successfulDeployments', 'LastEvaluation',
            'TaskQuerySucceeded', 'RoleQuerySucceeded', 'ApplicableResourceCount'
        ) | ForEach-Object { $ScriptText | Should -Match ([regex]::Escape($_)) }
        $ScriptText | Should -Match "authorizationresources\s*\r?\n\| where type =~ 'microsoft\.authorization/roleassignments'"
    }
}

Describe 'Compliance data quality contract' {
    BeforeAll {
        $global:ScriptVersion = 'test'
        $HtmlPolicy = [PSCustomObject]@{
            'Assignment Name' = 'deny-public-ip'
            'Display Name' = 'Deny public IP addresses'
            'Policy Type' = 'Policy'
            'Category' = 'Network'
            'Effect Type' = 'Deny'
            'Enforcement Mode' = 'Default'
            'Compliance State' = 'NotEvaluated'
            'Compliant Resources' = 0
            'Non-Compliant Resources' = 0
            'Non-Compliant Policies' = 0
            'Total Resources' = 0
            'Exemptions' = 0
            'Security Impact' = 'High'
            'Cost Exposure' = 'Low'
            'Compliance Impact' = 'High'
            'Operational Overhead' = 'Medium'
            'Risk Level' = 'Low'
            'Scope Type' = 'Management Group'
            'Scope Name' = 'mg-test'
            'Policy Name' = '00000000-0000-0000-0000-000000000101'
            'Policy Definition ID' = '/providers/Microsoft.Authorization/policyDefinitions/00000000-0000-0000-0000-000000000101'
            'Scope' = '/providers/Microsoft.Management/managementGroups/mg-test'
        }
    }

    It 'maps a failed query to DataUnavailable with failure evidence' {
        $assessment = Resolve-ComplianceAssessmentState `
            -QuerySucceeded $false `
            -ErrorMessage 'Synthetic query failure'

        $assessment.State | Should -Be 'DataUnavailable'
        @($assessment.DataQuality.SuccessfulQueries).Count | Should -Be 0
        @($assessment.DataQuality.FailedQueries).Count | Should -Be 1
        $assessment.DataQuality.FailedQueries[0].Error | Should -Be 'Synthetic query failure'
    }

    It 'maps a successful query with zero evaluations to NotEvaluated' {
        $scenario = $ComplianceScenarios | Where-Object name -EQ 'zero-evaluations'
        $assessment = Resolve-ComplianceAssessmentState `
            -QuerySucceeded $scenario.querySucceeded `
            -QueryRecordCount @($scenario.states).Count `
            -EvaluatedResources $scenario.evaluatedResources `
            -CompliantResources $scenario.compliantResources `
            -NonCompliantResources $scenario.nonCompliantResources

        $assessment.State | Should -Be 'NotEvaluated'
        $assessment.DataQuality.TotalRecords | Should -Be 0
        @($assessment.DataQuality.SuccessfulQueries).Count | Should -Be 1
    }

    It 'maps evaluated compliant resources to EvaluatedCompliant' {
        $scenario = $ComplianceScenarios | Where-Object name -EQ 'all-compliant'
        $assessment = Resolve-ComplianceAssessmentState `
            -QuerySucceeded $scenario.querySucceeded `
            -QueryRecordCount @($scenario.states).Count `
            -EvaluatedResources $scenario.evaluatedResources `
            -CompliantResources $scenario.compliantResources `
            -NonCompliantResources $scenario.nonCompliantResources

        $assessment.State | Should -Be 'EvaluatedCompliant'
    }

    It 'maps evaluated non-compliant resources to EvaluatedNonCompliant' {
        $scenario = $ComplianceScenarios | Where-Object name -EQ 'non-compliant-resources'
        $assessment = Resolve-ComplianceAssessmentState `
            -QuerySucceeded $scenario.querySucceeded `
            -QueryRecordCount @($scenario.states).Count `
            -EvaluatedResources $scenario.evaluatedResources `
            -CompliantResources $scenario.compliantResources `
            -NonCompliantResources $scenario.nonCompliantResources

        $assessment.State | Should -Be 'EvaluatedNonCompliant'
    }

    It 'never reports a positive quick posture when compliance is unknown' {
        Resolve-QuickAssessmentPosture -ComplianceState NotEvaluated | Should -Be '⚪ Not Evaluated'
        Resolve-QuickAssessmentPosture -ComplianceState DataUnavailable | Should -Be '⚪ Data Unavailable'
    }

    It 'reports a positive quick posture only from evaluated evidence' {
        Resolve-QuickAssessmentPosture -ComplianceState EvaluatedCompliant | Should -Be '✅ Excellent'
        Resolve-QuickAssessmentPosture -ComplianceState EvaluatedNonCompliant -NonCompliantObservationCount 5 | Should -Be '🟢 Good'
    }

    It 'prevents positive HTML compliance findings when data is not evaluated' {
        $exportSource = Get-FunctionSource -Name 'Export-HTMLReport'

        $exportSource | Should -Match '\$hasEvaluatedCompliance.*EvaluatedCompliant.*EvaluatedNonCompliant'
        $exportSource | Should -Match 'if \(\$hasEvaluatedCompliance.*\$enforcedCount'
        $exportSource | Should -Match '<strong>Not evaluated</strong>'
        $exportSource | Should -Match '<strong>Compliance data unavailable</strong>'
        $exportSource | Should -Match '<strong>Remediation assessment unavailable</strong>'
    }

    It 'renders zero evaluations as Not evaluated without a green compliance finding' {
        $assessment = Resolve-ComplianceAssessmentState -QuerySucceeded $true -EvaluatedResources 0
        $quality = $assessment.DataQuality
        $quality | Add-Member AssessmentState $assessment.State
        $outputPath = Join-Path $TestDrive 'not-evaluated.html'

        Export-HTMLReport -PolicyResults @($HtmlPolicy) -PolicyCount 1 -OutputPath $outputPath -DataQuality $quality
        $html = Get-Content $outputPath -Raw

        $html | Should -Match '<strong>Not evaluated</strong>'
        $html | Should -Match 'Data Quality'
        $html | Should -Match '>N/A</div>'
        $html | Should -Match 'No resource posture conclusion is available'
        $html | Should -Not -Match '<strong>Strong Policy Posture</strong>'
        $html | Should -Not -Match '<strong>Zero Non-Compliance</strong>'
    }

    It 'allows a positive compliance finding only after evaluation' {
        $assessment = Resolve-ComplianceAssessmentState `
            -QuerySucceeded $true `
            -QueryRecordCount 1 `
            -EvaluatedResources 1 `
            -CompliantResources 1
        $quality = $assessment.DataQuality
        $quality | Add-Member AssessmentState $assessment.State
        $evaluatedPolicy = $HtmlPolicy.PSObject.Copy()
        $evaluatedPolicy.'Compliance State' = 'EvaluatedCompliant'
        $evaluatedPolicy.'Compliant Resources' = 1
        $evaluatedPolicy.'Total Resources' = 1
        $outputPath = Join-Path $TestDrive 'evaluated-compliant.html'

        Export-HTMLReport -PolicyResults @($evaluatedPolicy) -PolicyCount 1 -OutputPath $outputPath -DataQuality $quality
        $html = Get-Content $outputPath -Raw

        $html | Should -Match '<strong>Strong Policy Posture</strong>'
        $html | Should -Not -Match '<strong>Not evaluated</strong>'
    }

    It 'describes enforcement mode without claiming every Default assignment blocks or remediates' {
        $outputPath = Join-Path $TestDrive 'enforcement-wording.html'

        Export-HTMLReport -PolicyResults @($HtmlPolicy) -PolicyCount 1 -OutputPath $outputPath
        $html = Get-Content $outputPath -Raw

        $html | Should -Match 'Behavior depends on effect: Deny blocks, Audit reports, and DINE/Modify can remediate.'
        $html | Should -Not -Match 'actively preventing non-compliant deployments or auto-remediating'
        $html | Should -Not -Match 'zero NC resources to reduce evaluation overhead'
    }

    It 'labels ALZ ratings and enforcement-gap counts as tool-specific and scoped' {
        $exportSource = Get-FunctionSource -Name 'Export-HTMLReport'

        $exportSource | Should -Match 'Tool Coverage Indicator'
        $exportSource | Should -Match 'Not an official ALZ maturity threshold'
        $exportSource | Should -Match 'High-Security Gaps'
        $exportSource | Should -Match 'Priority Enforcement Gaps'
        $exportSource | Should -Match 'High/Medium security-impact assignments'
    }

    It 'renders priority enforcement gaps as a subset of all DoNotEnforce assignments' {
        $priorityPolicy = $HtmlPolicy.PSObject.Copy()
        $priorityPolicy.'Assignment Name' = 'priority-gap'
        $priorityPolicy | Add-Member -NotePropertyName 'Assignment ID' -NotePropertyValue '/assignments/priority-gap'
        $priorityPolicy.'Display Name' = 'Priority enforcement gap'
        $priorityPolicy.'Enforcement Mode' = 'DoNotEnforce'
        $priorityPolicy.'Security Impact' = 'Medium'
        $lowPolicy = $HtmlPolicy.PSObject.Copy()
        $lowPolicy.'Assignment Name' = 'low-gap'
        $lowPolicy | Add-Member -NotePropertyName 'Assignment ID' -NotePropertyValue '/assignments/low-gap'
        $lowPolicy.'Display Name' = 'Low enforcement disabled assignment'
        $lowPolicy.'Enforcement Mode' = 'DoNotEnforce'
        $lowPolicy.'Security Impact' = 'Low'
        $outputPath = Join-Path $TestDrive 'priority-enforcement-gaps.html'

        Export-HTMLReport -PolicyResults @($priorityPolicy, $lowPolicy) -PolicyCount 2 -OutputPath $outputPath
        $html = Get-Content $outputPath -Raw
        $architectureDetail = [regex]::Match($html, '<section id="sec-architecture".*?</section>', 'Singleline').Value
        $securityDetail = [regex]::Match($html, '<section id="sec-security".*?</section>', 'Singleline').Value

        $html | Should -Match 'Priority Enforcement Gaps \(1 High/Medium security-impact assignments\)'
        $html | Should -Match 'risk-prioritised subset of 2 total DoNotEnforce assignments'
        $securityDetail | Should -Match 'id="enforcement-gap-table"|Priority enforcement gap'
        $architectureDetail | Should -Not -Match 'id="enforcement-gap-table"'
        $html | Should -Not -Match 'Enforcement Gaps \(1 assignments in DoNotEnforce mode\)'
    }

    It 'labels cost and scope architecture conclusions as evidence-limited' {
        $exportSource = Get-FunctionSource -Name 'Export-HTMLReport'

        $exportSource | Should -Match 'Low/Medium/High heuristic'
        $exportSource | Should -Match 'it is not measured spend'
        $exportSource | Should -Match 'rather than a universal target'
        $exportSource | Should -Not -Match 'A healthy architecture assigns policies at the'
    }

    It 'omits every control-balance message when its numeric condition is false' {
        $effects = @('Deny', 'Deny', 'Deny', 'Deny', 'Audit', 'Audit', 'Audit', 'Audit', 'DeployIfNotExists', 'DeployIfNotExists')
        $balancedPolicies = @(for ($index = 0; $index -lt $effects.Count; $index++) {
            $policy = $HtmlPolicy.PSObject.Copy()
            $policy.'Assignment Name' = "balanced-$index"
            $policy.'Display Name' = "Balanced policy $index"
            $policy.'Effect Type' = $effects[$index]
            $policy.'Policy Name' = "balanced-definition-$index"
            $policy
        })
        $outputPath = Join-Path $TestDrive 'balanced-controls.html'

        Export-HTMLReport -PolicyResults $balancedPolicies -PolicyCount $balancedPolicies.Count -OutputPath $outputPath
        $html = Get-Content $outputPath -Raw

        $html | Should -Not -Match '<strong>Detection-heavy</strong>'
        $html | Should -Not -Match '<strong>Low prevention</strong>'
        $html | Should -Not -Match '<strong>Low remediation</strong>'
        $html | Should -Not -Match '<strong>Disabled policies present</strong>'
        $html | Should -Match 'No control-balance threshold findings were triggered.'
    }

    It 'renders only the control-balance messages whose thresholds are true' {
        $effects = @('Audit', 'Audit', 'Audit', 'Audit', 'Audit', 'Audit', 'Deny', 'Deny', 'DeployIfNotExists', 'DeployIfNotExists')
        $detectionHeavyPolicies = @(for ($index = 0; $index -lt $effects.Count; $index++) {
            $policy = $HtmlPolicy.PSObject.Copy()
            $policy.'Assignment Name' = "detection-heavy-$index"
            $policy.'Display Name' = "Detection-heavy policy $index"
            $policy.'Effect Type' = $effects[$index]
            $policy.'Policy Name' = "detection-heavy-definition-$index"
            $policy
        })
        $outputPath = Join-Path $TestDrive 'detection-heavy-controls.html'

        Export-HTMLReport -PolicyResults $detectionHeavyPolicies -PolicyCount $detectionHeavyPolicies.Count -OutputPath $outputPath
        $html = Get-Content $outputPath -Raw

        $html | Should -Match '<strong>Detection-heavy</strong>'
        $html | Should -Match '<strong>Low prevention</strong>'
        $html | Should -Not -Match '<strong>Low remediation</strong>'
        $html | Should -Not -Match '<strong>Disabled policies present</strong>'
    }

    It 'renders low remediation only below its threshold' {
        $effects = @('Audit', 'Audit', 'Audit', 'Audit', 'Audit', 'Deny', 'Deny', 'Deny', 'Deny', 'DeployIfNotExists')
        $lowRemediationPolicies = @(for ($index = 0; $index -lt $effects.Count; $index++) {
            $policy = $HtmlPolicy.PSObject.Copy()
            $policy.'Assignment Name' = "low-remediation-$index"
            $policy.'Display Name' = "Low-remediation policy $index"
            $policy.'Effect Type' = $effects[$index]
            $policy.'Policy Name' = "low-remediation-definition-$index"
            $policy
        })
        $outputPath = Join-Path $TestDrive 'low-remediation-controls.html'

        Export-HTMLReport -PolicyResults $lowRemediationPolicies -PolicyCount $lowRemediationPolicies.Count -OutputPath $outputPath
        $html = Get-Content $outputPath -Raw

        $html | Should -Match '<strong>Low remediation</strong>'
        $html | Should -Not -Match '<strong>Detection-heavy</strong>'
        $html | Should -Not -Match '<strong>Low prevention</strong>'
    }

    It 'renders deterministic findings as fact interpretation verification and action with badges' {
        $finding = New-AssessmentFinding `
            -Id 'F-REPORT-0000000001' -Severity Medium -Category 'Cost Exposure' `
            -Title 'Synthetic deterministic fact' -Evidence @{ Count = 1 } `
            -Recommendation 'Review the measured condition.' `
            -VerificationSteps @('Verify the source record.') `
            -Source 'Deterministic cost-impact heuristic' -Confidence Medium
        $outputPath = Join-Path $TestDrive 'structured-findings.html'

        Export-HTMLReport -PolicyResults @($HtmlPolicy) -PolicyCount 1 -OutputPath $outputPath -AssessmentFindings @($finding)
        $html = Get-Content $outputPath -Raw

        $html | Should -Match '<span class="badge status-warn">Confidence: Medium</span>'
        $html | Should -Match '<span class="badge status-warn">Data quality: Derived</span>'
        $html | Should -Match '<strong>Fact:</strong> Synthetic deterministic fact'
        $html | Should -Match '<strong>Interpretation:</strong>'
        $html | Should -Match '<strong>Verify:</strong> Verify the source record.'
        $html | Should -Match '<strong>Action:</strong> Review the measured condition.'
    }

    It 'uses current enforcement terminology no static prices and the actual section count' {
        $outputPath = Join-Path $TestDrive 'report-language.html'

        Export-HTMLReport -PolicyResults @($HtmlPolicy) -PolicyCount 1 -OutputPath $outputPath
        $html = Get-Content $outputPath -Raw

        $html | Should -Match 'organised into 7 sections: 7 core sections'
        ([regex]::Matches($html, '<section id="sec-')).Count | Should -Be 7
        $html | Should -Not -Match 'href="#sec-alz"'
        $html | Should -Not -Match '(?i)audit-only|audit only'
        $html | Should -Not -Match '(?i)\$?15/server/month|\$?2\.76/GB'
        $html | Should -Match 'Enforcement disabled \(DoNotEnforce\)'
    }

    It 'renders five audience pages with a unified summary and preserves raw evidence' {
        $outputPath = Join-Path $TestDrive 'progressive-disclosure.html'
        $nonCompliantPolicy = $HtmlPolicy.PSObject.Copy()
        $nonCompliantPolicy.'Non-Compliant Resources' = 1
        $nonCompliantPolicy.'Total Resources' = 1

        Export-HTMLReport -PolicyResults @($nonCompliantPolicy) -PolicyCount 1 -OutputPath $outputPath
        $html = Get-Content $outputPath -Raw
        $summaryLead = [regex]::Match($html, '<section id="page-summary".*?</section>', 'Singleline').Value
        $csaLead = [regex]::Match($html, '<section id="page-csa".*?</section>', 'Singleline').Value
        $engineerLead = [regex]::Match($html, '<section id="page-engineer".*?</section>', 'Singleline').Value
        $evidenceLead = [regex]::Match($html, '<section id="page-evidence".*?</section>', 'Singleline').Value
        $findingsDetail = [regex]::Match($html, '<section id="sec-findings".*?</section>', 'Singleline').Value
        $engineeringDetail = [regex]::Match($html, '<section id="sec-engineering".*?</section>', 'Singleline').Value
        $architectureDetail = [regex]::Match($html, '<section id="sec-architecture".*?</section>', 'Singleline').Value
        $securityDetail = [regex]::Match($html, '<section id="sec-security".*?</section>', 'Singleline').Value
        $costDetail = [regex]::Match($html, '<section id="sec-cost".*?</section>', 'Singleline').Value

        @('Summary', 'CSA / Architect', 'Engineer', 'Evidence', 'Methodology') | ForEach-Object {
            $html | Should -Match ">$([regex]::Escape($_))</a>"
        }
        $html | Should -Not -Match '>Overview</a>|>Executive</a>'
        ([regex]::Matches($html, 'class="report-page page-lead(?: active)?" data-report-page')).Count | Should -Be 5
        $html | Should -Match '<section id="page-summary" class="report-page page-lead active" data-report-page data-page-group="page-summary">'
        $html | Should -Match '<section id="page-evidence" class="report-page page-lead" data-report-page data-page-group="page-evidence">'
        $html | Should -Match '<div class="compact-panel"><h3>Priority Risks</h3>'
        $html | Should -Match '<div class="compact-panel"><h3>Priority Actions</h3>'
        $html | Should -Match '<div class="header-main">'
        $html | Should -Match '<div class="meta" aria-label="Report metadata">'
        $html | Should -Match 'header \{[^}]*padding: 14px 20px;'
        $html | Should -Match 'header \.meta \{[^}]*flex-wrap: nowrap;[^}]*white-space: nowrap;[^}]*overflow-x: auto;'
        $html | Should -Not -Match 'header \.subtitle, header \.meta \{ display: none; \}'
        $html | Should -Match 'grid-template-columns: repeat\(5, minmax\(0, 1fr\)\);'
        ([regex]::Matches($html, 'data-page-group="page-summary"')).Count | Should -Be 1
        $html | Should -Match '<section id="sec-findings" class="report-page" data-report-page data-page-group="page-engineer">'
        $findingsDetail | Should -Match '<h2>Prioritised Findings</h2>|Actionable deterministic findings'
        $findingsDetail | Should -Match '<details class="report-disclosure depth-2" id="details-key-findings">\s*<summary>Key Findings &amp; Risks'
        $findingsDetail | Should -Not -Match '<details class="report-disclosure depth-2" id="details-key-findings"[^>]* open>'
        $html | Should -Match '<section id="sec-engineering" class="report-page" data-report-page data-page-group="page-engineer">'
        $html | Should -Match '<section id="sec-security" class="report-page" data-report-page data-page-group="page-engineer">'
        $html | Should -Match '<section id="sec-recommendations" class="report-page" data-report-page data-page-group="page-engineer">'
        $architectureDetail | Should -Match 'Scope Hierarchy Model|Control Type Balance|Policy Category Distribution|Scope Coverage Analysis'
        $architectureDetail | Should -Not -Match 'enforcement-gap-table|All Policy Assignments'
        $engineeringDetail | Should -Match 'All Policy Assignments|Non-Compliant Resources|id="cost-table"'
        $engineeringDetail | Should -Not -Match 'Assignments by Scope|Effect Type Distribution|Policy Category Distribution'
        $securityDetail | Should -Match 'Security Action Inventory|Risk-Rated Policy Table'
        $costDetail | Should -Match 'Cost Governance|Official Monetary Evidence'
        $costDetail | Should -Not -Match 'id="cost-table"|Policies with Cost/Operational Impact'
        $html | Should -Not -Match 'audiencePlacement|appendChild\(section\)|page-detail-host|host-engineer|host-evidence'
        $html | Should -Not -Match "'host-evidence': \[[^\]]*'sec-findings'"
        $summaryLead | Should -Match '<h2>Executive Summary</h2>'
        $summaryLead | Should -Match '<h3>What Is Happening</h3>'
        $summaryLead | Should -Match '<h3>If No Action Is Taken</h3>'
        $summaryLead | Should -Match '<h3>If Action Is Taken</h3>'
        $summaryLead | Should -Match '<h3>Leadership Decisions Required</h3>'
        $html | Should -Match '<div class="card-label">Critical Findings</div>'
        $html | Should -Not -Match '<div class="card-label">Tool Risk Indicator</div>'
        ([regex]::Matches($summaryLead, '<div class="card ')).Count | Should -Be 5
        $summaryLead | Should -Match 'Assessment Outcome|Affected Resources|Affected Subscriptions|Critical Findings|Evidence Status'
        $summaryLead | Should -Not -Match 'No Violations Observed|Assignments in Scope|Assessment Status|Data Quality'
        ([regex]::Matches($csaLead, '<div class="card ')).Count | Should -Be 4
        ([regex]::Matches($engineerLead, '<div class="card ')).Count | Should -Be 4
        ([regex]::Matches($evidenceLead, '<div class="card ')).Count | Should -Be 4
        $csaLead | Should -Not -Match '<div class="card-label">Assignments</div>'
        $engineerLead | Should -Not -Match 'Critical Remediation Actions|High-Priority Actions'
        $engineerLead | Should -Match 'Affected Resource Types|High-Security Enforcement Gaps'
        $evidenceLead | Should -Not -Match '<div class="card-label">Assignments</div>|<div class="card-label">Resource Records</div>'
        $evidenceLead | Should -Match 'Evidence Records|Successful Sources|Failed Sources'
        $findingsDetail | Should -Not -Match '<div class="summary-cards">|class="big-num"'
        $html | Should -Match 'function showPage\(pageId, updateHash = true\)'
        $html | Should -Match 'window.addEventListener\(''hashchange'', routeHash\)'
        $html | Should -Not -Match 'class="audience-nav"'
        ([regex]::Matches($html, '<details class="section-disclosure">')).Count | Should -Be 6
        $html | Should -Not -Match '<details class="section-disclosure" open>'
        $html | Should -Match '<details class="report-disclosure depth-2" id="details-findings-nc"'
        $html | Should -Not -Match '<details class="report-disclosure depth-2" id="details-findings-nc"[^>]* open>'
        $html | Should -Match 'details > \* \{ display: block !important; \}'
        $html | Should -Match 'All Policy Assignments \(1\)'
        $html | Should -Match '<table id="policies-table">'
        $html | Should -Match '<details class="report-disclosure depth-3 disclaimer-disclosure">'
        $html | Should -Not -Match '<strong>Assessment limitations</strong>'
        $html | Should -Match '<details class="guide-panel report-page" data-report-page data-page-group="page-methodology">'
        $html | Should -Match '<details class="report-disclosure depth-3 glossary report-page" data-report-page data-page-group="page-methodology">'
        (Get-FunctionSource -Name 'Export-HTMLReport') | Should -Not -Match '<details[^>]* open>'
    }

    It 'labels assignment non-compliance and aggregate risk without implying a compliance score' {
        $outputPath = Join-Path $TestDrive 'metric-semantics.html'
        $cleanPolicy = $HtmlPolicy.PSObject.Copy()
        $nonCompliantPolicy = $HtmlPolicy.PSObject.Copy()
        $nonCompliantPolicy.'Assignment Name' = 'non-compliant-assignment'
        $nonCompliantPolicy.'Display Name' = 'Non-compliant assignment'
        $nonCompliantPolicy.'Non-Compliant Resources' = 3
        $nonCompliantPolicy.'Total Resources' = 3
        $nonCompliantPolicy.'Risk Level' = 'High'

        Export-HTMLReport -PolicyResults @($cleanPolicy, $nonCompliantPolicy) -PolicyCount 2 -OutputPath $outputPath `
            -DataQuality ([PSCustomObject]@{ AssessmentState = 'EvaluatedNonCompliant'; SuccessfulQueries = @('PolicyStates'); FailedQueries = @(); TotalRecords = 3; Timestamp = '2026-07-16T00:00:00Z'; FallbackUsed = $false })
        $html = Get-Content $outputPath -Raw
        $summaryLead = [regex]::Match($html, '<section id="page-summary".*?</section>', 'Singleline').Value

        $summaryLead | Should -Match '<div class="card-num executive-outcome">Action required</div><div class="card-label">Assessment Outcome</div>'
        $summaryLead | Should -Match '<div class="card-num executive-evidence">Evaluated</div><div class="card-label">Evidence Status</div>'
        $summaryLead | Should -Not -Match '>EvaluatedNonCompliant</div>|No Violations Observed|Assignments Without Observed Violations|>50%</div>'
        $html | Should -Match '<div class="rating-badge [^"]+" title="Tool risk indicator based on [^"]+; not an official compliance or certification rating">'
        $html | Should -Not -Match '<div class="card-label">Tool Risk Indicator</div>'
        $html | Should -Match '1 high-risk assignment and 0 unique affected resources'
        $html | Should -Not -Match 'Assignment Compliance Signal'
        $html | Should -Not -Match '<div class="card-label">Risk Level</div>'
    }

    It 'groups repeated subscription findings in the Summary' {
        $outputPath = Join-Path $TestDrive 'grouped-summary-findings.html'
        $resourceCounts = @(10, 12, 16, 20)
        $policies = @(0..3 | ForEach-Object {
            $subscriptionId = "00000000-0000-0000-0000-00000000010$_"
            $policy = $HtmlPolicy.PSObject.Copy()
            $policy.'Assignment Name' = "asc-default-$_"
            $policy | Add-Member -NotePropertyName 'Assignment ID' -NotePropertyValue "/subscriptions/$subscriptionId/providers/Microsoft.Authorization/policyAssignments/asc-default"
            $policy.'Display Name' = "ASC Default (subscription: $subscriptionId)"
            $policy.'Scope' = "/subscriptions/$subscriptionId"
            $policy.'Scope Type' = 'Subscription'
            $policy.'Scope Name' = "Subscription $_"
            $policy.'Non-Compliant Resources' = $resourceCounts[$_]
            $policy.'Total Resources' = $resourceCounts[$_]
            $policy.'Risk Level' = 'High'
            $policy
        })

        Export-HTMLReport -PolicyResults $policies -PolicyCount 4 -OutputPath $outputPath `
            -DataQuality ([PSCustomObject]@{ AssessmentState = 'EvaluatedNonCompliant'; SuccessfulQueries = @('PolicyStates'); FailedQueries = @(); TotalRecords = 58; Timestamp = '2026-07-17T00:00:00Z'; FallbackUsed = $false })
        $html = Get-Content $outputPath -Raw
        $summaryLead = [regex]::Match($html, '<section id="page-summary".*?</section>', 'Singleline').Value
        $topFindings = [regex]::Match($summaryLead, '<div class="compact-panel"><h3>Priority Risks</h3>.*?</div>', 'Singleline').Value
        $priorityActions = [regex]::Match($summaryLead, '<div class="compact-panel"><h3>Priority Actions</h3>.*?</div>', 'Singleline').Value
        $engineerLead = [regex]::Match($html, '<section id="page-engineer".*?</section>', 'Singleline').Value

        ([regex]::Matches($topFindings, 'ASC Default')).Count | Should -Be 1
        $topFindings | Should -Match 'ASC Default &middot; 4 subscriptions &middot; 58 affected resources'
        $topFindings | Should -Not -Match '00000000-0000-0000-0000-00000000010[0-3]'
        ([regex]::Matches($priorityActions, 'ASC Default')).Count | Should -Be 1
        $priorityActions | Should -Match 'across 4 subscriptions \(58 affected resources\)'
        $priorityActions | Should -Not -Match '00000000-0000-0000-0000-00000000010[0-3]'
        $engineerLead | Should -Match '00000000-0000-0000-0000-00000000010[0-3]'
    }

    It 'summarizes initiative risk concentration on the CSA page' {
        $outputPath = Join-Path $TestDrive 'csa-initiative-summary.html'
        $initiative = $HtmlPolicy.PSObject.Copy()
        $initiative.'Policy Type' = 'Initiative'
        $initiative.'Display Name' = 'Critical platform initiative'
        $initiative.'Risk Level' = 'High'

        Export-HTMLReport -PolicyResults @($initiative) -PolicyCount 0 -InitiativeCount 1 -OutputPath $outputPath
        $html = Get-Content $outputPath -Raw

        $html | Should -Match '<div class="card-num">1</div><div class="card-label">High-Risk Initiative Assignments</div>'
        $html | Should -Not -Match '<div class="card-label">Critical Initiatives</div>'
        $html | Should -Match '<strong>Initiatives:</strong> Critical platform initiative'
    }

    It 'summarizes every assigned and measured compliance result without inferring unevaluated standards' {
        $outputPath = Join-Path $TestDrive 'executive-compliance-summary.html'
        $pciRoot = $HtmlPolicy.PSObject.Copy()
        $pciRoot.'Policy Type' = 'Initiative (Regulatory)'
        $pciRoot.'Display Name' = 'PCI DSS v4'
        $pciRoot.'Total Resources' = 10
        $pciRoot.'Non-Compliant Resources' = 2
        $pciSubscription = $pciRoot.PSObject.Copy()
        $pciSubscription.'Scope Name' = 'subscription-test'
        $pciSubscription.'Total Resources' = 10
        $pciSubscription.'Non-Compliant Resources' = 3
        $isoNotEvaluated = $HtmlPolicy.PSObject.Copy()
        $isoNotEvaluated.'Policy Type' = 'Initiative (Regulatory)'
        $isoNotEvaluated.'Display Name' = 'ISO/IEC 27001'
        $isoNotEvaluated.'Total Resources' = 0
        $isoNotEvaluated.'Non-Compliant Resources' = 0
        $operationalInitiative = $HtmlPolicy.PSObject.Copy()
        $operationalInitiative.'Policy Type' = 'Initiative'
        $operationalInitiative.'Display Name' = 'Enable platform logging'
        $operationalInitiative.'Total Resources' = 5
        $operationalInitiative.'Non-Compliant Resources' = 1
        $alzData = @{
            TotalRecommended = 10; TotalMatched = 6; TotalMissing = 2; TotalDoNotEnforce = 2
            TotalNotDetected = 2; TotalApplicabilityNotAssessed = 0; TotalNotApplicable = 0
            CoveragePercent = 80; EnforcedCoveragePercent = 60; RecommendedPolicies = @{}
            MatchedPolicies = @(); MissingPolicies = @(); DoNotEnforcePolicies = @(); AssetAssessments = @()
            SourceVersion = 'v-test'; SourceRetrievedAt = '2026-07-17T00:00:00Z'
        }
        $cepAssessment = New-CEPAssessment -Requested $true -State Evaluated -MappingState Available `
            -TestState Evaluated -ScoreState Measured -Score 80

        Export-HTMLReport -PolicyResults @($pciRoot, $pciSubscription, $isoNotEvaluated, $operationalInitiative) -PolicyCount 0 -InitiativeCount 4 `
            -OutputPath $outputPath -ALZData $alzData -CEPAssessment $cepAssessment `
            -DataQuality ([PSCustomObject]@{ AssessmentState = 'EvaluatedNonCompliant'; SuccessfulQueries = @('PolicyStates'); FailedQueries = @(); TotalRecords = 20; Timestamp = '2026-07-17T00:00:00Z'; FallbackUsed = $false })
        $html = Get-Content $outputPath -Raw
        $summaryLead = [regex]::Match($html, '<section id="page-summary".*?</section>', 'Singleline').Value

        $summaryLead | Should -Match '<details class="report-disclosure depth-2 executive-compliance" id="details-executive-compliance">\s*<summary>Compliance &amp; Landing Zone Results <span class="disclosure-meta">3 measured results</span></summary>'
        $summaryLead | Should -Not -Match '<details class="report-disclosure depth-2 executive-compliance"[^>]* open>'
        ([regex]::Matches($summaryLead, 'class="executive-compliance-item"')).Count | Should -Be 3
        $summaryLead | Should -Match 'Azure Landing Zone.*?80% detected.*?60% enforced; 2 applicable gaps across 10 assessed assets'
        $summaryLead | Should -Match 'Cyber Essentials Plus.*?80% tool indicator'
        $summaryLead | Should -Match 'PCI DSS v4.*?75%.*?5 non-compliant out of 20 policy evaluation records across 2 assignment\(s\)'
        $summaryLead | Should -Not -Match 'ISO/IEC 27001'
        $summaryLead | Should -Not -Match 'Enable platform logging'
    }

    It 'renders only complete official monetary evidence with provenance' {
        $outputPath = Join-Path $TestDrive 'cost-evidence.html'
        $completeEvidence = [PSCustomObject]@{
            EvidenceType = 'RetailPrice'; Description = 'Azure Monitor test SKU'; Amount = [decimal]'1.25'; Unit = '1 GB'
            Currency = 'EUR'; Region = 'westeurope'; Source = 'Azure Retail Prices API'
            SourceUri = 'https://prices.azure.com/api/retail/prices'; RetrievedAt = '2026-07-16T12:00:00Z'
            PriceOrCostDate = '2026-07-01T00:00:00Z'
        }
        $incompleteEvidence = [PSCustomObject]@{
            EvidenceType = 'RetailPrice'; Description = 'Unsupported amount'; Amount = [decimal]'999.99'; Unit = '1 unit'
            Currency = 'EUR'; Region = 'westeurope'; Source = 'Azure Retail Prices API'
            SourceUri = 'https://prices.azure.com/api/retail/prices'; RetrievedAt = ''; PriceOrCostDate = '2026-07-01'
        }

        Test-CostEvidenceRecord -Record $completeEvidence | Should -BeTrue
        Test-CostEvidenceRecord -Record $incompleteEvidence | Should -BeFalse
        $spoofedEvidence = $completeEvidence.PSObject.Copy()
        $spoofedEvidence.SourceUri = 'https://example.invalid/api/retail/prices'
        Test-CostEvidenceRecord -Record $spoofedEvidence | Should -BeFalse
        Export-HTMLReport -PolicyResults @($HtmlPolicy) -PolicyCount 1 -OutputPath $outputPath `
            -CostEvidenceRecords @($null, $completeEvidence, $incompleteEvidence)
        $html = Get-Content $outputPath -Raw

        $html | Should -Match '1\.25 EUR'
        $html | Should -Match 'westeurope'
        $html | Should -Match 'Azure Retail Prices API'
        $html | Should -Match '2026-07-01T00:00:00Z'
        $html | Should -Match '2026-07-16T12:00:00Z'
        $html | Should -Not -Match '999\.99'
    }

    It 'keeps unsourced cost governance output qualitative' {
        $outputPath = Join-Path $TestDrive 'cost-qualitative.html'

        Export-HTMLReport -PolicyResults @($HtmlPolicy) -PolicyCount 1 -OutputPath $outputPath
        $html = Get-Content $outputPath -Raw

        $html | Should -Match 'Cost exposure: High|Cost exposure: Medium|Cost exposure: Low'
        $html | Should -Match 'No amounts are shown'
        $html | Should -Not -Match '(?i)DoNotEnforce incurs zero cost|essentially free|DINE.+expensive'
        $html | Should -Not -Match '0&ndash;100.+Cost exposure|Cost exposure.+pts'
    }

    It 'renders remediation task failure only with explicit operational evidence' {
        $policy = $HtmlPolicy.PSObject.Copy()
        $policy | Add-Member -NotePropertyName 'Is Remediating' -NotePropertyValue $true
        $policy.'Effect Type' = 'DeployIfNotExists'
        $policy.'Display Name' = 'Deploy diagnostic settings'
        $policy | Add-Member -NotePropertyName 'Remediation Evidence' -NotePropertyValue (
            New-RemediationEvidence -AssignmentId '/assignments/remediation-failed' -Scope $policy.Scope `
                -IdentityType SystemAssigned -PrincipalId 'principal-1' -RequiredRoles @('role-1') `
                -RoleAssignments @([PSCustomObject]@{ PrincipalId = 'principal-1'; RoleDefinitionId = 'role-1'; Scope = $policy.Scope }) `
                -TaskRecords @([PSCustomObject]@{ TaskId = 'task-failed'; State = 'Failed'; Error = 'Synthetic deployment failure'; FailedDeployments = 3 }) `
                -TaskQuerySucceeded $true -RoleQuerySucceeded $true -ApplicableResourceCount 7 -LastEvaluation '2026-07-16T09:00:00Z' `
                -Exemptions @('exemption-1') -NotScopes @('/excluded') -ResourceSelectors @(@{ name = 'location' }) -Overrides @(@{ kind = 'policyEffect' })
        )
        $outputPath = Join-Path $TestDrive 'remediation-evidence-failed.html'

        Export-HTMLReport -PolicyResults @($policy) -PolicyCount 1 -OutputPath $outputPath
        $html = Get-Content $outputPath -Raw

        $html | Should -Match 'Remediation Operational Evidence'
        $html | Should -Match '>Failed<'
        $html | Should -Match 'task-failed'
        $html | Should -Match 'Synthetic deployment failure'
        $html | Should -Match '2026-07-16T09:00:00Z'
        $html | Should -Match 'Exemptions 1 \| notScopes 1 \| selectors 1 \| overrides 1'
    }

    It 'does not render remediation as working or failed when evidence is unavailable' {
        $policy = $HtmlPolicy.PSObject.Copy()
        $policy | Add-Member -NotePropertyName 'Is Remediating' -NotePropertyValue $true
        $policy | Add-Member -NotePropertyName 'Remediation Evidence' -NotePropertyValue (
            New-RemediationEvidence -AssignmentId '/assignments/remediation-unknown' -Scope $policy.Scope `
                -TaskQuerySucceeded $false -RoleQuerySucceeded $false `
                -TaskQueryError 'Synthetic task query unavailable' -RoleQueryError 'Synthetic role query unavailable'
        )
        $outputPath = Join-Path $TestDrive 'remediation-evidence-unavailable.html'

        Export-HTMLReport -PolicyResults @($policy) -PolicyCount 1 -OutputPath $outputPath
        $html = Get-Content $outputPath -Raw

        $html | Should -Match '>NotAssessed<'
        $html | Should -Match 'Synthetic task query unavailable'
        $html | Should -Match 'Synthetic role query unavailable'
        $html | Should -Not -Match '<span class="badge status-pass">Succeeded</span>'
        $html | Should -Not -Match '<span class="badge status-fail">Failed</span>'
    }

    It 'collects current Retail Prices API records with complete provenance' {
        Mock Invoke-RestMethod {
            [PSCustomObject]@{ Items = @([PSCustomObject]@{
                serviceName = 'Azure Monitor'; productName = 'Logs'; skuName = 'Pay-as-you-go'
                retailPrice = [decimal]'2.50'; unitOfMeasure = '1 GB'; currencyCode = 'EUR'
                armRegionName = 'westeurope'; effectiveStartDate = '2026-07-01T00:00:00Z'
            }) }
        }

        $records = @(Get-AzureRetailPriceEvidence -Region westeurope -Currency EUR -ServiceNames 'Azure Monitor')

        $records.Count | Should -Be 1
        Test-CostEvidenceRecord -Record $records[0] | Should -BeTrue
        $records[0].Source | Should -Be 'Azure Retail Prices API'
        $records[0].Region | Should -Be 'westeurope'
        $records[0].Currency | Should -Be 'EUR'
        Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter { $Uri -match 'prices\.azure\.com' -and $Uri -match 'currencyCode=EUR' }
    }

    It 'collects actual Cost Management records with period and region provenance' {
        Mock Invoke-AzRestMethod {
            [PSCustomObject]@{ Content = (@{
                properties = @{
                    columns = @(@{ name = 'Cost' }, @{ name = 'ResourceLocation' }, @{ name = 'Currency' })
                    rows = @(@([decimal]'42.75', 'westeurope', 'EUR'))
                }
            } | ConvertTo-Json -Depth 10 -Compress) }
        }

        $records = @(Get-AzureCostManagementEvidence -SubscriptionId '00000000-0000-0000-0000-000000000001' -LookbackDays 30)

        $records.Count | Should -Be 1
        Test-CostEvidenceRecord -Record $records[0] | Should -BeTrue
        $records[0].Source | Should -Be 'Azure Cost Management'
        $records[0].Region | Should -Be 'westeurope'
        $records[0].Currency | Should -Be 'EUR'
        $records[0].Unit | Should -Be 'Actual cost for period'
        Should -Invoke Invoke-AzRestMethod -Times 1 -ParameterFilter { $Path -match '/providers/Microsoft\.CostManagement/query' }
    }

    It 'counts the ALZ section only when ALZ data is rendered' {
        $outputPath = Join-Path $TestDrive 'report-with-alz.html'
        $alzData = @{
            TotalRecommended = 0; TotalMatched = 0; TotalMissing = 0; TotalDoNotEnforce = 0
            TotalNotDetected = 0; TotalApplicabilityNotAssessed = 0; TotalNotApplicable = 0
            CoveragePercent = 0; EnforcedCoveragePercent = 0; RecommendedPolicies = @{}
            MatchedPolicies = @(); MissingPolicies = @(); DoNotEnforcePolicies = @(); AssetAssessments = @()
            SourceVersion = 'v9.9.9-test'; SourceRetrievedAt = '2026-07-16T12:00:00.0000000Z'
        }

        Export-HTMLReport -PolicyResults @($HtmlPolicy) -PolicyCount 1 -OutputPath $outputPath -ALZData $alzData
        $html = Get-Content $outputPath -Raw

        $html | Should -Match 'organised into 8 sections: 7 core sections plus the optional sections listed below'
        ([regex]::Matches($html, '<section id="sec-')).Count | Should -Be 8
        $html | Should -Match '<section id="sec-alz" class="report-page" data-report-page data-page-group="page-csa">'
        $html | Should -Match 'Section 8 of 8'
        $html | Should -Match '<strong>Source release:</strong> v9\.9\.9-test'
        $html | Should -Match '<strong>Retrieved:</strong> 2026-07-16T12:00:00\.0000000Z'
        $html | Should -Match 'Applicable gap'
        $html | Should -Match 'Applicability not assessed'
        $html | Should -Match 'No match and insufficient evidence to claim a governance gap'
    }

    It 'renders snapshot delta directly in the Evidence page' {
        $outputPath = Join-Path $TestDrive 'report-with-delta.html'
        $deltaData = @{
            PreviousDate = '2026-07-16T00:00:00Z'; PreviousVersion = 'test'; Trend = 'STABLE'
            CurrTotal = 1; AssignmentDelta = 0; CurrNC = 0; NCDelta = 0
            CurrHigh = 0; HighDelta = 0; CurrEnforced = 1; EnfDelta = 0
            CurrExTotal = 0; PrevExTotal = 0; ExTotalDelta = 0
            NewAssignments = @(); RemovedAssignments = @(); ChangedAssignments = @(); EffectChanges = @()
            NewExemptions = @(); RemovedExemptions = @(); CEPPreviousResults = $null
        }

        Export-HTMLReport -PolicyResults @($HtmlPolicy) -PolicyCount 1 -OutputPath $outputPath -YAMLDeltaData $deltaData
        $html = Get-Content $outputPath -Raw

        ([regex]::Matches($html, '<section id="sec-')).Count | Should -Be 8
        $html | Should -Match '<section id="sec-yaml-delta" class="report-page" data-report-page data-page-group="page-evidence">'
        $html | Should -Match '<strong>No Changes Detected</strong>'
    }
}

Describe 'Offline regression fixture baseline' {
    It 'covers zero, compliant, and non-compliant evaluation scenarios' {
        @($ComplianceScenarios.name) | Should -Be @(
            'zero-evaluations',
            'all-compliant',
            'non-compliant-resources'
        )

        $zero = $ComplianceScenarios | Where-Object name -EQ 'zero-evaluations'
        $allCompliant = $ComplianceScenarios | Where-Object name -EQ 'all-compliant'
        $nonCompliant = $ComplianceScenarios | Where-Object name -EQ 'non-compliant-resources'

        $zero.evaluatedResources | Should -Be 0
        $allCompliant.compliantResources | Should -Be $allCompliant.evaluatedResources
        $nonCompliant.nonCompliantResources | Should -BeGreaterThan 0
        @($nonCompliant.states | Where-Object complianceState -EQ 'NonCompliant').Count |
            Should -Be $nonCompliant.nonCompliantResources
    }

    It 'covers mixed and parameterised effects through the current scoring contract' {
        $assignment = $Assignments | Where-Object displayName -EQ 'Security baseline'
        $assignment.effectType | Should -Match 'Audit'
        $assignment.effectType | Should -Match 'Deny'
        $assignment.effectType | Should -Match 'DeployIfNotExists'
        $assignment.effectType | Should -Match 'Parameterised'

        $recommendation = Get-PolicyRecommendation `
            -PolicyName $assignment.displayName `
            -EffectType $assignment.effectType `
            -EnforcementMode $assignment.enforcementMode `
            -PolicyType $assignment.policyType `
            -Category $assignment.category

        $recommendation.SecurityImpact | Should -Be 'High'
        $recommendation.CostImpact | Should -BeIn @('Medium', 'High')
    }

    It 'keeps effect and DoNotEnforce as separate fixture fields' {
        $assignment = $Assignments | Where-Object enforcementMode -EQ 'DoNotEnforce'

        $assignment.effectType | Should -Be 'Audit'
        $assignment.enforcementMode | Should -Be 'DoNotEnforce'
        $recommendation = Get-PolicyRecommendation `
            -PolicyName $assignment.displayName `
            -EffectType $assignment.effectType `
            -EnforcementMode $assignment.enforcementMode `
            -PolicyType $assignment.policyType `
            -Category $assignment.category
        $recommendation.Recommendation | Should -Match 'does not turn an Audit effect into Deny'
    }

    It 'preserves duplicate ALZ definition IDs as distinct assets' {
        @($ALZFixture.assets).Count | Should -Be 2
        @($ALZFixture.assets.policyDefinitionId | Select-Object -Unique).Count | Should -Be 1
        @($ALZFixture.assets.assetName | Select-Object -Unique).Count | Should -Be 2
        @($ALZFixture.assets.archetype | Select-Object -Unique).Count | Should -Be 2
    }

    It 'provides offline remediation evidence for not started, failed, and pending states' {
        @($Remediations.state) | Should -Contain 'NotStarted'
        @($Remediations.state) | Should -Contain 'Failed'
        @($Remediations.state) | Should -Contain 'Evaluating'
        ($Remediations | Where-Object state -EQ 'Failed').error | Should -Not -BeNullOrEmpty
    }

    It 'resolves remediation states only from explicit task and role evidence' {
        $notStartedEvidence = ($Remediations | Where-Object state -EQ 'NotStarted').PSObject.Copy()
        $notStartedEvidence | Add-Member ApplicableResourceCount 12
        $notStartedEvidence.availableRoles = @($notStartedEvidence.requiredRoles)
        (Resolve-RemediationEvidenceState -Evidence $notStartedEvidence -TaskQuerySucceeded $true -RoleQuerySucceeded $true).State | Should -Be 'NotStarted'

        $failedEvidence = ($Remediations | Where-Object state -EQ 'Failed').PSObject.Copy()
        (Resolve-RemediationEvidenceState -Evidence $failedEvidence -TaskQuerySucceeded $true -RoleQuerySucceeded $true).State | Should -Be 'Failed'

        $pendingEvidence = ($Remediations | Where-Object state -EQ 'Evaluating').PSObject.Copy()
        (Resolve-RemediationEvidenceState -Evidence $pendingEvidence -TaskQuerySucceeded $true -RoleQuerySucceeded $true).State | Should -Be 'Pending'

        $missingPermissionEvidence = ($Remediations | Where-Object state -EQ 'NotStarted').PSObject.Copy()
        $missingPermissionEvidence | Add-Member ApplicableResourceCount 12
        $missingPermissionState = Resolve-RemediationEvidenceState -Evidence $missingPermissionEvidence -TaskQuerySucceeded $true -RoleQuerySucceeded $true
        $missingPermissionState.State | Should -Be 'MissingPermissions'
        $missingPermissionState.MissingRoles | Should -Be @('00000000-0000-0000-0000-000000000201')

        (Resolve-RemediationEvidenceState -Evidence $failedEvidence -TaskQuerySucceeded $false -RoleQuerySucceeded $false).State | Should -Be 'NotAssessed'
    }

    It 'correlates remediation tasks roles evaluation and exclusions' {
        $roleId = '00000000-0000-0000-0000-000000000201'
        $evidence = New-RemediationEvidence `
            -AssignmentId '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/assignment-1' `
            -Scope '/subscriptions/sub-1/resourceGroups/rg-1' -IdentityType SystemAssigned -PrincipalId 'principal-1' `
            -RequiredRoles @($roleId) `
            -RoleAssignments @([PSCustomObject]@{ PrincipalId = 'principal-1'; RoleDefinitionId = "/providers/Microsoft.Authorization/roleDefinitions/$roleId"; Scope = '/subscriptions/sub-1' }) `
            -TaskRecords @([PSCustomObject]@{ TaskId = 'task-1'; State = 'Succeeded'; FailedDeployments = 0; LastUpdated = '2026-07-16T10:00:00Z' }) `
            -TaskQuerySucceeded $true -RoleQuerySucceeded $true -ApplicableResourceCount 5 `
            -LastEvaluation '2026-07-16T09:00:00Z' -Exemptions @('exemption-1') -NotScopes @('/subscriptions/sub-1/resourceGroups/excluded') `
            -ResourceSelectors @(@{ name = 'locations' }) -Overrides @(@{ kind = 'policyEffect' })

        $evidence.State | Should -Be 'Succeeded'
        $evidence.ManagedIdentityPresent | Should -BeTrue
        $evidence.MissingRoles | Should -BeNullOrEmpty
        $evidence.AvailableRoles | Should -Contain $roleId
        $evidence.ApplicableResourceCount | Should -Be 5
        $evidence.LastEvaluation | Should -Be '2026-07-16T09:00:00Z'
        $evidence.Exemptions | Should -Contain 'exemption-1'
        $evidence.NotScopes.Count | Should -Be 1
        $evidence.ResourceSelectors.Count | Should -Be 1
        $evidence.Overrides.Count | Should -Be 1
    }

    It 'uses the latest remediation task instead of a historical failure' {
        $evidence = New-RemediationEvidence -AssignmentId '/assignments/task-history' `
            -TaskQuerySucceeded $true -RoleQuerySucceeded $true -ApplicableResourceCount 4 `
            -TaskRecords @(
                [PSCustomObject]@{ TaskId = 'old-failure'; State = 'Failed'; Error = 'Historical failure'; LastUpdated = '2026-07-15T08:00:00Z' },
                [PSCustomObject]@{ TaskId = 'new-success'; State = 'Succeeded'; LastUpdated = '2026-07-16T08:00:00Z' }
            )

        $evidence.State | Should -Be 'Succeeded'
        $evidence.SelectedTaskId | Should -Be 'new-success'
        $evidence.Error | Should -BeNullOrEmpty
    }

    It 'normalizes null remediation collection entries to empty arrays' {
        $evidence = New-RemediationEvidence -AssignmentId '/assignments/no-operational-records' `
            -TaskQuerySucceeded $true -RoleQuerySucceeded $true `
            -TaskRecords @($null) -RoleAssignments @($null) -Exemptions @($null) `
            -NotScopes @($null) -ResourceSelectors @($null) -Overrides @($null)

        @($evidence.TaskRecords).Count | Should -Be 0
        @($evidence.Exemptions).Count | Should -Be 0
        @($evidence.NotScopes).Count | Should -Be 0
        @($evidence.ResourceSelectors).Count | Should -Be 0
        @($evidence.Overrides).Count | Should -Be 0
    }

    It 'keeps the compact critical-message HTML snapshot aligned with the renderer' {
        $exportSource = Get-FunctionSource -Name 'Export-HTMLReport'

        foreach ($fragment in $CriticalMessageSnapshot) {
            $exportSource | Should -Match ([regex]::Escape($fragment))
        }
    }
}

Describe 'Effective policy effect contract' {
    It 'returns the complete stable contract' {
        $resolved = Resolve-EffectivePolicyEffects -Effect 'Audit'

        @($resolved.PSObject.Properties.Name) | Should -Be @(
            'EffectiveEffects', 'PrimaryEffect', 'IsPreventive', 'IsDetective',
            'IsRemediating', 'IsParameterised', 'IsDisabled'
        )
    }

    It 'normalizes casing and mixed effects deterministically' {
        $resolved = Resolve-EffectivePolicyEffects -Effect 'audit(4), DENY(1), deployifnotexists(2), MODIFY(3)'

        $resolved.EffectiveEffects | Should -Be @('Deny', 'DeployIfNotExists', 'Modify', 'Audit')
        $resolved.PrimaryEffect | Should -Be 'Deny'
        $resolved.IsPreventive | Should -BeTrue
        $resolved.IsDetective | Should -BeTrue
        $resolved.IsRemediating | Should -BeTrue
        $resolved.IsDisabled | Should -BeFalse
    }

    It 'marks only wholly disabled assignments as disabled' {
        $disabled = Resolve-EffectivePolicyEffects -Effect 'Disabled'
        $mixed = Resolve-EffectivePolicyEffects -Effect 'AuditIfNotExists, Disabled'

        $disabled.IsDisabled | Should -BeTrue
        $mixed.EffectiveEffects | Should -Be @('AuditIfNotExists', 'Disabled')
        $mixed.PrimaryEffect | Should -Be 'AuditIfNotExists'
        $mixed.IsDisabled | Should -BeFalse
    }

    It 'resolves an assignment effect parameter from an object' {
        $parameters = [PSCustomObject]@{ effect = [PSCustomObject]@{ value = 'mOdIfY' } }
        $resolved = Resolve-EffectivePolicyEffects `
            -Effect "[parameters('effect')]" `
            -AssignmentParameters $parameters

        $resolved.EffectiveEffects | Should -Be @('Modify')
        $resolved.PrimaryEffect | Should -Be 'Modify'
        $resolved.IsParameterised | Should -BeTrue
        $resolved.IsRemediating | Should -BeTrue
    }

    It 'resolves an assignment effect parameter from JSON' {
        $resolved = Resolve-EffectivePolicyEffects `
            -Effect 'Parameterised' `
            -AssignmentParameters '{"policyEffect":{"value":"AuditIfNotExists"}}'

        $resolved.EffectiveEffects | Should -Be @('AuditIfNotExists')
        $resolved.IsParameterised | Should -BeTrue
        $resolved.IsDetective | Should -BeTrue
    }

    It 'keeps an unresolved parameter explicit' {
        $resolved = Resolve-EffectivePolicyEffects -Effect "[parameters('effect')]"

        $resolved.EffectiveEffects | Should -Be @('Parameterised')
        $resolved.PrimaryEffect | Should -Be 'Parameterised'
        $resolved.IsParameterised | Should -BeTrue
    }

    It 'does not accept or infer enforcement mode' {
        (Get-Command Resolve-EffectivePolicyEffects).Parameters.Keys | Should -Not -Contain 'EnforcementMode'
        $resolved = Resolve-EffectivePolicyEffects -Effect 'Audit'
        $resolved.PrimaryEffect | Should -Be 'Audit'
        $resolved.IsPreventive | Should -BeFalse
    }

    It 'counts every effective category once per assignment' {
        $results = @(
            [PSCustomObject]@{
                'Effect Type' = 'Deny'
                'Effective Effects' = @('Deny', 'DeployIfNotExists', 'Modify', 'Audit')
            },
            [PSCustomObject]@{
                'Effect Type' = 'AuditIfNotExists'
                'Effective Effects' = @('AuditIfNotExists')
            }
        )

        $counts = Get-EffectivePolicyEffectCounts -PolicyResults $results

        $counts.Deny | Should -Be 1
        $counts.Audit | Should -Be 2
        $counts.DeployIfNotExists | Should -Be 1
        $counts.Modify | Should -Be 1
        $counts.Remediating | Should -Be 1
        ($counts.Breakdown | Where-Object Effect -EQ 'Audit').Count | Should -Be 1
    }

    It 'uses the normalized contract for scoring, findings, HTML, roadmap, and YAML' {
        $htmlSource = Get-FunctionSource -Name 'Export-HTMLReport'
        $yamlSource = Get-FunctionSource -Name 'Export-AssessmentYAML'

        $ScriptText | Should -Match 'Get-PolicyRecommendation[^\r\n]+EffectiveEffects -join'
        $htmlSource | Should -Match 'Get-EffectivePolicyEffectCounts -PolicyResults \$PolicyResults'
        $htmlSource | Should -Not -Match '\$effectNormMap|\$normalizedEffects'
        (Get-FunctionSource -Name 'New-AssessmentFindings') | Should -Match '\$policy\.''Is Remediating'' -and'
        $ScriptText | Should -Match 'assessmentFindings\s*=\s*@\(New-AssessmentFindings'
        $ScriptText | Should -Match 'assessmentActions\s*=\s*@\(ConvertTo-AssessmentActions'
        $htmlSource | Should -Match 'ConvertTo-AssessmentActions -AssessmentFindings \$AssessmentFindings'
        $yamlSource | Should -Match 'effectiveEffects\s*=|primaryEffect\s*=|isPreventive\s*=|isDetective\s*=|isRemediating\s*=|isParameterised\s*=|isDisabled\s*='
        $yamlSource | Should -Match 'assessmentFindings\s*=\s*@\(\$AssessmentFindings\)'
        $yamlSource | Should -Match 'assessmentActions\s*=\s*@\(ConvertTo-AssessmentActions'
        $yamlSource | Should -Match 'assignmentId\s*=\s*\$_\.''Assignment ID'''
    }
}

Describe 'Deterministic assessment finding contract' {
    BeforeAll {
        $FindingPolicyResults = @(
            [PSCustomObject]@{
                'Assignment ID' = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/assignment-1'
                'Assignment Name' = 'assignment-1'
                'Display Name' = 'Deploy secure diagnostic settings'
                'Category' = 'Monitoring'
                'Effective Effects' = @('DeployIfNotExists')
                'Primary Effect' = 'DeployIfNotExists'
                'Is Remediating' = $true
                'Is Disabled' = $false
                'Enforcement Mode' = 'DoNotEnforce'
                'Security Impact' = 'High'
                'Cost Exposure' = 'High'
                'Risk Level' = 'High'
                'Compliance State' = 'EvaluatedNonCompliant'
                'Non-Compliant Resources' = 12
                'Identity Type' = 'SystemAssigned'
                'Scope Name' = 'sub-1'
                'Scope' = '/subscriptions/sub-1'
            }
        )
        $AssessmentFindings = @(New-AssessmentFindings -PolicyResults $FindingPolicyResults)
    }

    It 'uses the exact stable finding schema in the required order' {
        $AssessmentFindings[0].PSObject.Properties.Name | Should -Be @(
            'Id', 'Severity', 'Category', 'Title', 'Evidence', 'AssignmentIds', 'ScopeIds',
            'Recommendation', 'VerificationSteps', 'Source', 'Confidence'
        )
    }

    It 'returns no findings for an empty policy inventory' {
        @(New-AssessmentFindings -PolicyResults @()).Count | Should -Be 0
    }

    It 'creates deterministic unique IDs and all required finding families' {
        $secondRun = @(New-AssessmentFindings -PolicyResults $FindingPolicyResults)

        @($AssessmentFindings.Id) | Should -Be @($secondRun.Id)
        @($AssessmentFindings.Id | Select-Object -Unique).Count | Should -Be $AssessmentFindings.Count
        @($AssessmentFindings.Category) | Should -Contain 'Enforcement Gap'
        @($AssessmentFindings.Category) | Should -Contain 'Missing Controls'
        @($AssessmentFindings.Category) | Should -Contain 'Cost Exposure'
        @($AssessmentFindings.Category) | Should -Not -Contain 'Remediation Review'
    }

    It 'creates distinct remediation findings only from explicit evidence states' {
        $policy = $FindingPolicyResults[0].PSObject.Copy()
        $policy.'Enforcement Mode' = 'Default'
        $policy | Add-Member -NotePropertyName 'Remediation Evidence' -NotePropertyValue $null
        $roleId = '00000000-0000-0000-0000-000000000201'
        $baseArguments = @{
            AssignmentId = $policy.'Assignment ID'; Scope = $policy.Scope
            IdentityType = 'SystemAssigned'; PrincipalId = 'principal-1'; RequiredRoles = @($roleId)
            RoleAssignments = @([PSCustomObject]@{ PrincipalId = 'principal-1'; RoleDefinitionId = $roleId; Scope = '/subscriptions/sub-1' })
            TaskQuerySucceeded = $true; RoleQuerySucceeded = $true; ApplicableResourceCount = 12
            LastEvaluation = '2026-07-16T09:00:00Z'
        }

        $cases = @(
            @{ State = 'NotStarted'; Tasks = @(); Category = 'Remediation Not Started'; Roles = $baseArguments.RoleAssignments },
            @{ State = 'Failed'; Tasks = @([PSCustomObject]@{ TaskId = 'failed'; State = 'Failed'; Error = 'Synthetic failure' }); Category = 'Remediation Failed'; Roles = $baseArguments.RoleAssignments },
            @{ State = 'Evaluating'; Tasks = @([PSCustomObject]@{ TaskId = 'pending'; State = 'Evaluating' }); Category = 'Remediation Pending'; Roles = $baseArguments.RoleAssignments },
            @{ State = 'MissingPermissions'; Tasks = @(); Category = 'Remediation Permissions'; Roles = @() }
        )
        foreach ($case in $cases) {
            $arguments = $baseArguments.Clone()
            $arguments.TaskRecords = $case.Tasks
            $arguments.RoleAssignments = $case.Roles
            $policy.'Remediation Evidence' = New-RemediationEvidence @arguments
            $findings = @(New-AssessmentFindings -PolicyResults @($policy))
            @($findings.Category) | Should -Contain $case.Category
        }

        $succeededArguments = $baseArguments.Clone()
        $succeededArguments.TaskRecords = @([PSCustomObject]@{ TaskId = 'succeeded'; State = 'Succeeded' })
        $policy.'Remediation Evidence' = New-RemediationEvidence @succeededArguments
        @((New-AssessmentFindings -PolicyResults @($policy)).Category) | Should -Not -Contain 'Remediation Failed'

        $unavailableArguments = $baseArguments.Clone()
        $unavailableArguments.TaskQuerySucceeded = $false
        $unavailableArguments.RoleQuerySucceeded = $false
        $unavailableArguments.TaskQueryError = 'Synthetic task query failure'
        $policy.'Remediation Evidence' = New-RemediationEvidence @unavailableArguments
        $unavailableFindings = @(New-AssessmentFindings -PolicyResults @($policy))
        @($unavailableFindings.Category) | Should -Contain 'Remediation Evidence'
        @($unavailableFindings.Category) | Should -Not -Contain 'Remediation Failed'
    }

    It 'does not create a disabled-policy finding for a mixed active initiative' {
        $mixedPolicy = $FindingPolicyResults[0].PSObject.Copy()
        $mixedPolicy.'Effective Effects' = @('AuditIfNotExists', 'Disabled')
        $mixedPolicy.'Primary Effect' = 'AuditIfNotExists'
        $mixedPolicy.'Is Disabled' = $false

        $mixedFindings = @(New-AssessmentFindings -PolicyResults @($mixedPolicy))

        @($mixedFindings.Category) | Should -Not -Contain 'Housekeeping'
    }

    It 'qualifies direct-scope preventive gaps without claiming inherited coverage was evaluated' {
        $coverageFinding = $AssessmentFindings | Where-Object Category -EQ 'Missing Controls' | Select-Object -First 1

        $coverageFinding.Title | Should -Match 'directly assigned Deny'
        $coverageFinding.Evidence.InheritedCoverageEvaluated | Should -BeFalse
        $coverageFinding.Confidence | Should -Be 'Medium'
    }

    It 'links every generated action to at least one existing finding ID' {
        $actions = @(ConvertTo-AssessmentActions -AssessmentFindings $AssessmentFindings)

        $actions.Count | Should -BeGreaterThan 0
        foreach ($action in $actions) {
            @($action.FindingIds).Count | Should -BeGreaterThan 0
            foreach ($findingId in @($action.FindingIds)) {
                @($AssessmentFindings.Id) | Should -Contain $findingId
            }
        }
    }

    It 'orders same-priority actions by deterministic finding ID rather than recommendation text' {
        $samePriorityFindings = @(
            New-AssessmentFinding -Id 'F-TEST-0000000002' -Severity High -Category Test -Title Second -Evidence @{} -Recommendation 'A text-first action' -Source Test -Confidence High
            New-AssessmentFinding -Id 'F-TEST-0000000001' -Severity High -Category Test -Title First -Evidence @{} -Recommendation 'Z text-last action' -Source Test -Confidence High
        )

        $actions = @(ConvertTo-AssessmentActions -AssessmentFindings $samePriorityFindings)

        @($actions | ForEach-Object { @($_.FindingIds)[0] }) | Should -Be @('F-TEST-0000000001', 'F-TEST-0000000002')
    }

    It 'classifies ALZ coverage with enforced assignments taking precedence' {
        Resolve-ALZPolicyMatchState -MatchingAssignments @() | Should -Be 'Missing'
        Resolve-ALZPolicyMatchState -MatchingAssignments @(
            [PSCustomObject]@{ 'Enforcement Mode' = 'DoNotEnforce' }
        ) | Should -Be 'DoNotEnforce'
        Resolve-ALZPolicyMatchState -MatchingAssignments @(
            [PSCustomObject]@{ 'Enforcement Mode' = 'DoNotEnforce' }
            [PSCustomObject]@{ 'Enforcement Mode' = 'Default' }
        ) | Should -Be 'Enforced'
    }

    It 'matches an ALZ asset by exact assignment name when definition IDs differ' {
        $assignments = @(
            [PSCustomObject]@{
                'Assignment Name' = 'Enforce-ALZ-Decomm'
                'Policy Definition ID' = '/providers/Microsoft.Authorization/policySetDefinitions/custom-version'
                'Enforcement Mode' = 'Default'
            }
        )

        $alzMatches = @(Find-ALZMatchingAssignments -AssetName 'Enforce-ALZ-Decomm' `
            -OfficialDefinitionId '/providers/Microsoft.Authorization/policySetDefinitions/official-version' `
            -Assignments $assignments)

        $alzMatches.Count | Should -Be 1
        Resolve-ALZPolicyMatchState -MatchingAssignments $alzMatches | Should -Be 'Enforced'
    }

    It 'does not match shared definition IDs without asset discriminators' {
        $assignment = [PSCustomObject]@{
            'Assignment ID' = '/assignments/shared'
            'Assignment Name' = 'custom-assignment'
            'Policy Definition ID' = '/providers/Microsoft.Authorization/policyDefinitions/shared'
            'Enforcement Mode' = 'Default'
        }

        $alzMatches = @(Find-ALZMatchingAssignments -AssetName 'Asset-A' `
            -OfficialDefinitionId '/providers/Microsoft.Authorization/policyDefinitions/shared' `
            -SharedDefinitionIdCount 2 -Assignments @($assignment))

        $alzMatches.Count | Should -Be 0
    }

    It 'uses definition ID parameters and archetype then consumes an assignment only once' {
        $assignment = [PSCustomObject]@{
            'Assignment ID' = '/assignments/shared-corp'
            'Assignment Name' = 'custom-shared-assignment'
            'Policy Definition ID' = '/providers/Microsoft.Authorization/policyDefinitions/shared'
            'Enforcement Mode' = 'Default'
            'Parameters' = @{ effect = 'Deny' }
            'Scope Name' = 'corp'
        }
        $consumed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        $corpMatches = @(Find-ALZMatchingAssignments -AssetName 'Deny-Public-IP' `
            -OfficialDefinitionId '/providers/Microsoft.Authorization/policyDefinitions/shared' `
            -AssetParameters @{ effect = 'Deny' } -Archetype 'corp' -SharedDefinitionIdCount 2 `
            -ConsumedAssignmentKeys $consumed -Assignments @($assignment))
        $corpMatches.Count | Should -Be 1
        [void]$consumed.Add('/assignments/shared-corp')

        $onlineMatches = @(Find-ALZMatchingAssignments -AssetName 'Deny-Public-IP-Online' `
            -OfficialDefinitionId '/providers/Microsoft.Authorization/policyDefinitions/shared' `
            -AssetParameters @{ effect = 'Audit' } -Archetype 'online' -SharedDefinitionIdCount 2 `
            -ConsumedAssignmentKeys $consumed -Assignments @($assignment))
        $onlineMatches.Count | Should -Be 0
    }

    It 'maps ALZ detection and applicability evidence to explicit states' {
        Resolve-ALZAssetState -MatchState Enforced | Should -Be 'Detected'
        Resolve-ALZAssetState -MatchState DoNotEnforce | Should -Be 'Detected'
        Resolve-ALZAssetState -MatchState Missing -ApplicabilityAssessed:$false | Should -Be 'Applicability not assessed'
        Resolve-ALZAssetState -MatchState Missing -ApplicabilityAssessed:$true | Should -Be 'Not detected'
        Resolve-ALZAssetState -MatchState Missing -Applicable $true -ApplicabilityAssessed:$true | Should -Be 'Applicable gap'
        Resolve-ALZAssetState -MatchState Missing -Applicable $false -ApplicabilityAssessed:$true | Should -Be 'Not applicable'
    }

    It 'keeps finding decisions out of console and HTML consumers' {
        ([regex]::Matches($ScriptText, '\$policy\.''Enforcement Mode'' -eq ''DoNotEnforce'' -and \$policy\.''Security Impact''')).Count | Should -Be 1
        ([regex]::Matches($ScriptText, '\$policy\.''Cost Exposure'' -eq ''High''')).Count | Should -Be 1
        ([regex]::Matches($ScriptText, 'Get-EffectivePolicyEffectCounts -PolicyResults \$scopeResults\)\.Deny -eq 0')).Count | Should -Be 1
    }

}

Describe 'CEP assessment state contract' {
    BeforeAll {
        $Global:CEPGroupFriendlyNames = @{}
        function Get-AzPolicySetDefinition { @() }
        function Get-AzPolicyDefinition { [PSCustomObject]@{ DisplayName = 'Synthetic CE member policy' } }
        function Search-AzGraph { @() }
        function Expand-AzGraphResult { process { $_ } }
        function Get-AzRoleAssignment { @() }
        $CEPDefinitionFixture = [PSCustomObject]@{
            Name = 'ce-initiative'
            ResourceId = '/providers/Microsoft.Authorization/policySetDefinitions/ce-initiative'
            DisplayName = 'UK NCSC Cyber Essentials v3.1'
            Metadata = @{ version = '1.0.0' }
            PolicyDefinition = @([PSCustomObject]@{
                policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/ce-member-policy'
                policyDefinitionReferenceId = 'ce-member-ref'
                groupNames = @('ce-group')
            })
            PolicyDefinitionGroup = @([PSCustomObject]@{ name = 'ce-group'; displayName = 'Synthetic CE Group' })
        }
        $CEPAssignmentFixture = [PSCustomObject]@{
            policyDefinitionId = '/providers/Microsoft.Authorization/policySetDefinitions/ce-initiative'
            policyType = 'Initiative'
            assignmentId = '/providers/Microsoft.Management/managementGroups/test/providers/Microsoft.Authorization/policyAssignments/ce-assignment'
            enforcementMode = 'Default'
            displayName = 'Synthetic CE assignment'
            scopeType = 'Management Group'
        }
        $CEPHtmlPolicy = [PSCustomObject]@{
            'Display Name' = 'Synthetic policy'
            'Policy Type' = 'Policy'
            'Category' = 'Test'
            'Effect Type' = 'Audit'
            'Enforcement Mode' = 'Default'
            'Compliance State' = 'NotEvaluated'
            'Compliant Resources' = 0
            'Non-Compliant Resources' = 0
            'Total Resources' = 0
            'Exemptions' = 0
            'Scope Type' = 'Management Group'
            'Scope Name' = 'mg-test'
        }
    }

    It 'represents CEP not requested without inferring a score' {
        $assessment = New-CEPAssessment -Requested $false -State NotRequested

        $assessment.Requested | Should -BeFalse
        $assessment.State | Should -Be 'NotRequested'
        $assessment.ScoreState | Should -Be 'NotMeasured'
        $assessment.Score | Should -BeNullOrEmpty
    }

    It 'exposes configurable CE definition identity and version parameters without wildcard source selection' {
        $ScriptText | Should -Match '\[string\]\$CEPDefinitionId\s*=\s*''?''?'
        $ScriptText | Should -Match '\[string\]\$CEPDefinitionVersion\s*=\s*''3\.1'''
        $ScriptText | Should -Not -Match 'DisplayName\s+-like\s+"\*Cyber Essentials\*v3\*"'
    }

    It 'forces a null score when CEP is not measured' {
        $assessment = New-CEPAssessment `
            -Requested $true `
            -State PrerequisiteUnavailable `
            -MappingState Unavailable `
            -TestState PartiallyEvaluated `
            -ScoreState NotMeasured `
            -Score 0 `
            -PrerequisiteReason 'CE v3.1 initiative definition not found'

        $assessment.State | Should -Be 'PrerequisiteUnavailable'
        $assessment.MappingState | Should -Be 'Unavailable'
        $assessment.Score | Should -BeNullOrEmpty
        $assessment.DataQuality.State | Should -Be 'Unavailable'
    }

    It 'resolves the configured CE definition ID before display-name fallback' {
        $definitions = @(
            [PSCustomObject]@{ Name = 'exact-name'; ResourceId = '/providers/Microsoft.Authorization/policySetDefinitions/exact-name'; DisplayName = 'UK NCSC Cyber Essentials v3.1'; Metadata = @{ version = '1.0.0' } }
            [PSCustomObject]@{ Name = 'configured-id'; ResourceId = '/providers/Microsoft.Authorization/policySetDefinitions/configured-id'; DisplayName = 'Renamed Cyber Essentials source'; Metadata = @{ version = '2.0.0' } }
        )

        $resolution = Resolve-CEPMappingSource -DefinitionId 'configured-id' -DefinitionVersion '3.1' -Definitions $definitions

        $resolution.State | Should -Be 'Available'
        $resolution.SelectionMethod | Should -Be 'DefinitionId'
        $resolution.Definition.Name | Should -Be 'configured-id'
        @($resolution.Candidates).Count | Should -Be 2
    }

    It 'uses an exact versioned display name only as fallback' {
        $definitions = @(
            [PSCustomObject]@{ Name = 'ce-32'; ResourceId = '/definitions/ce-32'; DisplayName = 'UK NCSC Cyber Essentials v3.2'; Metadata = @{} }
        )

        $resolution = Resolve-CEPMappingSource -DefinitionVersion '3.2' -Definitions $definitions

        $resolution.State | Should -Be 'Available'
        $resolution.SelectionMethod | Should -Be 'ExactDisplayName'
        $resolution.Definition.Name | Should -Be 'ce-32'
    }

    It 'reports candidate definitions when the expected source appears renamed' {
        $definitions = @(
            [PSCustomObject]@{ Name = 'ce-current'; ResourceId = '/definitions/ce-current'; DisplayName = 'UK Cyber Essentials current mapping'; Metadata = @{ version = '4.0.0' } }
        )

        $resolution = Resolve-CEPMappingSource -DefinitionVersion '3.1' -Definitions $definitions

        $resolution.State | Should -Be 'Renamed'
        $resolution.Definition | Should -BeNullOrEmpty
        @($resolution.Candidates).Count | Should -Be 1
        $resolution.Candidates[0].DisplayName | Should -Be 'UK Cyber Essentials current mapping'
    }

    It 'distinguishes configured source retirement from generic unavailability' {
        $retired = Resolve-CEPMappingSource -DefinitionId 'known-official-id' -Definitions @()
        $unavailable = Resolve-CEPMappingSource -Definitions @()

        $retired.State | Should -Be 'RetiredOrUnavailable'
        $retired.Message | Should -Match 'may be retired or unavailable'
        $unavailable.State | Should -Be 'Unavailable'
        $unavailable.Message | Should -Not -Match 'tenant.*configur'
    }

    It 'keeps definition discovery errors distinct from an unavailable source' {
        Mock Get-AzPolicySetDefinition { throw 'synthetic discovery failure' }

        $resolution = Resolve-CEPMappingSource

        $resolution.State | Should -Be 'DiscoveryFailed'
        $resolution.Message | Should -Match 'console diagnostic'
        $resolution.DiagnosticMessage | Should -Match 'synthetic discovery failure'
    }

    It 'sanitizes tenant authentication discovery failures for report consumers' {
        Mock Get-AzPolicySetDefinition {
            throw "[InvalidAuthenticationTokenTenant] access token is from the wrong issuer https://sts.windows.net/source-tenant and must match https://sts.windows.net/target-tenant"
        }

        $resolution = Resolve-CEPMappingSource

        $resolution.State | Should -Be 'DiscoveryFailed'
        $resolution.Message | Should -Match 'active Azure token tenant does not match the subscription tenant'
        $resolution.Message | Should -Not -Match 'source-tenant|target-tenant|https://'
        $resolution.DiagnosticMessage | Should -Match 'InvalidAuthenticationTokenTenant'
    }

    It 'handles a present CE definition that is not assigned' {
        Mock Get-AzPolicySetDefinition { @($CEPDefinitionFixture) }
        Mock Search-AzGraph { @() }

        $result = Invoke-CEPInitiativeAssessment -PolicyAssignments @([PSCustomObject]@{
            policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/unrelated'
            policyType = 'Policy'
        })

        $result.Assessment.MappingState | Should -Be 'Available'
        ($result.TestResults | Where-Object { $_.'Test Name' -eq 'CE Initiative is Assigned' }).Status | Should -Be 'WARN'
        ($result.TestResults | Where-Object { $_.'Test Name' -eq 'CE Initiative is Assigned' }).Details | Should -Match 'Not directly assigned'
    }

    It 'fails the enforcement check when the CE definition is assigned in DoNotEnforce' {
        Mock Get-AzPolicySetDefinition { @($CEPDefinitionFixture) }
        Mock Search-AzGraph { @() }
        $assignment = $CEPAssignmentFixture.PSObject.Copy()
        $assignment.enforcementMode = 'DoNotEnforce'

        $result = Invoke-CEPInitiativeAssessment -PolicyAssignments @($assignment)

        ($result.TestResults | Where-Object { $_.'Test Name' -eq 'CE Initiative is Assigned' }).Status | Should -Be 'PASS'
        ($result.TestResults | Where-Object { $_.'Test Name' -eq 'Enforcement Mode is Active' }).Status | Should -Be 'FAIL'
        ($result.TestResults | Where-Object { $_.'Test Name' -eq 'Enforcement Mode is Active' }).Details | Should -Match 'DoNotEnforce'
    }

    It 'keeps mapping available but skips control evidence when PolicyStates are empty' {
        Mock Get-AzPolicySetDefinition { @($CEPDefinitionFixture) }
        Mock Search-AzGraph { @() }

        $result = Invoke-CEPInitiativeAssessment -PolicyAssignments @($CEPAssignmentFixture)
        $groupResult = $result.TestResults | Where-Object { $_.'Control Group' -eq 'Synthetic CE Group' }

        $result.Assessment.MappingState | Should -Be 'Available'
        $groupResult.Status | Should -Be 'SKIP'
        $groupResult.Details | Should -Match '1 skipped'
    }

    It 'represents partially available technical evidence without a PASS aggregate' {
        Mock Search-AzGraph {
            param($Query, $First, [switch]$UseTenantScope)

            if ($Query -match 'TotalAccounts') {
                return [PSCustomObject]@{ TotalAccounts = 1; PublicAccessEnabled = 0; NotHttpsOnly = 0; OldTls = 0 }
            }
            @()
        }

        $result = Invoke-CEPPlusTechnicalAssessment -PolicyAssignments @([PSCustomObject]@{})

        $result.Assessment.State | Should -Be 'PartiallyEvaluated'
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC1.4' }).Status | Should -Be 'PASS'
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC1.3' }).Status | Should -Be 'SKIP'
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC1' }).Status | Should -Be 'WARN'
    }

    It 'records technical query errors as partial evidence instead of throwing' {
        Mock Search-AzGraph { throw 'synthetic ARG query failure' }

        $result = Invoke-CEPPlusTechnicalAssessment -PolicyAssignments @([PSCustomObject]@{})
        $failedEvidence = @($result.TestResults | Where-Object { $_.Details -match 'synthetic ARG query failure' })

        $result.Assessment.State | Should -Be 'PartiallyEvaluated'
        $failedEvidence.Count | Should -BeGreaterThan 0
        @($failedEvidence.Status | Sort-Object -Unique) | Should -Not -Contain 'PASS'
    }

    It 'does not measure an empty or SKIP and MANUAL-only technical result set' {
        $emptyScore = Get-CEPScore
        $nonAutomatedScore = Get-CEPScore -TestResults @(
            [PSCustomObject]@{ 'Test #' = 'T1'; Status = 'PASS' }
            [PSCustomObject]@{ 'Test #' = 'TC1'; Status = 'SKIP' }
            [PSCustomObject]@{ 'Test #' = 'TC2.4'; Status = 'MANUAL' }
            [PSCustomObject]@{ 'Test #' = 'TC3'; Status = 'WARN' }
        )

        $emptyScore.Denominator | Should -Be 0
        $emptyScore.ScoreState | Should -Be 'NotMeasured'
        $emptyScore.Score | Should -BeNullOrEmpty
        $nonAutomatedScore.Denominator | Should -Be 0
        $nonAutomatedScore.ScoreState | Should -Be 'NotMeasured'
        $nonAutomatedScore.Score | Should -BeNullOrEmpty
    }

    It 'scores only top-level technical PASS and FAIL verdicts' {
        $score = Get-CEPScore -TestResults @(
            [PSCustomObject]@{ 'Test #' = 'T1'; Status = 'PASS' }
            [PSCustomObject]@{ 'Test #' = 'TC1'; Status = 'PASS' }
            [PSCustomObject]@{ 'Test #' = 'TC2'; Status = 'FAIL' }
            [PSCustomObject]@{ 'Test #' = 'TC3'; Status = 'PASS' }
            [PSCustomObject]@{ 'Test #' = 'TC4'; Status = 'WARN' }
            [PSCustomObject]@{ 'Test #' = 'TC5.3'; Status = 'MANUAL' }
        )

        $score.Pass | Should -Be 2
        $score.Fail | Should -Be 1
        $score.Denominator | Should -Be 3
        $score.ScoreState | Should -Be 'Measured'
        $score.Score | Should -Be 66.7
    }

    It 'keeps the score unavailable when the initiative prerequisite blocks measurement' {
        $score = Get-CEPScore `
            -TestResults @([PSCustomObject]@{ 'Test #' = 'TC1'; Status = 'PASS' }) `
            -MeasurementBlocked

        $score.Denominator | Should -Be 1
        $score.ScoreState | Should -Be 'NotMeasured'
        $score.Score | Should -BeNullOrEmpty
    }

    It 'creates stable CEP finding families with evidence and linked actions' {
        $assessment = New-CEPAssessment `
            -Requested $true `
            -State PrerequisiteUnavailable `
            -MappingState Unavailable `
            -TestState PartiallyEvaluated `
            -PrerequisiteReason 'CE v3.1 initiative definition not found' `
            -DataQuality ([PSCustomObject]@{ State = 'Partial'; EvidenceCount = 3; Limitations = @('Mapping unavailable') })
        $testResults = @(
            [PSCustomObject]@{ 'Test #' = 'T1'; 'Test Name' = 'Definition'; Status = 'SKIP'; Details = 'Definition unavailable' }
            [PSCustomObject]@{
                'Test #' = 'TC1'; 'Test Name' = 'Remote Vulnerability Assessment'; Status = 'WARN'
                Details = 'Review technical evidence'; 'Non-Compliant' = 1; Compliant = 2; 'Total Resources' = 3
                AssignmentId = '/assignments/cep-test'; ScopeId = '/subscriptions/sub-1'
            }
            [PSCustomObject]@{ 'Test #' = 'TC1.5'; 'Test Name' = 'Account Lockout'; Status = 'MANUAL'; Details = 'Manual test' }
        )

        $firstRun = @(New-CEPAssessmentFindings -CEPAssessment $assessment -CEPTestResults $testResults)
        $secondRun = @(New-CEPAssessmentFindings -CEPAssessment $assessment -CEPTestResults $testResults)
        $actions = @(ConvertTo-AssessmentActions -AssessmentFindings $firstRun)

        @($firstRun.Id) | Should -Be @($secondRun.Id)
        @($firstRun.Category | Sort-Object) | Should -Be @(
            'CEP Data Quality', 'CEP Manual Verification', 'CEP Prerequisite', 'CEP Technical Control'
        )
        foreach ($finding in $firstRun) {
            $finding.Id | Should -Match '^F-CEP'
            $finding.Evidence.Fact | Should -Not -BeNullOrEmpty
            $finding.Evidence.Interpretation | Should -Not -BeNullOrEmpty
            @($finding.VerificationSteps).Count | Should -BeGreaterThan 0
            $finding.Recommendation | Should -Not -BeNullOrEmpty
            $finding.Source | Should -Not -BeNullOrEmpty
            $finding.Confidence | Should -BeIn @('High', 'Medium', 'Low')
        }
        $technicalFinding = $firstRun | Where-Object Category -eq 'CEP Technical Control'
        $prerequisiteFinding = $firstRun | Where-Object Category -eq 'CEP Prerequisite'
        $prerequisiteFinding.Evidence.MappingSourceState | Should -Be 'NotRequested'
        $technicalFinding.Title | Should -Be 'TC1: Remote Vulnerability Assessment requires review'
        $technicalFinding.Title | Should -Not -Match '^TC1\s+TC1'
        @($technicalFinding.AssignmentIds) | Should -Be @('/assignments/cep-test')
        @($technicalFinding.ScopeIds) | Should -Be @('/subscriptions/sub-1')
        $actions.Count | Should -Be $firstRun.Count
        foreach ($action in $actions) {
            @($action.FindingIds).Count | Should -BeGreaterThan 0
            foreach ($findingId in @($action.FindingIds)) {
                @($firstRun.Id) | Should -Contain $findingId
            }
        }
    }

    It 'uses tenant-wide scope for aggregate CEP technical findings without a narrower scope' {
        $assessment = New-CEPAssessment -Requested $true -State PartiallyEvaluated -MappingState Available -TestState PartiallyEvaluated
        $testResults = @([PSCustomObject]@{
            'Test #' = 'TC3'; 'Test Name' = 'TC3: Malware Protection'; Status = 'WARN'; Details = 'Review evidence'
            'Non-Compliant' = 0; Compliant = 0; 'Total Resources' = 0
        })

        $finding = New-CEPAssessmentFindings -CEPAssessment $assessment -CEPTestResults $testResults |
            Where-Object Category -eq 'CEP Technical Control'
        $action = ConvertTo-AssessmentActions -AssessmentFindings @($finding)

        @($finding.ScopeIds) | Should -Be @('Tenant-wide')
        $action.Scope | Should -Be 'Tenant-wide'
    }

    It 'uses singular ALZ asset wording for a single missing item' {
        $alzData = @{
            SourceVersion = 'test'
            MissingPolicies = @([PSCustomObject]@{ Category = 'Compliance'; PolicyPattern = 'Audit-Test' })
        }

        $finding = New-AssessmentFindings -PolicyResults @() -ALZData $alzData |
            Where-Object Category -eq 'ALZ Inventory'

        $finding.Title | Should -Be "1 applicable ALZ asset not detected in 'Compliance'"
    }

    It 'does not create CEP findings when CEP was not requested' {
        $assessment = New-CEPAssessment -Requested $false -State NotRequested

        @(New-CEPAssessmentFindings -CEPAssessment $assessment).Count | Should -Be 0
    }

    It 'renders requested unavailable CEP as N/A without a not-run instruction' {
        $assessment = New-CEPAssessment `
            -Requested $true `
            -State PrerequisiteUnavailable `
            -MappingState Unavailable `
            -TestState PartiallyEvaluated `
            -PrerequisiteReason 'Expected source appears renamed' `
            -MappingSourceState Renamed `
            -DefinitionVersion '3.1' `
            -DefinitionDisplayName 'UK NCSC Cyber Essentials v3.1' `
            -CandidateDefinitions @([PSCustomObject]@{
                Id = '/providers/Microsoft.Authorization/policySetDefinitions/candidate-id'
                Name = 'candidate-id'
                DisplayName = 'UK Cyber Essentials current mapping'
                Version = '4.0.0'
            })
        $outputPath = Join-Path $TestDrive 'cep-prerequisite-unavailable.html'

        Export-HTMLReport `
            -PolicyResults @($CEPHtmlPolicy) `
            -PolicyCount 1 `
            -OutputPath $outputPath `
            -CEPAssessment $assessment
        $html = Get-Content $outputPath -Raw

        $html | Should -Match '<strong>N/A</strong>'
        $html | Should -Match '<strong>Assessment prerequisite unavailable</strong>'
        $html | Should -Match 'Score: N/A\.'
        $html | Should -Not -Match '<div class="card [^"]+"><div class="card-num">N/A</div><div class="card-label">CE\+ Score'
        $html | Should -Not -Match '<div class="card-num">%</div>'
        $html | Should -Match 'Mapping unavailable'
        $html | Should -Match 'Assessment partially evaluated'
        $html | Should -Match 'Assessment: PrerequisiteUnavailable'
        $html | Should -Match 'Mapping: Unavailable'
        $html | Should -Match 'Source: Renamed'
        $html | Should -Match 'Score: NotMeasured'
        $html | Should -Match 'Confidence: Low'
        $html | Should -Match 'Data quality: Unavailable'
        $html | Should -Match '<strong>Fact:</strong>'
        $html | Should -Match '<strong>Interpretation:</strong>'
        $html | Should -Match '<strong>Verify:</strong>'
        $html | Should -Match '<strong>Action:</strong>'
        $html | Should -Match 'Candidate CE policy set definitions \(1\)'
        $html | Should -Match 'UK Cyber Essentials current mapping'
        $html | Should -Match 'candidate-id'
        $html | Should -Match 'Definition version: 4\.0\.0'
        $html | Should -Not -Match 'CE\+ (Tests|Compliance) Not Run'
        $html | Should -Not -Match 'Run with <code>-CEP (Test|Show|Full)'
    }

    It 'shows run instructions only when CEP was not requested' {
        $outputPath = Join-Path $TestDrive 'cep-not-requested.html'

        Export-HTMLReport `
            -PolicyResults @($CEPHtmlPolicy) `
            -PolicyCount 1 `
            -OutputPath $outputPath `
            -CEPAssessment (New-CEPAssessment -Requested $false -State NotRequested)
        $html = Get-Content $outputPath -Raw

        $html | Should -Match 'CE\+ Tests Not Run'
        $html | Should -Match 'CE\+ Compliance Not Run'
        $html | Should -Match 'Run with <code>-CEP (Test|Show)'
    }

    It 'renders partial technical evidence without a not-run instruction' {
        $outputPath = Join-Path $TestDrive 'cep-partial.html'
        $assessment = New-CEPAssessment `
            -Requested $true `
            -State PartiallyEvaluated `
            -MappingState Available `
            -TestState PartiallyEvaluated `
            -DataQuality ([PSCustomObject]@{ State = 'Partial'; EvidenceCount = 2; Limitations = @('Manual checks remain') })

        Export-HTMLReport `
            -PolicyResults @($CEPHtmlPolicy) `
            -PolicyCount 1 `
            -OutputPath $outputPath `
            -CEPAssessment $assessment
        $html = Get-Content $outputPath -Raw

        $html | Should -Match 'Assessment partially evaluated'
        $html | Should -Match 'Confidence: Medium'
        $html | Should -Match 'Data quality: Partial'
        $html | Should -Not -Match 'Automated checks passed'
        $html | Should -Not -Match 'CE\+ (Tests|Compliance) Not Run'
        $html | Should -Not -Match 'Run with <code>-CEP'
    }

    It 'renders warning-only guidance and distinguishes configuration evidence from resource counts' {
        $outputPath = Join-Path $TestDrive 'cep-evidence-types.html'
        $assessment = New-CEPAssessment `
            -Requested $true `
            -State PartiallyEvaluated `
            -MappingState Unavailable `
            -TestState PartiallyEvaluated `
            -ScoreState NotMeasured
        $testResults = @(
            [PSCustomObject]@{
                'Test #' = 'TC1'; 'Control Group' = 'CE+ v3.2 Spec'; 'Test Name' = 'TC1: Remote Vulnerability Assessment'
                Status = 'PASS'; Details = '4 passed | 0 failed | 0 warnings | 2 manual subtests'; 'Non-Compliant' = 0; Compliant = 0; 'Total Resources' = 0
            }
            [PSCustomObject]@{
                'Test #' = 'TC3'; 'Control Group' = 'CE+ v3.2 Spec'; 'Test Name' = 'TC3: Malware Protection'
                Status = 'WARN'; Details = '0 passed | 0 failed | 2 warnings'; 'Non-Compliant' = 0; Compliant = 0; 'Total Resources' = 0
            }
            [PSCustomObject]@{
                'Test #' = 'TC3.1'; 'Control Group' = 'TC3: Malware'; 'Test Name' = 'Endpoint Protection Installed and Running'
                Status = 'WARN'; Details = 'No endpoint protection assessments found'; 'Non-Compliant' = 0; Compliant = 0; 'Total Resources' = 0
                'Evidence Type' = 'Automated'; Source = 'Azure Resource Graph: securityresources'; Query = "securityresources`n| where TotalChecks < 1"
            }
            [PSCustomObject]@{
                'Test #' = 'TC3.4'; 'Control Group' = 'TC3: Malware'; 'Test Name' = 'Email Malware Test'
                Status = 'MANUAL'; Details = 'Run EICAR test'; 'Non-Compliant' = 0; Compliant = 0; 'Total Resources' = 0
            }
        )

        $cepFindings = @(New-CEPAssessmentFindings -CEPAssessment $assessment -CEPTestResults $testResults)
        Export-HTMLReport -PolicyResults @($CEPHtmlPolicy) -PolicyCount 1 -OutputPath $outputPath `
            -CEPAssessment $assessment -CEPTestResults $testResults -AssessmentFindings $cepFindings
        $html = Get-Content $outputPath -Raw

        $html | Should -Match 'Review warning evidence and complete all manual tests'
        $html | Should -Not -Match 'Recommendation:</em> Review failed checks'
        $html | Should -Match 'Configuration checks: 4 passed \| 0 failed'
        $html | Should -Match '<span class="badge status-pass">AUTOMATED PASS</span>'
        $html | Should -Match 'automated configuration checks passed, but listed manual verification may remain'
        $html | Should -Match 'Automated check: No endpoint protection assessments found'
        $html | Should -Match '<summary>Source and query</summary>'
        $html | Should -Match 'Azure Resource Graph: securityresources'
        $html | Should -Match 'TotalChecks &lt; 1'
        $html | Should -Match 'Evidence basis: Observed'
        $html | Should -Match 'Data quality: Partial'
        $html | Should -Not -Match 'Data quality: Observed'
        $html | Should -Match 'Manual procedure: Run EICAR test'
        $html | Should -Match '<td>N/A</td><td>N/A</td><td>N/A</td>'
        $html | Should -Match 'Azure Policy mapping uses the <strong>UK NCSC Cyber Essentials v3.1 initiative</strong>'
        $html | Should -Match 'Independent technical checks use the <strong>NCSC CE\+ v3.2 Test Specification</strong>'
    }

    It 'renders evaluation failed only for an explicit failure state' {
        $outputPath = Join-Path $TestDrive 'cep-failed.html'
        $assessment = New-CEPAssessment `
            -Requested $true `
            -State EvaluationFailed `
            -MappingState Failed `
            -TestState Failed

        Export-HTMLReport `
            -PolicyResults @($CEPHtmlPolicy) `
            -PolicyCount 1 `
            -OutputPath $outputPath `
            -CEPAssessment $assessment
        $html = Get-Content $outputPath -Raw

        $html | Should -Match 'Evaluation failed'
        $html | Should -Match 'Assessment: EvaluationFailed'
        $html | Should -Match 'Mapping: Failed'
        $html | Should -Match 'Data quality: Failed'
        $html | Should -Not -Match 'Automated checks passed'
        $html | Should -Not -Match 'CE\+ (Tests|Compliance) Not Run'
        $html | Should -Not -Match 'Run with <code>-CEP'
    }

    It 'returns prerequisite unavailable from the CEP engine when the definition is absent' {
        $result = Invoke-CEPComplianceTests -PolicyAssignments @([PSCustomObject]@{})

        $result.Assessment.Requested | Should -BeTrue
        $result.Assessment.State | Should -Be 'PrerequisiteUnavailable'
        $result.Assessment.MappingState | Should -Be 'Unavailable'
        $result.Assessment.TestState | Should -Be 'PartiallyEvaluated'
        $result.Assessment.ScoreState | Should -Be 'NotMeasured'
        $result.Assessment.Score | Should -BeNullOrEmpty
        @($result.TestResults).Count | Should -BeGreaterThan 1
        $result.TestResults[0].Status | Should -Be 'SKIP'
        $result.TestResults[0].'Test Name' | Should -Be 'Azure Policy CE Mapping Source Exists'
        $result.Assessment.PrerequisiteReason | Should -Match 'Azure Policy mapping source'
        @($result.TestResults.'Test #' | Where-Object { $_ -match '^TC[1-5]$' }) | Should -Be @('TC1', 'TC2', 'TC3', 'TC4', 'TC5')
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC1.3' }).Status | Should -Be 'SKIP'
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC1.4' }).Status | Should -Be 'SKIP'
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC2.1' }).Status | Should -Be 'SKIP'
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC2.2' }).Status | Should -Be 'SKIP'
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC2.3' }).Status | Should -Be 'SKIP'
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC1' }).Status | Should -Be 'WARN'
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC2' }).Status | Should -Be 'WARN'
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC1.4' }).Details | Should -Match 'No storage accounts were found in scope'
        $automatedEvidence = @($result.TestResults | Where-Object { $_.'Evidence Type' -eq 'Automated' })
        $automatedEvidence.Count | Should -Be 14
        @($automatedEvidence.'Test #') | Should -Be @(
            'TC1.1', 'TC1.2', 'TC1.3', 'TC1.4',
            'TC2.1', 'TC2.2', 'TC2.3',
            'TC3.1', 'TC3.2', 'TC3.3',
            'TC4.1', 'TC4.2',
            'TC5.1', 'TC5.2'
        )
        foreach ($evidence in $automatedEvidence) {
            $evidence.Status | Should -BeIn @('PASS', 'FAIL', 'WARN', 'SKIP')
            $evidence.Details | Should -Not -BeNullOrEmpty
            $evidence.Source | Should -Not -BeNullOrEmpty
            $evidence.Query | Should -Not -BeNullOrEmpty
        }
        @($result.TestResults | Where-Object Status -eq 'MANUAL').Count | Should -BeGreaterThan 0
    }

    It 'passes Defender checks only when applicable assessment coverage exists' {
        Mock Search-AzGraph {
            param($Query, $First, [switch]$UseTenantScope)

            if ($Query -match 'HighSevFindings') {
                return [PSCustomObject]@{ CoverageCount = 12; HighSevFindings = 0; CriticalFindings = 0; HighFindings = 0 }
            }
            if ($Query -match 'MissingPatches') {
                return [PSCustomObject]@{ CoverageCount = 8; MissingPatches = 0; AffectedResources = 0 }
            }
            if ($Query -match 'TotalHighCvss') {
                return [PSCustomObject]@{ CoverageCount = 6; TotalHighCvss = 0; PatchableCount = 0; CriticalCvss = 0 }
            }
            if ($Query -match 'EolFindings') {
                return [PSCustomObject]@{ CoverageCount = 4; EolFindings = 0; AffectedResources = 0 }
            }
            if ($Query -match 'TotalAccounts') {
                return [PSCustomObject]@{ TotalAccounts = 2; PublicAccessEnabled = 0; NotHttpsOnly = 0; OldTls = 0 }
            }
            @()
        }

        $result = Invoke-CEPPlusTechnicalAssessment -PolicyAssignments @([PSCustomObject]@{})

        foreach ($testId in @('TC1.3', 'TC1.4', 'TC2.1', 'TC2.2', 'TC2.3')) {
            ($result.TestResults | Where-Object { $_.'Test #' -eq $testId }).Status | Should -Be 'PASS'
        }
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC1' }).Status | Should -Be 'PASS'
        ($result.TestResults | Where-Object { $_.'Test #' -eq 'TC2' }).Status | Should -Be 'PASS'
    }
}