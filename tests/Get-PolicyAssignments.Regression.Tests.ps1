#Requires -Version 7.0
#Requires -Module @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    $RepoRoot = Split-Path $PSScriptRoot -Parent
    $ScriptPath = Join-Path $RepoRoot 'Get-PolicyAssignments.ps1'
    $ManifestPath = Join-Path $RepoRoot 'VERSION.json'
    $ReadmePath = Join-Path $RepoRoot 'README.md'

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
        'Resolve-AIProvider',
        'New-AIPromptPayload',
        'Get-FallbackALZPolicies',
        'Get-PolicyRecommendation'
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

    It 'retains the official-source functions' {
        $functionNames = @($TopLevelFunctions.Name)
        @(
            'Resolve-AIProvider',
            'Get-ALZRecommendedPolicies',
            'Get-FallbackALZPolicies',
            'Get-PolicyRecommendation',
            'Export-HTMLReport'
        ) | ForEach-Object { $functionNames | Should -Contain $_ }
    }
}

Describe 'GitHub Models provider contract' {
    It 'does not resolve a provider when AI is disabled' {
        Resolve-AIProvider -AI Off -AIKey 'unused' -AIModel 'openai/gpt-4.1' | Should -BeNullOrEmpty
    }

    It 'uses the current endpoint, model ID, permission-era headers, and supplied token' {
        $provider = Resolve-AIProvider -AI Summary -AIKey 'regression-token' -AIModel 'openai/gpt-4.1'

        $provider.Provider | Should -Be 'GitHub Models'
        $provider.Endpoint | Should -Be 'https://models.github.ai/inference/chat/completions'
        $provider.Model | Should -Be 'openai/gpt-4.1'
        $provider.Headers.Authorization | Should -Be 'Bearer regression-token'
        $provider.Headers.Accept | Should -Be 'application/vnd.github+json'
        $provider.Headers.'X-GitHub-Api-Version' | Should -Match '^\d{4}-\d{2}-\d{2}$'
    }

    It 'builds deterministic requests without static pricing claims' {
        $provider = Resolve-AIProvider -AI Summary -AIKey 'regression-token' -AIModel 'openai/gpt-4.1'
        $payload = New-AIPromptPayload -Mode Summary -Metrics @{ policyCount = 1 } -AIConfig $provider | ConvertFrom-Json

        $payload.model | Should -Be 'openai/gpt-4.1'
        $payload.temperature | Should -Be 0
        $payload.messages[0].content | Should -Match 'not measured'
        $payload.messages[0].content | Should -Not -Match '\$\d+(\.\d+)?\s+per\s+(GB|hour|month|1K)'
    }

    It 'contains no legacy GitHub Models endpoint or scope guidance' {
        $ScriptText | Should -Not -Match 'models\.inference\.ai\.azure\.com'
        $ScriptText | Should -Not -Match 'read:models|No special scopes'
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
        $ScriptText | Should -Match '\$officialDefinitionId\s*=\s*\$script:ALZPolicyDefinitionIds'
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

    It 'requires DINE remediation verification instead of declaring failure' {
        $ScriptText | Should -Match 'remediationReviewNote'
        $ScriptText | Should -Match 'checking remediation task status'
        $ScriptText | Should -Match 'does not by itself prove broken auto-remediation'
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
}