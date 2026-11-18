<#
.SYNOPSIS
    BRDS-PEC Lab Network Rollback Script

.DESCRIPTION
    Re-enables network adapters that were disabled by ContainHost.ps1 during
    a lab detonation test.

    State-aware rollback: if a containment_state.json file exists (written by
    ContainHost.ps1), only the adapters listed in disabled_by_containment are
    re-enabled.  This prevents restoring adapters that were already disabled
    before containment ran.

    Security fail-safe: if the containment state file is missing, corrupt,
    or empty, rollback aborts with an error rather than indiscriminately
    enabling all disabled adapters on the system.

    Mode guard: requires BRDS_LIVE_CONTAINMENT=1 AND -Armed, identical to
    ContainHost.ps1, so a misconfigured environment cannot accidentally
    re-enable adapters mid-test.

.PARAMETER Armed
    Must be explicitly passed.  Requires BRDS_LIVE_CONTAINMENT=1 to execute.

.PARAMETER DryRunOverride
    Force dry-run for CI / testing.

.PARAMETER StateFilePath
    Path to the adapter state JSON file written by ContainHost.ps1.
    Defaults to containment_state.json beside this script.

.EXAMPLE
    $env:BRDS_LIVE_CONTAINMENT = "1"
    .\RollbackHost.ps1 -Armed
#>

[CmdletBinding()]
param (
    [switch]$Armed = $false,
    [switch]$DryRunOverride = $false,
    [string]$StateFilePath = ""
)

# Resolve default StateFilePath here (not in param block) so $PSScriptRoot is
# already populated. $PSScriptRoot is empty when the default expression in
# [param()] is parsed on Windows PowerShell 5.x.
if ([string]::IsNullOrWhiteSpace($StateFilePath)) {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $StateFilePath = Join-Path $PSScriptRoot "containment_state.json"
    } else {
        $StateFilePath = Join-Path (Get-Location).Path "containment_state.json"
    }
}

# Mode resolution (identical guard to ContainHost.ps1)
$liveContainmentEnv = [System.Environment]::GetEnvironmentVariable("BRDS_LIVE_CONTAINMENT")
$envArmed = ($liveContainmentEnv -eq "1")

if ($DryRunOverride.IsPresent) {
    $DryRun = $true
    Write-Host "[BRDS-PEC] Mode: DRY-RUN (DryRunOverride flag set)"
} elseif (-not $Armed.IsPresent) {
    $DryRun = $true
    Write-Host "[BRDS-PEC] Mode: DRY-RUN (-Armed not passed by caller)"
} elseif (-not $envArmed) {
    $DryRun = $true
    Write-Warning "[BRDS-PEC] Mode: DRY-RUN (BRDS_LIVE_CONTAINMENT not set to 1)"
} else {
    $DryRun = $false
    Write-Warning "[BRDS-PEC] Mode: LIVE ROLLBACK (BRDS_LIVE_CONTAINMENT=1 and -Armed verified)"
}

# Determine which adapters to restore
Write-Host "[BRDS-PEC] Starting network rollback..."

if (-not (Test-Path $StateFilePath)) {
    Write-Warning "[SECURITY FAIL-SAFE] No containment state file found at: $StateFilePath"
    Write-Warning "[SECURITY FAIL-SAFE] Aborting rollback to prevent unintended adapter re-enablement."
    exit 1
}

try {
    $rawContent = Get-Content -Path $StateFilePath -Raw -ErrorAction Stop
    $state = $rawContent | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Warning "[SECURITY FAIL-SAFE] Could not parse containment state file: $StateFilePath"
    Write-Warning "[SECURITY FAIL-SAFE] Aborting rollback to prevent unintended adapter re-enablement."
    exit 1
}

if ($null -eq $state -or -not ($state -is [System.Management.Automation.PSCustomObject])) {
    Write-Warning "[SECURITY FAIL-SAFE] Containment state file is not a valid JSON object: $StateFilePath"
    Write-Warning "[SECURITY FAIL-SAFE] Aborting rollback to prevent unintended adapter re-enablement."
    exit 1
}

$prop = $state.PSObject.Properties['disabled_by_containment']
if ($null -eq $prop) {
    Write-Warning "[SECURITY FAIL-SAFE] Containment state file missing required property 'disabled_by_containment': $StateFilePath"
    Write-Warning "[SECURITY FAIL-SAFE] Aborting rollback to prevent unintended adapter re-enablement."
    exit 1
}

$val = $prop.Value
if ($null -eq $val) {
    Write-Warning "[SECURITY FAIL-SAFE] Property 'disabled_by_containment' in state file cannot be null: $StateFilePath"
    Write-Warning "[SECURITY FAIL-SAFE] Aborting rollback to prevent unintended adapter re-enablement."
    exit 1
}

$adapterNamesToRestore = @()
if ($val -is [System.Array] -or $val -is [System.Collections.IList]) {
    foreach ($item in $val) {
        if (-not ($item -is [string]) -or [string]::IsNullOrWhiteSpace($item)) {
            Write-Warning "[SECURITY FAIL-SAFE] Property 'disabled_by_containment' contains invalid non-string adapter entry: $StateFilePath"
            Write-Warning "[SECURITY FAIL-SAFE] Aborting rollback to prevent unintended adapter re-enablement."
            exit 1
        }
        $adapterNamesToRestore += [string]$item
    }
} elseif ($val -is [string]) {
    if ([string]::IsNullOrWhiteSpace($val)) {
        Write-Warning "[SECURITY FAIL-SAFE] Property 'disabled_by_containment' string is empty: $StateFilePath"
        Write-Warning "[SECURITY FAIL-SAFE] Aborting rollback to prevent unintended adapter re-enablement."
        exit 1
    }
    $adapterNamesToRestore += [string]$val
} else {
    Write-Warning "[SECURITY FAIL-SAFE] Property 'disabled_by_containment' has invalid type: $StateFilePath"
    Write-Warning "[SECURITY FAIL-SAFE] Aborting rollback to prevent unintended adapter re-enablement."
    exit 1
}

Write-Host "[BRDS-PEC] State file found: $StateFilePath"
Write-Host "[BRDS-PEC] Adapters recorded for rollback: $($adapterNamesToRestore -join ', ')"

if ($adapterNamesToRestore.Count -eq 0) {
    Write-Host "[BRDS-PEC] State file records 0 adapters disabled by containment. Nothing to restore."
    exit 0
}

# State-aware path: ONLY restore recorded adapters
$restored = @()
foreach ($adapterName in $adapterNamesToRestore) {
    $adapter = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
    if ($null -eq $adapter) {
        Write-Warning "[BRDS-PEC] Adapter '$adapterName' from state file not found on system, skipping."
        continue
    }
    Write-Host "[BRDS-PEC] Adapter to restore: $adapterName (status: $($adapter.Status))"
    if ($DryRun) {
        Write-Host "[DRY-RUN] Would re-enable adapter: $adapterName"
    } else {
        Write-Host "[ROLLBACK] Re-enabling network adapter: $adapterName..."
        try {
            Enable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction Stop
            Write-Host "[ROLLBACK] Adapter $adapterName re-enabled."
            $restored += $adapterName
        } catch {
            Write-Warning "Could not re-enable adapter $adapterName"
        }
    }
}
Write-Host "[BRDS-PEC] Network rollback completed. DryRun=$DryRun RestoredAdapters=$($restored.Count)"
