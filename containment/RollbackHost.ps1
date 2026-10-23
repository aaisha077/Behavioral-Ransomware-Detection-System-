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

    If no state file is found, the script falls back to re-enabling all
    currently Disabled adapters and emits a warning.

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

$adapterNamesToRestore = $null

if (Test-Path $StateFilePath) {
    try {
        $state = Get-Content -Path $StateFilePath -Raw | ConvertFrom-Json
        $adapterNamesToRestore = $state.disabled_by_containment
        Write-Host "[BRDS-PEC] State file found: $StateFilePath"
        Write-Host "[BRDS-PEC] Adapters recorded for rollback: $($adapterNamesToRestore -join ', ')"
    } catch {
        Write-Warning "[BRDS-PEC] Could not parse state file. Falling back to all disabled adapters."
        $adapterNamesToRestore = $null
    }
} else {
    Write-Warning "[BRDS-PEC] No state file found at: $StateFilePath"
    Write-Warning "[BRDS-PEC] Falling back to re-enabling ALL currently Disabled adapters (imprecise)."
}

# Re-enable adapters
if ($null -ne $adapterNamesToRestore -and $adapterNamesToRestore.Count -gt 0) {
    # State-aware path: only restore recorded adapters
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
} else {
    # Fallback: re-enable all currently Disabled adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" }

    if ($adapters.Count -eq 0) {
        Write-Host "[BRDS-PEC] No disabled network adapters found. Nothing to restore."
        exit 0
    }

    $restored = @()
    foreach ($adapter in $adapters) {
        Write-Host "[BRDS-PEC] Disabled adapter found: $($adapter.Name)"
        if ($DryRun) {
            Write-Host "[DRY-RUN] Would re-enable adapter: $($adapter.Name)"
        } else {
            Write-Host "[ROLLBACK] Re-enabling network adapter: $($adapter.Name)..."
            try {
                Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
                Write-Host "[ROLLBACK] Adapter $($adapter.Name) re-enabled."
                $restored += $adapter.Name
            } catch {
                Write-Warning "Could not re-enable adapter $($adapter.Name)"
            }
        }
    }
    Write-Host "[BRDS-PEC] Network rollback completed (fallback). DryRun=$DryRun RestoredAdapters=$($restored.Count)"
}
