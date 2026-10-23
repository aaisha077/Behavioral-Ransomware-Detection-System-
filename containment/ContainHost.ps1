<#
.SYNOPSIS
    BRDS-PEC Host Network Isolation Script

.DESCRIPTION
    Disables all active network adapters to isolate a compromised host.
    Execution mode is determined by the BRDS_LIVE_CONTAINMENT environment
    variable AND a separately verified HMAC arm token.  Neither condition
    alone is sufficient for live action.

    Mode resolution (evaluated in order):
      1. If BRDS_LIVE_CONTAINMENT != "1"  -> dry-run (log only)
      2. If -DryRunOverride switch present -> dry-run (caller forces simulation)
      3. If -Armed switch NOT present      -> dry-run
      4. All three conditions met          -> live containment

    Adapter state persistence:
      Before disabling any adapter the script writes a JSON state file listing
      the adapter names that were Up at containment time.  RollbackHost.ps1
      reads this file and re-enables ONLY those adapters, preventing incorrect
      re-enablement of adapters already disabled before containment ran.

.PARAMETER Armed
    Must be passed by trigger_daemon.py after independently verifying the
    HMAC-signed arm token.  This switch alone does NOT enable live action;
    BRDS_LIVE_CONTAINMENT must also be set.

.PARAMETER DryRunOverride
    Force dry-run regardless of other flags.  Used in CI / unit tests.

.PARAMETER StateFilePath
    Path to write the adapter state JSON file.  Defaults to
    containment_state.json beside this script.

.EXAMPLE
    # Always dry-run (default lab safe behaviour):
    .\ContainHost.ps1

    # Live containment (VM detonation lab only):
    $env:BRDS_LIVE_CONTAINMENT = "1"
    .\ContainHost.ps1 -Armed
#>

[CmdletBinding()]
param (
    [switch]$Armed = $false,
    [Alias("DryRun")]
    [switch]$DryRunOverride = $false,
    [string]$StateFilePath = ""
)

# Resolve default StateFilePath here (not in param block) so $PSScriptRoot is
# already populated. $PSScriptRoot is empty when param defaults are parsed on
# Windows PowerShell 5.x.
if ([string]::IsNullOrWhiteSpace($StateFilePath)) {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $StateFilePath = Join-Path $PSScriptRoot "containment_state.json"
    } else {
        $StateFilePath = Join-Path (Get-Location).Path "containment_state.json"
    }
}

# Mode resolution
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
    Write-Warning "[BRDS-PEC] Mode: LIVE CONTAINMENT (BRDS_LIVE_CONTAINMENT=1 and -Armed verified)"
}

# Adapter isolation
Write-Host "[BRDS-PEC] Executing Host Isolation..."

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

if ($adapters.Count -eq 0) {
    Write-Host "[BRDS-PEC] No active network adapters detected."
    exit 0
}

# Build the list of adapter names for state persistence
$adapterNamesList = @($adapters | ForEach-Object { $_.Name })

# Persist adapter names that were Up so RollbackHost.ps1 can restore ONLY
# those adapters (not ones pre-disabled for other reasons).
# Use [ordered] hashtable + ConvertTo-Json for PS5-compatible JSON output.
$stateObj = [ordered]@{
    timestamp               = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    disabled_by_containment = $adapterNamesList
    dry_run                 = $DryRun
}

if ($DryRun) {
    Write-Host "[DRY-RUN] Would write adapter state to: $StateFilePath"
    Write-Host "[DRY-RUN] State would contain: $($adapterNamesList -join ', ')"
} else {
    try {
        $stateObj | ConvertTo-Json -Depth 3 | Set-Content -Path $StateFilePath -Encoding UTF8 -ErrorAction Stop
        Write-Host "[CONTAINMENT] Adapter state written to: $StateFilePath"
    } catch {
        Write-Warning "[CONTAINMENT] Could not write adapter state file. Rollback may be imprecise."
    }
}

$disabled = @()
foreach ($adapter in $adapters) {
    Write-Host "[BRDS-PEC] Target adapter: $($adapter.Name) ($($adapter.InterfaceDescription))"
    if ($DryRun) {
        Write-Host "[DRY-RUN] Would disable adapter: $($adapter.Name)"
    } else {
        Write-Host "[CONTAINMENT] Disabling network adapter: $($adapter.Name)..."
        try {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
            Write-Host "[CONTAINMENT] Adapter $($adapter.Name) disabled."
            $disabled += $adapter.Name
        } catch {
            Write-Warning "Could not disable adapter $($adapter.Name)"
        }
    }
}

Write-Host "[BRDS-PEC] Host isolation completed. DryRun=$DryRun DisabledAdapters=$($disabled.Count)"
