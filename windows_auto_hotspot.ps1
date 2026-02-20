[CmdletBinding(DefaultParameterSetName = "Help")]
param(
    [Parameter(ParameterSetName = "Install", Mandatory = $true)]
    [switch]$Install,

    [Parameter(ParameterSetName = "Uninstall", Mandatory = $true)]
    [switch]$Uninstall,

    [Parameter(ParameterSetName = "Run", Mandatory = $true)]
    [switch]$Run,

    [Parameter(ParameterSetName = "Once", Mandatory = $true)]
    [switch]$Once,

    [Parameter(ParameterSetName = "Status", Mandatory = $true)]
    [switch]$Status,

    [string]$TaskName = "WindowsAutoHotspot",

    [string]$InstallDir = "$env:ProgramData\WindowsAutoHotspot",

    [string]$LogPath,

    [int]$CheckIntervalSec = 5,

    [int]$UpStableChecks = 2,

    [int]$DownStableChecks = 2,

    [string]$AdapterName,

    [switch]$Quiet,

    [switch]$NoDelay,

    [string]$SourceUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $LogPath = Join-Path $InstallDir "windows-auto-hotspot.log"
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Interactive {
    try {
        if ($Quiet) { return $false }
        if ($Host -and $Host.UI -and $Host.Name -notlike "*Server*") { return $true }
        return $false
    } catch {
        return $false
    }
}

$script:IsInteractive = Test-Interactive

function Ui-Pause {
    if ($NoDelay) { return }
    if (-not $script:IsInteractive) { return }
    Start-Sleep -Milliseconds 800
}

function Ensure-Path {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","OK","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts [$Level] $Message"

    try {
        Ensure-Path (Split-Path -Parent $LogPath)
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    } catch {}

    if (-not $Quiet) {
        $color = "Gray"
        switch ($Level) {
            "OK"    { $color = "Green" }
            "WARN"  { $color = "Yellow" }
            "ERROR" { $color = "Red" }
            "DEBUG" { $color = "DarkGray" }
            default { $color = "Cyan" }
        }
        Write-Host $line -ForegroundColor $color
        Ui-Pause
    }
}

function Wait-AsyncOp {
    param(
        $Op,
        [int]$TimeoutSec = 30
    )

    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $status = $Op.Status.ToString()
        if ($status -ne "Started") { break }
        if ($sw.Elapsed.TotalSeconds -ge $TimeoutSec) { break }
        Start-Sleep -Milliseconds 100
    }

    $final = $Op.Status.ToString()
    if ($final -eq "Completed") {
        try { $null = $Op.GetResults() } catch {}
        return $true
    }

    if ($final -eq "Error") {
        try {
            $code = $Op.ErrorCode
            Write-Log "Async error. Code: $code" "ERROR"
        } catch {
            Write-Log "Async error." "ERROR"
        }
        return $false
    }

    Write-Log "Async timeout. Status: $final" "ERROR"
    return $false
}

function Get-EthernetState {
    $adapters = @()
    try {
        $all = Get-NetAdapter -ErrorAction SilentlyContinue
        if ($AdapterName) {
            $all = $all | Where-Object { $_.Name -eq $AdapterName }
        }
        $adapters = $all | Where-Object { $_.Status -eq "Up" -and $_.MediaType -eq "802.3" }
    } catch {
        $adapters = @()
    }

    [pscustomobject]@{
        IsUp = ($adapters.Count -gt 0)
        Names = ($adapters | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue)
    }
}

function Get-ConnectionProfileSafe {
    try {
        $ni = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]
        $p = $ni::GetInternetConnectionProfile()
        if ($null -ne $p) { return $p }

        $profiles = $ni::GetConnectionProfiles()
        foreach ($x in $profiles) {
            try {
                $lvl = $x.GetNetworkConnectivityLevel().ToString()
                if ($lvl -ne "None") { return $x }
            } catch {}
        }

        return $null
    } catch {
        return $null
    }
}

function Get-TetheringManagerSafe {
    try {
        $profile = Get-ConnectionProfileSafe
        if ($null -eq $profile) { return $null }

        $tm = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]
        return $tm::CreateFromConnectionProfile($profile)
    } catch {
        return $null
    }
}

function Ensure-Hotspot {
    param(
        [ValidateSet("On","Off")]
        [string]$Desired
    )

    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) {
        Write-Log "No connection profile. Cannot control hotspot." "WARN"
        return $false
    }

    $state = $mgr.TetheringOperationalState.ToString()
    if ($Desired -eq "On") {
        if ($state -eq "On") { return $true }
        Write-Log "Turning hotspot ON..." "INFO"
        try {
            $op = $mgr.StartTetheringAsync()
            $ok = Wait-AsyncOp $op 30
            if ($ok) { Write-Log "Hotspot is ON." "OK" }
            return $ok
        } catch {
            Write-Log ("Failed to start hotspot: " + $_.Exception.Message) "ERROR"
            return $false
        }
    } else {
        if ($state -eq "Off") { return $true }
        Write-Log "Turning hotspot OFF..." "INFO"
        try {
            $op = $mgr.StopTetheringAsync()
            $ok = Wait-AsyncOp $op 30
            if ($ok) { Write-Log "Hotspot is OFF." "OK" }
            return $ok
        } catch {
            Write-Log ("Failed to stop hotspot: " + $_.Exception.Message) "ERROR"
            return $false
        }
    }
}

function Acquire-SingleInstance {
    $name = "Local\WindowsAutoHotspot_Mutex"
    $m = New-Object System.Threading.Mutex($false, $name)
    $ok = $false
    try { $ok = $m.WaitOne(0, $false) } catch { $ok = $true }
    if (-not $ok) { return $null }
    return $m
}

function Install-App {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to install." -ForegroundColor Red
        exit 1
    }

    Ensure-Path $InstallDir

    $srcPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($srcPath) -or -not (Test-Path -LiteralPath $srcPath)) {
        if ([string]::IsNullOrWhiteSpace($SourceUrl)) {
            Write-Host "This script has no file path. Use -SourceUrl to install from URL." -ForegroundColor Red
            exit 1
        }
        $dest = Join-Path $InstallDir "windows-auto-hotspot.ps1"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $SourceUrl -OutFile $dest
        } catch {
            Write-Host ("Download failed: " + $_.Exception.Message) -ForegroundColor Red
            exit 1
        }
    } else {
        $dest = Join-Path $InstallDir "windows-auto-hotspot.ps1"
        Copy-Item -LiteralPath $srcPath -Destination $dest -Force
    }

    Ensure-Path (Split-Path -Parent $LogPath)
    if (-not (Test-Path -LiteralPath $LogPath)) {
        New-Item -ItemType File -Path $LogPath -Force | Out-Null
    }

    $userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", "`"$dest`"",
        "-Run",
        "-Quiet",
        "-CheckIntervalSec", $CheckIntervalSec,
        "-UpStableChecks", $UpStableChecks,
        "-DownStableChecks", $DownStableChecks,
        "-LogPath", "`"$LogPath`""
    )

    if ($AdapterName) {
        $args += @("-AdapterName", "`"$AdapterName`"")
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ($args -join " ")
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
    
    try {
        $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType InteractiveToken -RunLevel Highest
    } catch {
        $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Highest
    }
    
    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Days 3650) `
        -MultipleInstances IgnoreNew `
        -RestartCount 10 `
        -RestartInterval (New-TimeSpan -Minutes 1)
    
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

    Write-Host "Installed. Task Scheduler task created: $TaskName" -ForegroundColor Green
    Write-Host "Logs: $LogPath" -ForegroundColor Cyan
}

function Uninstall-App {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to uninstall." -ForegroundColor Red
        exit 1
    }

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    try {
        if (Test-Path -LiteralPath $InstallDir) {
            Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {}

    Write-Host "Uninstalled. Task removed and files deleted." -ForegroundColor Yellow
}

function Show-Status {
    $eth = Get-EthernetState
    Write-Host ("Ethernet Up: " + $eth.IsUp) -ForegroundColor Cyan
    if ($eth.Names) {
        Write-Host ("Adapters: " + ($eth.Names -join ", ")) -ForegroundColor Cyan
    }

    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) {
        Write-Host "Hotspot state: Unknown (no connection profile)" -ForegroundColor Yellow
    } else {
        Write-Host ("Hotspot state: " + $mgr.TetheringOperationalState.ToString()) -ForegroundColor Green
    }

    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Host ("Scheduled task: Present (" + $t.State + ")") -ForegroundColor Green
    } catch {
        Write-Host "Scheduled task: Not found" -ForegroundColor Red
    }

    Write-Host ("Log file: " + $LogPath) -ForegroundColor Gray
}

function Run-Monitor {
    $mutex = Acquire-SingleInstance
    if ($null -eq $mutex) { return }

    try {
        Write-Log "Windows Auto Hotspot started." "INFO"
        Write-Log "Interval: $CheckIntervalSec sec. Stable Up: $UpStableChecks. Stable Down: $DownStableChecks." "DEBUG"
        if ($AdapterName) { Write-Log "Adapter filter: $AdapterName" "DEBUG" }
        Write-Log "Log path: $LogPath" "DEBUG"

        $upCount = 0
        $downCount = 0
        $lastWanted = ""

        while ($true) {
            $eth = Get-EthernetState

            if ($eth.IsUp) {
                $upCount++
                $downCount = 0
                if ($upCount -ge $UpStableChecks) {
                    if ($lastWanted -ne "On") {
                        $names = ""
                        if ($eth.Names) { $names = ($eth.Names -join ", ") }
                        Write-Log "Ethernet stable ON. $names" "OK"
                        $lastWanted = "On"
                    }
                    $null = Ensure-Hotspot "On"
                }
            } else {
                $downCount++
                $upCount = 0
                if ($downCount -ge $DownStableChecks) {
                    if ($lastWanted -ne "Off") {
                        Write-Log "Ethernet stable OFF." "WARN"
                        $lastWanted = "Off"
                    }
                    $null = Ensure-Hotspot "Off"
                }
            }

            Start-Sleep -Seconds $CheckIntervalSec
        }
    } finally {
        try { $mutex.ReleaseMutex() } catch {}
        try { $mutex.Dispose() } catch {}
    }
}

function Run-Once {
    Write-Log "Running one check..." "INFO"
    $eth = Get-EthernetState
    if ($eth.IsUp) {
        $names = ""
        if ($eth.Names) { $names = ($eth.Names -join ", ") }
        Write-Log "Ethernet is ON. $names" "OK"
        $null = Ensure-Hotspot "On"
    } else {
        Write-Log "Ethernet is OFF." "WARN"
        $null = Ensure-Hotspot "Off"
    }
}

switch ($PSCmdlet.ParameterSetName) {
    "Install"   { Install-App; break }
    "Uninstall" { Uninstall-App; break }
    "Status"    { Show-Status; break }
    "Run"       { Run-Monitor; break }
    "Once"      { Run-Once; break }
    default {
        Write-Host "Usage:" -ForegroundColor Cyan
        Write-Host "  -Install    (needs Admin)" -ForegroundColor Gray
        Write-Host "  -Uninstall  (needs Admin)" -ForegroundColor Gray
        Write-Host "  -Run        (monitor loop)" -ForegroundColor Gray
        Write-Host "  -Once       (single check)" -ForegroundColor Gray
        Write-Host "  -Status     (show status)" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        Write-Host "Examples:" -ForegroundColor Cyan
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows-auto-hotspot.ps1 -Install" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows-auto-hotspot.ps1 -Status" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows-auto-hotspot.ps1 -Uninstall" -ForegroundColor Gray
        break
    }
}

