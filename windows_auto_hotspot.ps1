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

    [Parameter(ParameterSetName = "Disable", Mandatory = $true)]
    [switch]$Disable,

    [Parameter(ParameterSetName = "Enable", Mandatory = $true)]
    [switch]$Enable,

    [Parameter(ParameterSetName = "Toggle", Mandatory = $true)]
    [switch]$Toggle,

    [Parameter(ParameterSetName = "OpenLog", Mandatory = $true)]
    [switch]$OpenLog,

    [Parameter(ParameterSetName = "Doctor", Mandatory = $true)]
    [switch]$Doctor,

    [Parameter(ParameterSetName = "Update", Mandatory = $true)]
    [switch]$Update,

    [Parameter(ParameterSetName = "Repair", Mandatory = $true)]
    [switch]$Repair,

    [Parameter(ParameterSetName = "ConfigShow", Mandatory = $true)]
    [switch]$ConfigShow,

    [Parameter(ParameterSetName = "ConfigSet", Mandatory = $true)]
    [switch]$ConfigSet,

    [Parameter(ParameterSetName = "ConfigSet", Mandatory = $true)]
    [string[]]$Set,

    [string]$TaskName = "WindowsAutoHotspot",

    [string]$InstallDir = "$env:ProgramData\WindowsAutoHotspot",

    [string]$LogPath,

    [int]$CheckIntervalSec = 5,

    [int]$UpStableChecks = 2,

    [int]$DownStableChecks = 2,

    [string]$AdapterName,

    [int]$CooldownOnFailMin = 5,

    [int]$CooldownOffFailMin = 2,

    [int]$CooldownOnExceptionSec = 30,

    [switch]$ForceOffWhenDisabled,

    [switch]$Quiet,

    [switch]$NoDelay,

    [string]$SourceUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:StateDir = Join-Path $env:LOCALAPPDATA "WindowsAutoHotspot"
$script:DisableFlagPath = Join-Path $script:StateDir "hotspot.disabled"
$script:ConfigPath = Join-Path $script:StateDir "config.json"
$script:InstalledScriptPath = Join-Path $InstallDir "windows-auto-hotspot.ps1"

function Ensure-Path {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Resolve-LogPath {
    param([string]$Candidate)
    try {
        Ensure-Path (Split-Path -Parent $Candidate)
        Add-Content -LiteralPath $Candidate -Value "" -Encoding UTF8 -ErrorAction Stop
        return $Candidate
    } catch {
        $fallback = Join-Path $script:StateDir "windows-auto-hotspot.log"
        try {
            Ensure-Path (Split-Path -Parent $fallback)
            Add-Content -LiteralPath $fallback -Value "" -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch {}
        return $fallback
    }
}

Ensure-Path $script:StateDir

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

if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $LogPath = Join-Path $script:StateDir "windows-auto-hotspot.log"
}
$LogPath = Resolve-LogPath $LogPath

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

function Convert-ConfigValue {
    param([string]$Value)
    if ($Value -match '^(?i:true|false)$') { return [bool]::Parse($Value) }
    $i = 0
    if ([int]::TryParse($Value, [ref]$i)) { return $i }
    return $Value
}

function Get-DefaultConfig {
    [pscustomobject]@{
        CheckIntervalSec = 5
        UpStableChecks = 2
        DownStableChecks = 2
        AdapterName = ""
        CooldownOnFailMin = 5
        CooldownOffFailMin = 2
        CooldownOnExceptionSec = 30
        ForceOffWhenDisabled = $true
        LogPath = (Join-Path $script:StateDir "windows-auto-hotspot.log")
    }
}

function Load-Config {
    $d = Get-DefaultConfig
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) { return $d }

    try {
        $raw = Get-Content -LiteralPath $script:ConfigPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $d }
        $cfg = $raw | ConvertFrom-Json -ErrorAction Stop

        foreach ($p in $d.PSObject.Properties.Name) {
            if ($null -eq $cfg.PSObject.Properties[$p]) { $cfg | Add-Member -MemberType NoteProperty -Name $p -Value $d.$p -Force }
        }

        return $cfg
    } catch {
        return $d
    }
}

function Save-Config {
    param($Cfg)
    Ensure-Path $script:StateDir
    $Cfg | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
}

function Apply-Config {
    $cfg = Load-Config

    if (-not $PSBoundParameters.ContainsKey("CheckIntervalSec")) { $script:CheckIntervalSec = [int]$cfg.CheckIntervalSec } else { $script:CheckIntervalSec = $CheckIntervalSec }
    if (-not $PSBoundParameters.ContainsKey("UpStableChecks")) { $script:UpStableChecks = [int]$cfg.UpStableChecks } else { $script:UpStableChecks = $UpStableChecks }
    if (-not $PSBoundParameters.ContainsKey("DownStableChecks")) { $script:DownStableChecks = [int]$cfg.DownStableChecks } else { $script:DownStableChecks = $DownStableChecks }
    if (-not $PSBoundParameters.ContainsKey("AdapterName")) { $script:AdapterName = [string]$cfg.AdapterName } else { $script:AdapterName = $AdapterName }
    if (-not $PSBoundParameters.ContainsKey("CooldownOnFailMin")) { $script:CooldownOnFailMin = [int]$cfg.CooldownOnFailMin } else { $script:CooldownOnFailMin = $CooldownOnFailMin }
    if (-not $PSBoundParameters.ContainsKey("CooldownOffFailMin")) { $script:CooldownOffFailMin = [int]$cfg.CooldownOffFailMin } else { $script:CooldownOffFailMin = $CooldownOffFailMin }
    if (-not $PSBoundParameters.ContainsKey("CooldownOnExceptionSec")) { $script:CooldownOnExceptionSec = [int]$cfg.CooldownOnExceptionSec } else { $script:CooldownOnExceptionSec = $CooldownOnExceptionSec }

    if (-not $PSBoundParameters.ContainsKey("ForceOffWhenDisabled")) {
        $script:ForceOffWhenDisabled = [bool]$cfg.ForceOffWhenDisabled
    } else {
        $script:ForceOffWhenDisabled = $true
    }

    if (-not $PSBoundParameters.ContainsKey("LogPath")) {
        $script:LogPath = Resolve-LogPath ([string]$cfg.LogPath)
    } else {
        $script:LogPath = Resolve-LogPath $LogPath
    }

    $global:CheckIntervalSec = $script:CheckIntervalSec
    $global:UpStableChecks = $script:UpStableChecks
    $global:DownStableChecks = $script:DownStableChecks
    $global:AdapterName = $script:AdapterName
    $global:CooldownOnFailMin = $script:CooldownOnFailMin
    $global:CooldownOffFailMin = $script:CooldownOffFailMin
    $global:CooldownOnExceptionSec = $script:CooldownOnExceptionSec
    $global:ForceOffWhenDisabled = $script:ForceOffWhenDisabled
    $global:LogPath = $script:LogPath
}

Apply-Config

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
        if ($script:AdapterName) {
            $all = $all | Where-Object { $_.Name -eq $script:AdapterName }
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

function Test-WifiAdapterPresent {
    try {
        $all = Get-NetAdapter -ErrorAction SilentlyContinue
        $wifi = $all | Where-Object {
            $_.Status -ne "Disabled" -and (
                $_.InterfaceDescription -match "Wi-?Fi|Wireless|802\.11" -or
                ($_.NdisPhysicalMedium -eq 9)
            )
        }
        return ($null -ne $wifi)
    } catch {
        return $false
    }
}

function Get-TetheringCapabilityText {
    param($Mgr)
    try {
        $cap = $Mgr.TetheringCapability
        if ($null -eq $cap) { return "Unknown" }
        return $cap.ToString()
    } catch {
        return "Unknown"
    }
}

function Ensure-Hotspot {
    param(
        [ValidateSet("On","Off")]
        [string]$Desired
    )

    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) {
        Write-Log "Hotspot manager not available (no connection profile)." "ERROR"
        return $false
    }

    $capText = Get-TetheringCapabilityText $mgr
    if ($capText -ne "Enabled" -and $capText -ne "Unknown") {
        Write-Log "Hotspot not available. Capability: $capText" "ERROR"
        return $false
    }

    $state = "Unknown"
    try { $state = $mgr.TetheringOperationalState.ToString() } catch {}

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
    $m = $null
    try {
        $m = New-Object System.Threading.Mutex($false, "Global\WindowsAutoHotspot_Mutex")
    } catch {
        $m = New-Object System.Threading.Mutex($false, "Local\WindowsAutoHotspot_Mutex")
    }

    $ok = $false
    try { $ok = $m.WaitOne(0, $false) } catch { $ok = $true }
    if (-not $ok) { return $null }
    return $m
}

function Stop-OldMonitorProcess {
    param([string]$ScriptPath)

    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            $cmd = $p.CommandLine
            if ($cmd -and $cmd -like "*$ScriptPath*" -and $cmd -like "* -Run*") {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}

function Is-AutomationDisabled {
    return (Test-Path -LiteralPath $script:DisableFlagPath)
}

function Set-DisabledFlag {
    param([bool]$Disabled)

    Ensure-Path $script:StateDir

    if ($Disabled) {
        Set-Content -LiteralPath $script:DisableFlagPath -Value "disabled" -Encoding UTF8
        Write-Log "Automation disabled by user." "WARN"
    } else {
        Remove-Item -LiteralPath $script:DisableFlagPath -Force -ErrorAction SilentlyContinue
        Write-Log "Automation enabled by user." "OK"
    }
}

function Open-LogFile {
    try {
        if (-not (Test-Path -LiteralPath $script:LogPath)) { return }
        Start-Process -FilePath "notepad.exe" -ArgumentList "`"$script:LogPath`""
    } catch {}
}

function New-Shortcut {
    param(
        [string]$LinkPath,
        [string]$TargetPath,
        [string]$Arguments,
        [string]$WorkingDirectory,
        [string]$IconLocation
    )

    try {
        Ensure-Path (Split-Path -Parent $LinkPath)
        $wsh = New-Object -ComObject WScript.Shell
        $sc = $wsh.CreateShortcut($LinkPath)
        $sc.TargetPath = $TargetPath
        $sc.Arguments = $Arguments
        if ($WorkingDirectory) { $sc.WorkingDirectory = $WorkingDirectory }
        if ($IconLocation) { $sc.IconLocation = $IconLocation }
        $sc.Save()
    } catch {}
}

function Create-Shortcuts {
    param([string]$InstalledScriptPath)

    $ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $icon = (Join-Path $env:SystemRoot "System32\shell32.dll") + ",44"

    $commonStart = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    $folder = Join-Path $commonStart "Windows Auto Hotspot"
    Ensure-Path $folder

    $publicDesktop = Join-Path $env:Public "Desktop"

    $baseArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$InstalledScriptPath`""

    New-Shortcut (Join-Path $folder "Enable Hotspot Automation.lnk") $ps "$baseArgs -Enable" $env:WINDIR $icon
    New-Shortcut (Join-Path $folder "Disable Hotspot Automation.lnk") $ps "$baseArgs -Disable" $env:WINDIR $icon
    New-Shortcut (Join-Path $folder "Toggle Hotspot Automation.lnk") $ps "$baseArgs -Toggle" $env:WINDIR $icon
    New-Shortcut (Join-Path $folder "Status.lnk") $ps "$baseArgs -Status" $env:WINDIR $icon
    New-Shortcut (Join-Path $folder "Open Log.lnk") $ps "$baseArgs -OpenLog" $env:WINDIR $icon

    New-Shortcut (Join-Path $publicDesktop "Hotspot Enable.lnk") $ps "$baseArgs -Enable" $env:WINDIR $icon
    New-Shortcut (Join-Path $publicDesktop "Hotspot Disable.lnk") $ps "$baseArgs -Disable" $env:WINDIR $icon
    New-Shortcut (Join-Path $publicDesktop "Hotspot Toggle.lnk") $ps "$baseArgs -Toggle" $env:WINDIR $icon
}

function Remove-Shortcuts {
    $commonStart = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    $folder = Join-Path $commonStart "Windows Auto Hotspot"
    $publicDesktop = Join-Path $env:Public "Desktop"

    $toRemove = @(
        (Join-Path $publicDesktop "Hotspot Enable.lnk"),
        (Join-Path $publicDesktop "Hotspot Disable.lnk"),
        (Join-Path $publicDesktop "Hotspot Toggle.lnk")
    )

    foreach ($p in $toRemove) {
        try { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } catch {}
    }

    try { Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

function Build-TaskArgs {
    param([string]$InstalledScriptPath)

    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", "`"$InstalledScriptPath`"",
        "-Run",
        "-Quiet",
        "-CheckIntervalSec", $script:CheckIntervalSec,
        "-UpStableChecks", $script:UpStableChecks,
        "-DownStableChecks", $script:DownStableChecks,
        "-CooldownOnFailMin", $script:CooldownOnFailMin,
        "-CooldownOffFailMin", $script:CooldownOffFailMin,
        "-CooldownOnExceptionSec", $script:CooldownOnExceptionSec,
        "-LogPath", "`"$script:LogPath`""
    )

    if ($script:AdapterName) {
        $args += @("-AdapterName", "`"$script:AdapterName`"")
    }

    if ($script:ForceOffWhenDisabled) {
        $args += @("-ForceOffWhenDisabled")
    }

    return $args
}

function Register-OrRepairTask {
    param([string]$InstalledScriptPath)

    $userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $taskArgs = Build-TaskArgs $InstalledScriptPath

    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 500

    Stop-OldMonitorProcess $InstalledScriptPath

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ($taskArgs -join " ")
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Highest

    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Days 3650) `
        -MultipleInstances IgnoreNew `
        -RestartCount 60 `
        -RestartInterval (New-TimeSpan -Minutes 1)

    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

    $started = $false
    $st = "Unknown"

    try {
        Start-ScheduledTask -TaskName $TaskName
        $deadline = (Get-Date).AddSeconds(5)
        do {
            $st = (Get-ScheduledTask -TaskName $TaskName).State
            if ($st -eq "Running") { $started = $true; break }
            Start-Sleep -Milliseconds 250
        } while ((Get-Date) -lt $deadline)
    } catch {}

    if (-not $started) {
        $p = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-WindowStyle", "Hidden",
            "-File", "`"$InstalledScriptPath`"",
            "-Run",
            "-Quiet",
            "-CheckIntervalSec", $script:CheckIntervalSec,
            "-UpStableChecks", $script:UpStableChecks,
            "-DownStableChecks", $script:DownStableChecks,
            "-CooldownOnFailMin", $script:CooldownOnFailMin,
            "-CooldownOffFailMin", $script:CooldownOffFailMin,
            "-CooldownOnExceptionSec", $script:CooldownOnExceptionSec,
            "-LogPath", "`"$script:LogPath`""
        )

        if ($script:AdapterName) { $p += @("-AdapterName", "`"$script:AdapterName`"") }
        if ($script:ForceOffWhenDisabled) { $p += @("-ForceOffWhenDisabled") }

        Start-Process -FilePath "powershell.exe" -ArgumentList ($p -join " ") -WindowStyle Hidden
    }

    return $st
}

function Install-App {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to install." -ForegroundColor Red
        exit 1
    }

    Ensure-Path $InstallDir
    Ensure-Path $script:StateDir

    $cfg = Load-Config
    $cfg.CheckIntervalSec = $script:CheckIntervalSec
    $cfg.UpStableChecks = $script:UpStableChecks
    $cfg.DownStableChecks = $script:DownStableChecks
    $cfg.AdapterName = $script:AdapterName
    $cfg.CooldownOnFailMin = $script:CooldownOnFailMin
    $cfg.CooldownOffFailMin = $script:CooldownOffFailMin
    $cfg.CooldownOnExceptionSec = $script:CooldownOnExceptionSec
    $cfg.ForceOffWhenDisabled = $script:ForceOffWhenDisabled
    $cfg.LogPath = $script:LogPath
    Save-Config $cfg

    $srcPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($srcPath) -or -not (Test-Path -LiteralPath $srcPath)) {
        if ([string]::IsNullOrWhiteSpace($SourceUrl)) {
            Write-Host "This script has no file path. Use -SourceUrl to install from URL." -ForegroundColor Red
            exit 1
        }
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $SourceUrl -OutFile $script:InstalledScriptPath
        } catch {
            Write-Host ("Download failed: " + $_.Exception.Message) -ForegroundColor Red
            exit 1
        }
    } else {
        Copy-Item -LiteralPath $srcPath -Destination $script:InstalledScriptPath -Force
    }

    $st = Register-OrRepairTask $script:InstalledScriptPath
    Create-Shortcuts $script:InstalledScriptPath

    Write-Host "Task state: $st" -ForegroundColor Cyan
    Write-Host "Installed. Task created: $TaskName" -ForegroundColor Green
    Write-Host "Logs: $script:LogPath" -ForegroundColor Cyan
    Write-Host "Start Menu: Windows Auto Hotspot" -ForegroundColor Gray
    Write-Host "Desktop shortcuts created on Public Desktop" -ForegroundColor Gray
}

function Uninstall-App {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to uninstall." -ForegroundColor Red
        exit 1
    }

    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 300

    try { Stop-OldMonitorProcess $script:InstalledScriptPath } catch {}

    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}

    try { Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item -LiteralPath $script:StateDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}

    Remove-Shortcuts

    Write-Host "Uninstalled. Task removed and files deleted." -ForegroundColor Yellow
}

function Show-Status {
    $eth = Get-EthernetState
    Write-Host ("Ethernet Up: " + $eth.IsUp) -ForegroundColor Cyan
    if ($eth.Names) { Write-Host ("Adapters: " + ($eth.Names -join ", ")) -ForegroundColor Cyan }

    Write-Host ("Automation disabled: " + (Is-AutomationDisabled)) -ForegroundColor Yellow
    Write-Host ("Config: " + $script:ConfigPath) -ForegroundColor Gray

    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) {
        Write-Host "Hotspot: Unknown (no connection profile)" -ForegroundColor Yellow
    } else {
        $cap = Get-TetheringCapabilityText $mgr
        $st = "Unknown"
        try { $st = $mgr.TetheringOperationalState.ToString() } catch {}
        Write-Host ("Hotspot: " + $st + " | Capability: " + $cap) -ForegroundColor Green
    }

    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Host ("Scheduled task: Present (" + $t.State + ")") -ForegroundColor Green
    } catch {
        Write-Host "Scheduled task: Not found" -ForegroundColor Red
    }

    Write-Host ("Log file: " + $script:LogPath) -ForegroundColor Gray
}

function Run-Monitor {
    $mutex = Acquire-SingleInstance
    if ($null -eq $mutex) { return }

    try {
        $script:LogPath = Resolve-LogPath $script:LogPath

        if (-not (Test-WifiAdapterPresent)) {
            Write-Log "No Wi-Fi adapter detected. Hotspot cannot work. Exiting monitor." "ERROR"
            return
        }

        $mgr = Get-TetheringManagerSafe
        if ($null -eq $mgr) {
            Write-Log "Hotspot manager not available (no connection profile). Exiting monitor." "ERROR"
            return
        }

        $cap = Get-TetheringCapabilityText $mgr
        if ($cap -ne "Enabled" -and $cap -ne "Unknown") {
            Write-Log "Hotspot not available. Capability: $cap. Exiting monitor." "ERROR"
            return
        }

        Write-Log "Windows Auto Hotspot started." "INFO"
        Write-Log "Interval: $script:CheckIntervalSec sec. Stable Up: $script:UpStableChecks. Stable Down: $script:DownStableChecks." "DEBUG"
        if ($script:AdapterName) { Write-Log "Adapter filter: $script:AdapterName" "DEBUG" }
        Write-Log "Log path: $script:LogPath" "DEBUG"

        $upCount = 0
        $downCount = 0
        $lastWanted = ""
        $cooldownUntil = Get-Date

        while ($true) {
            try {
                if (Is-AutomationDisabled) {
                    if ($script:ForceOffWhenDisabled) { $null = Ensure-Hotspot "Off" }
                    Start-Sleep -Seconds $script:CheckIntervalSec
                    continue
                }

                if ((Get-Date) -lt $cooldownUntil) {
                    Start-Sleep -Seconds $script:CheckIntervalSec
                    continue
                }

                $eth = Get-EthernetState

                if ($eth.IsUp) {
                    $upCount++
                    $downCount = 0
                    if ($upCount -ge $script:UpStableChecks) {
                        if ($lastWanted -ne "On") {
                            $names = ""
                            if ($eth.Names) { $names = ($eth.Names -join ", ") }
                            Write-Log "Ethernet stable ON. $names" "OK"
                            $lastWanted = "On"
                        }
                        $ok = Ensure-Hotspot "On"
                        if (-not $ok) { $cooldownUntil = (Get-Date).AddMinutes([int]$script:CooldownOnFailMin) }
                    }
                } else {
                    $downCount++
                    $upCount = 0
                    if ($downCount -ge $script:DownStableChecks) {
                        if ($lastWanted -ne "Off") {
                            Write-Log "Ethernet stable OFF." "WARN"
                            $lastWanted = "Off"
                        }
                        $ok = Ensure-Hotspot "Off"
                        if (-not $ok) { $cooldownUntil = (Get-Date).AddMinutes([int]$script:CooldownOffFailMin) }
                    }
                }
            } catch {
                Write-Log ("Monitor error: " + $_.Exception.Message) "ERROR"
                $cooldownUntil = (Get-Date).AddSeconds([int]$script:CooldownOnExceptionSec)
            }

            Start-Sleep -Seconds $script:CheckIntervalSec
        }
    } finally {
        try { $mutex.ReleaseMutex() } catch {}
        try { $mutex.Dispose() } catch {}
    }
}

function Run-Once {
    $script:LogPath = Resolve-LogPath $script:LogPath

    if (Is-AutomationDisabled) {
        Write-Log "Automation is disabled." "WARN"
        if ($script:ForceOffWhenDisabled) { $null = Ensure-Hotspot "Off" }
        return
    }

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

function Disable-Automation {
    Set-DisabledFlag $true
    if ($script:ForceOffWhenDisabled) { $null = Ensure-Hotspot "Off" }
}

function Enable-Automation {
    Set-DisabledFlag $false
}

function Toggle-Automation {
    if (Is-AutomationDisabled) {
        Set-DisabledFlag $false
    } else {
        Set-DisabledFlag $true
        if ($script:ForceOffWhenDisabled) { $null = Ensure-Hotspot "Off" }
    }
}

function Show-Doctor {
    $wifi = Test-WifiAdapterPresent
    $mgr = Get-TetheringManagerSafe
    $cap = "Unknown"
    $hst = "Unknown"
    if ($null -ne $mgr) {
        $cap = Get-TetheringCapabilityText $mgr
        try { $hst = $mgr.TetheringOperationalState.ToString() } catch {}
    }

    Write-Host "Doctor Report" -ForegroundColor Cyan
    Write-Host ("Admin: " + (Test-Admin)) -ForegroundColor Gray
    Write-Host ("Wi-Fi present: " + $wifi) -ForegroundColor Gray
    Write-Host ("Hotspot capability: " + $cap) -ForegroundColor Gray
    Write-Host ("Hotspot state: " + $hst) -ForegroundColor Gray
    Write-Host ("Automation disabled: " + (Is-AutomationDisabled)) -ForegroundColor Gray
    Write-Host ("TaskName: " + $TaskName) -ForegroundColor Gray
    Write-Host ("InstallDir: " + $InstallDir) -ForegroundColor Gray
    Write-Host ("InstalledScript: " + $script:InstalledScriptPath) -ForegroundColor Gray
    Write-Host ("StateDir: " + $script:StateDir) -ForegroundColor Gray
    Write-Host ("ConfigPath: " + $script:ConfigPath) -ForegroundColor Gray
    Write-Host ("LogPath: " + $script:LogPath) -ForegroundColor Gray

    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Host ("Task: Present (" + $t.State + ")") -ForegroundColor Gray
    } catch {
        Write-Host "Task: Not found" -ForegroundColor Gray
    }
}

function Do-Repair {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to repair." -ForegroundColor Red
        exit 1
    }

    if (-not (Test-Path -LiteralPath $script:InstalledScriptPath)) {
        Write-Host "Installed script not found. Install first." -ForegroundColor Red
        exit 1
    }

    $cfg = Load-Config
    $script:CheckIntervalSec = [int]$cfg.CheckIntervalSec
    $script:UpStableChecks = [int]$cfg.UpStableChecks
    $script:DownStableChecks = [int]$cfg.DownStableChecks
    $script:AdapterName = [string]$cfg.AdapterName
    $script:CooldownOnFailMin = [int]$cfg.CooldownOnFailMin
    $script:CooldownOffFailMin = [int]$cfg.CooldownOffFailMin
    $script:CooldownOnExceptionSec = [int]$cfg.CooldownOnExceptionSec
    $script:ForceOffWhenDisabled = [bool]$cfg.ForceOffWhenDisabled
    $script:LogPath = Resolve-LogPath ([string]$cfg.LogPath)

    $st = Register-OrRepairTask $script:InstalledScriptPath
    Create-Shortcuts $script:InstalledScriptPath

    Write-Host "Task state: $st" -ForegroundColor Cyan
    Write-Host "Repair done." -ForegroundColor Green
}

function Do-Update {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to update." -ForegroundColor Red
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($SourceUrl)) {
        Write-Host "Use -SourceUrl to update from URL." -ForegroundColor Red
        exit 1
    }

    Ensure-Path $InstallDir

    $tmp = Join-Path $env:TEMP ("windows-auto-hotspot.update." + [DateTime]::UtcNow.Ticks + ".ps1")
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $SourceUrl -OutFile $tmp
    } catch {
        Write-Host ("Download failed: " + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }

    $ok = $false
    try {
        $content = Get-Content -LiteralPath $tmp -Raw -ErrorAction Stop
        if ($content -match "WindowsAutoHotspot" -and $content -match "Run-Monitor") { $ok = $true }
    } catch { $ok = $false }

    if (-not $ok) {
        Write-Host "Downloaded file does not look valid. Aborting." -ForegroundColor Red
        try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch {}
        exit 1
    }

    try {
        Copy-Item -LiteralPath $tmp -Destination $script:InstalledScriptPath -Force
    } catch {
        Write-Host ("Update copy failed: " + $_.Exception.Message) -ForegroundColor Red
        exit 1
    } finally {
        try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch {}
    }

    Write-Host "Updated installed script." -ForegroundColor Green
    Do-Repair
}

function Show-Config {
    $cfg = Load-Config
    $cfg | ConvertTo-Json -Depth 6 | Write-Host
}

function Set-ConfigValues {
    $cfg = Load-Config

    foreach ($item in $Set) {
        if ([string]::IsNullOrWhiteSpace($item)) { continue }
        $parts = $item.Split("=", 2)
        if ($parts.Count -ne 2) { continue }
        $k = $parts[0].Trim()
        $v = $parts[1].Trim()
        if ([string]::IsNullOrWhiteSpace($k)) { continue }

        $val = Convert-ConfigValue $v

        if ($null -eq $cfg.PSObject.Properties[$k]) {
            $cfg | Add-Member -MemberType NoteProperty -Name $k -Value $val -Force
        } else {
            $cfg.$k = $val
        }
    }

    foreach ($p in (Get-DefaultConfig).PSObject.Properties.Name) {
        if ($null -eq $cfg.PSObject.Properties[$p]) { $cfg | Add-Member -MemberType NoteProperty -Name $p -Value (Get-DefaultConfig).$p -Force }
    }

    Save-Config $cfg
    Write-Host "Config saved: $script:ConfigPath" -ForegroundColor Green

    if (Test-Admin) {
        try {
            $exists = $false
            try { $null = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop; $exists = $true } catch { $exists = $false }
            if ($exists) {
                Do-Repair
            } else {
                Write-Host "Task not found. Run -Install." -ForegroundColor Yellow
            }
        } catch {}
    } else {
        Write-Host "Config saved. Run PowerShell as Admin and use -Repair to apply." -ForegroundColor Yellow
    }
}

switch ($PSCmdlet.ParameterSetName) {
    "Install"   { Install-App; break }
    "Uninstall" { Uninstall-App; break }
    "Status"    { Show-Status; break }
    "Run"       { Run-Monitor; break }
    "Once"      { Run-Once; break }
    "Disable"   { Disable-Automation; break }
    "Enable"    { Enable-Automation; break }
    "Toggle"    { Toggle-Automation; break }
    "OpenLog"   { Open-LogFile; break }
    "Doctor"    { Show-Doctor; break }
    "Repair"    { Do-Repair; break }
    "Update"    { Do-Update; break }
    "ConfigShow"{ Show-Config; break }
    "ConfigSet" { Set-ConfigValues; break }
    default {
        Write-Host "Usage:" -ForegroundColor Cyan
        Write-Host "  -Install    (needs Admin)" -ForegroundColor Gray
        Write-Host "  -Uninstall  (needs Admin)" -ForegroundColor Gray
        Write-Host "  -Run        (monitor loop)" -ForegroundColor Gray
        Write-Host "  -Once       (single check)" -ForegroundColor Gray
        Write-Host "  -Status     (show status)" -ForegroundColor Gray
        Write-Host "  -Disable    (stop forcing hotspot)" -ForegroundColor Gray
        Write-Host "  -Enable     (allow forcing hotspot)" -ForegroundColor Gray
        Write-Host "  -Toggle     (enable or disable)" -ForegroundColor Gray
        Write-Host "  -OpenLog    (open log in Notepad)" -ForegroundColor Gray
        Write-Host "  -Doctor     (diagnostic report)" -ForegroundColor Gray
        Write-Host "  -ConfigShow (print config)" -ForegroundColor Gray
        Write-Host "  -ConfigSet  -Set Key=Value ..." -ForegroundColor Gray
        Write-Host "  -Repair     (recreate task + shortcuts, needs Admin)" -ForegroundColor Gray
        Write-Host "  -Update     -SourceUrl <url> (needs Admin)" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        Write-Host "Examples:" -ForegroundColor Cyan
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Install" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Disable" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Enable" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Toggle" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -OpenLog" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Doctor" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -ConfigSet -Set CheckIntervalSec=3 AdapterName=Ethernet" -ForegroundColor Gray
        break
    }
}
