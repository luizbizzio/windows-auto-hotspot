[CmdletBinding(DefaultParameterSetName = "Help")]
param(
    [Parameter(ParameterSetName = "Install", Mandatory = $true)]
    [switch]$Install,

    [Parameter(ParameterSetName = "Uninstall", Mandatory = $true)]
    [switch]$Uninstall,

    [Parameter(ParameterSetName = "Run", Mandatory = $true)]
    [switch]$Run,

    [Parameter(ParameterSetName = "Status", Mandatory = $true)]
    [switch]$Status,

    [Parameter(ParameterSetName = "Disable", Mandatory = $true)]
    [switch]$Disable,

    [Parameter(ParameterSetName = "Enable", Mandatory = $true)]
    [switch]$Enable,

    [Parameter(ParameterSetName = "Toggle", Mandatory = $true)]
    [switch]$Toggle,

    [Parameter(ParameterSetName = "Repair", Mandatory = $true)]
    [switch]$Repair,

    [Parameter(ParameterSetName = "Update", Mandatory = $true)]
    [switch]$Update,

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
$script:StartMenuFolderName = "Windows Auto Hotspot"
$script:ToggleBaseName = "Windows Auto Hotspot Toggle"
$script:IsInteractive = $false

function Ensure-Path {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
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

function Resolve-LogPath {
    param([string]$Candidate)

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        $Candidate = Join-Path $script:StateDir "windows-auto-hotspot.log"
    }

    try {
        $parent = Split-Path -Parent $Candidate
        Ensure-Path $parent
        if (-not (Test-Path -LiteralPath $Candidate)) {
            New-Item -ItemType File -Path $Candidate -Force | Out-Null
        } else {
            Add-Content -LiteralPath $Candidate -Value "" -Encoding UTF8 -ErrorAction Stop
        }
        return $Candidate
    } catch {
        $fallback = Join-Path $script:StateDir "windows-auto-hotspot.log"
        try {
            Ensure-Path (Split-Path -Parent $fallback)
            if (-not (Test-Path -LiteralPath $fallback)) {
                New-Item -ItemType File -Path $fallback -Force | Out-Null
            }
        } catch {}
        return $fallback
    }
}

Ensure-Path $script:StateDir

if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $LogPath = Join-Path $script:StateDir "windows-auto-hotspot.log"
}
$script:LogPath = Resolve-LogPath $LogPath

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","OK","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts [$Level] $Message"

    try {
        Ensure-Path (Split-Path -Parent $script:LogPath)
        Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
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
            if ($null -eq $cfg.PSObject.Properties[$p]) {
                $cfg | Add-Member -MemberType NoteProperty -Name $p -Value $d.$p -Force
            }
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

    if ($PSBoundParameters.ContainsKey("CheckIntervalSec")) { $script:CheckIntervalSec = [int]$CheckIntervalSec } else { $script:CheckIntervalSec = [int]$cfg.CheckIntervalSec }
    if ($PSBoundParameters.ContainsKey("UpStableChecks")) { $script:UpStableChecks = [int]$UpStableChecks } else { $script:UpStableChecks = [int]$cfg.UpStableChecks }
    if ($PSBoundParameters.ContainsKey("DownStableChecks")) { $script:DownStableChecks = [int]$DownStableChecks } else { $script:DownStableChecks = [int]$cfg.DownStableChecks }
    if ($PSBoundParameters.ContainsKey("AdapterName")) { $script:AdapterName = [string]$AdapterName } else { $script:AdapterName = [string]$cfg.AdapterName }
    if ($PSBoundParameters.ContainsKey("CooldownOnFailMin")) { $script:CooldownOnFailMin = [int]$CooldownOnFailMin } else { $script:CooldownOnFailMin = [int]$cfg.CooldownOnFailMin }
    if ($PSBoundParameters.ContainsKey("CooldownOffFailMin")) { $script:CooldownOffFailMin = [int]$CooldownOffFailMin } else { $script:CooldownOffFailMin = [int]$cfg.CooldownOffFailMin }
    if ($PSBoundParameters.ContainsKey("CooldownOnExceptionSec")) { $script:CooldownOnExceptionSec = [int]$CooldownOnExceptionSec } else { $script:CooldownOnExceptionSec = [int]$cfg.CooldownOnExceptionSec }

    if ($PSBoundParameters.ContainsKey("ForceOffWhenDisabled")) {
        $script:ForceOffWhenDisabled = $true
    } else {
        $script:ForceOffWhenDisabled = [bool]$cfg.ForceOffWhenDisabled
    }

    if ($PSBoundParameters.ContainsKey("LogPath")) {
        $script:LogPath = Resolve-LogPath $LogPath
    } else {
        $script:LogPath = Resolve-LogPath ([string]$cfg.LogPath)
    }
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
        $all = @(Get-NetAdapter -ErrorAction SilentlyContinue)

        if ($script:AdapterName) {
            $all = @($all | Where-Object { $_ -and $_.Name -eq $script:AdapterName })
        } else {
            $all = @($all | Where-Object { $_ })
        }

        $adapters = @(
            $all | Where-Object {
                $_.Status -eq "Up" -and (
                    $_.MediaType -eq "802.3" -or
                    $_.NdisPhysicalMedium -eq 0 -or
                    $_.InterfaceDescription -match "Ethernet|GbE|LAN|USB.*Ethernet"
                )
            }
        )
    } catch {
        $adapters = @()
    }

    $names = @()
    try {
        $names = @($adapters | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue)
    } catch {
        $names = @()
    }

    [pscustomobject]@{
        IsUp  = (@($adapters).Count -gt 0)
        Names = @($names)
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
        $all = @(Get-NetAdapter -ErrorAction SilentlyContinue)
        $wifi = @(
            $all | Where-Object {
                $_ -and $_.Status -ne "Disabled" -and (
                    $_.InterfaceDescription -match "Wi-?Fi|Wireless|802\.11" -or
                    $_.Name -match "Wi-?Fi|Wireless" -or
                    $_.NdisPhysicalMedium -eq 9
                )
            }
        )
        return ($wifi.Count -gt 0)
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
        $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -in @("powershell.exe","pwsh.exe")
        })

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

function Get-HotspotSystemIconLocation {
    $candidates = @(
        (Join-Path $env:SystemRoot "System32\pnidui.dll") + ",6",
        (Join-Path $env:SystemRoot "System32\netshell.dll") + ",86",
        (Join-Path $env:SystemRoot "System32\imageres.dll") + ",171",
        (Join-Path $env:SystemRoot "System32\shell32.dll") + ",44"
    )

    foreach ($c in $candidates) {
        $file = $c.Split(",")[0]
        if (Test-Path -LiteralPath $file) { return $c }
    }

    return ((Join-Path $env:SystemRoot "System32\shell32.dll") + ",44")
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

function Remove-ToggleShortcuts {
    $commonStart = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    $folder = Join-Path $commonStart $script:StartMenuFolderName
    $publicDesktop = Join-Path $env:Public "Desktop"
    $userDesktop = [Environment]::GetFolderPath("Desktop")

    $names = @(
        "🟢 $($script:ToggleBaseName).lnk",
        "🔴 $($script:ToggleBaseName).lnk",
        "$($script:ToggleBaseName).lnk"
    )

    foreach ($n in $names) {
        foreach ($root in @($folder, $publicDesktop, $userDesktop)) {
            if ([string]::IsNullOrWhiteSpace($root)) { continue }
            $p = Join-Path $root $n
            try { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } catch {}
        }
    }

    try {
        if (Test-Path -LiteralPath $folder) {
            $remaining = @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue)
            if ($remaining.Count -eq 0) {
                Remove-Item -LiteralPath $folder -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}

function Get-ToggleShortcutFileName {
    if (Is-AutomationDisabled) {
        return "🔴 $($script:ToggleBaseName).lnk"
    }
    return "🟢 $($script:ToggleBaseName).lnk"
}

function Refresh-ToggleShortcuts {
    param([string]$InstalledScriptPath)

    if ([string]::IsNullOrWhiteSpace($InstalledScriptPath)) { return }
    if (-not (Test-Path -LiteralPath $InstalledScriptPath)) { return }

    Remove-ToggleShortcuts

    $ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path -LiteralPath $ps)) { $ps = "powershell.exe" }

    $icon = Get-HotspotSystemIconLocation

    $commonStart = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    $folder = Join-Path $commonStart $script:StartMenuFolderName
    Ensure-Path $folder

    $publicDesktop = Join-Path $env:Public "Desktop"
    $name = Get-ToggleShortcutFileName
    $baseArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$InstalledScriptPath`" -Toggle"

    New-Shortcut (Join-Path $folder $name) $ps $baseArgs $env:WINDIR $icon
    New-Shortcut (Join-Path $publicDesktop $name) $ps $baseArgs $env:WINDIR $icon
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

function Get-TaskStateSafe {
    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        return [string]$t.State
    } catch {
        return "NotFound"
    }
}

function Register-OrRepairTask {
    param([string]$InstalledScriptPath)

    $userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $taskArgs = Build-TaskArgs $InstalledScriptPath

    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 400

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
        $deadline = (Get-Date).AddSeconds(6)
        do {
            $st = Get-TaskStateSafe
            if ($st -eq "Running") {
                $started = $true
                break
            }
            Start-Sleep -Milliseconds 250
        } while ((Get-Date) -lt $deadline)
    } catch {}

    if (-not $started) {
        $p = Build-TaskArgs $InstalledScriptPath
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList ($p -join " ") -WindowStyle Hidden
        } catch {}
        Start-Sleep -Milliseconds 500
        $st = Get-TaskStateSafe
    }

    return $st
}

function Save-CurrentConfig {
    $cfg = Get-DefaultConfig
    $cfg.CheckIntervalSec = [int]$script:CheckIntervalSec
    $cfg.UpStableChecks = [int]$script:UpStableChecks
    $cfg.DownStableChecks = [int]$script:DownStableChecks
    $cfg.AdapterName = [string]$script:AdapterName
    $cfg.CooldownOnFailMin = [int]$script:CooldownOnFailMin
    $cfg.CooldownOffFailMin = [int]$script:CooldownOffFailMin
    $cfg.CooldownOnExceptionSec = [int]$script:CooldownOnExceptionSec
    $cfg.ForceOffWhenDisabled = [bool]$script:ForceOffWhenDisabled
    $cfg.LogPath = [string]$script:LogPath
    Save-Config $cfg
}

function Clean-InstallArtifactsOnly {
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 300
    try { Stop-OldMonitorProcess $script:InstalledScriptPath } catch {}
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    Remove-ToggleShortcuts
}

function Install-App {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to install." -ForegroundColor Red
        exit 1
    }

    Write-Host "Installing (clean reinstall mode)..." -ForegroundColor Cyan

    Clean-InstallArtifactsOnly

    Ensure-Path $InstallDir
    Ensure-Path $script:StateDir

    Save-CurrentConfig

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
    Refresh-ToggleShortcuts $script:InstalledScriptPath

    Write-Host "Task state: $st" -ForegroundColor Cyan
    Write-Host "Installed. Task created: $TaskName" -ForegroundColor Green
    Write-Host "Logs: $script:LogPath" -ForegroundColor Cyan
    Write-Host "Desktop + Start Menu toggle shortcut refreshed." -ForegroundColor Gray
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

    Remove-ToggleShortcuts

    Write-Host "Uninstalled. Task, files and shortcuts removed." -ForegroundColor Yellow
}

function Start-TaskIfPresent {
    try {
        $null = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        try { Start-ScheduledTask -TaskName $TaskName } catch {}
    } catch {}
}

function Disable-Automation {
    Set-DisabledFlag $true
    Refresh-ToggleShortcuts $script:InstalledScriptPath
    if ($script:ForceOffWhenDisabled) { $null = Ensure-Hotspot "Off" }
    Write-Host "Automation disabled." -ForegroundColor Yellow
}

function Enable-Automation {
    Set-DisabledFlag $false
    Refresh-ToggleShortcuts $script:InstalledScriptPath
    Start-TaskIfPresent
    Write-Host "Automation enabled." -ForegroundColor Green
}

function Toggle-Automation {
    if (Is-AutomationDisabled) {
        Enable-Automation
    } else {
        Disable-Automation
    }
}

function Show-Status {
    $eth = Get-EthernetState
    Write-Host ("Ethernet Up: " + $eth.IsUp) -ForegroundColor Cyan
    if (@($eth.Names).Count -gt 0) {
        Write-Host ("Adapters: " + (@($eth.Names) -join ", ")) -ForegroundColor Cyan
    }

    Write-Host ("Automation disabled: " + (Is-AutomationDisabled)) -ForegroundColor Yellow

    $wifiPresent = Test-WifiAdapterPresent
    Write-Host ("Wi-Fi adapter present: " + $wifiPresent) -ForegroundColor Gray

    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) {
        Write-Host "Hotspot: Unknown (no connection profile)" -ForegroundColor Yellow
    } else {
        $cap = Get-TetheringCapabilityText $mgr
        $hst = "Unknown"
        try { $hst = $mgr.TetheringOperationalState.ToString() } catch {}
        Write-Host ("Hotspot: " + $hst + " | Capability: " + $cap) -ForegroundColor Green
    }

    Write-Host ("Scheduled task: " + (Get-TaskStateSafe)) -ForegroundColor Gray
    Write-Host ("Installed script: " + $script:InstalledScriptPath) -ForegroundColor Gray
    Write-Host ("Config: " + $script:ConfigPath) -ForegroundColor Gray
    Write-Host ("Log: " + $script:LogPath) -ForegroundColor Gray
}

function Do-Repair {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to repair." -ForegroundColor Red
        exit 1
    }

    if (-not (Test-Path -LiteralPath $script:InstalledScriptPath)) {
        Write-Host "Installed script not found. Run -Install first." -ForegroundColor Red
        exit 1
    }

    Apply-Config
    Save-CurrentConfig

    $st = Register-OrRepairTask $script:InstalledScriptPath
    Refresh-ToggleShortcuts $script:InstalledScriptPath

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
    } catch {
        $ok = $false
    }

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

    Write-Host "Installed script updated." -ForegroundColor Green
    Do-Repair
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
                            if (@($eth.Names).Count -gt 0) { $names = (@($eth.Names) -join ", ") }
                            Write-Log "Ethernet stable ON. $names" "OK"
                            $lastWanted = "On"
                        }

                        $ok = Ensure-Hotspot "On"
                        if (-not $ok) {
                            $cooldownUntil = (Get-Date).AddMinutes([int]$script:CooldownOnFailMin)
                        }
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
                        if (-not $ok) {
                            $cooldownUntil = (Get-Date).AddMinutes([int]$script:CooldownOffFailMin)
                        }
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

try {
    switch ($PSCmdlet.ParameterSetName) {
        "Install"   { Install-App; break }
        "Uninstall" { Uninstall-App; break }
        "Run"       { Run-Monitor; break }
        "Status"    { Show-Status; break }
        "Disable"   { Disable-Automation; break }
        "Enable"    { Enable-Automation; break }
        "Toggle"    { Toggle-Automation; break }
        "Repair"    { Do-Repair; break }
        "Update"    { Do-Update; break }
        default {
            Write-Host "Usage:" -ForegroundColor Cyan
            Write-Host "  -Install    (needs Admin, clean reinstall)" -ForegroundColor Gray
            Write-Host "  -Uninstall  (needs Admin)" -ForegroundColor Gray
            Write-Host "  -Status" -ForegroundColor Gray
            Write-Host "  -Enable" -ForegroundColor Gray
            Write-Host "  -Disable" -ForegroundColor Gray
            Write-Host "  -Toggle" -ForegroundColor Gray
            Write-Host "  -Repair     (needs Admin)" -ForegroundColor Gray
            Write-Host "  -Update -SourceUrl <url> (needs Admin)" -ForegroundColor Gray
            Write-Host "" -ForegroundColor Gray
            Write-Host "Examples:" -ForegroundColor Cyan
            Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Install" -ForegroundColor Gray
            Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Toggle" -ForegroundColor Gray
            Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Repair" -ForegroundColor Gray
            break
        }
    }
} catch {
    $msg = $_.Exception.Message
    try { Write-Log ("Fatal error: " + $msg) "ERROR" } catch {}
    Write-Host ("Error: " + $msg) -ForegroundColor Red
    exit 1
}
