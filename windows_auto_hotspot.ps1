[CmdletBinding(DefaultParameterSetName = "Help")]
param(
    [Parameter(ParameterSetName = "Install", Mandatory = $true)]
    [switch]$Install,

    [Parameter(ParameterSetName = "Uninstall", Mandatory = $true)]
    [switch]$Uninstall,

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

    [Parameter(ParameterSetName = "Repair", Mandatory = $true)]
    [switch]$Repair,

    [Parameter(ParameterSetName = "Update", Mandatory = $true)]
    [switch]$Update,

    [Parameter(ParameterSetName = "Worker", Mandatory = $true)]
    [switch]$Worker,

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
$script:DisableFlagPath = Join-Path $script:StateDir "automation.disabled"
$script:ConfigPath = Join-Path $script:StateDir "config.json"
$script:InstalledScriptPath = Join-Path $InstallDir "windows-auto-hotspot.ps1"
$script:ShortcutFolderName = "Windows Auto Hotspot"
$script:DesktopToggleBaseName = "Hotspot Toggle"

$script:IconToggleOn = "$env:SystemRoot\System32\imageres.dll,109"
$script:IconToggleOff = "$env:SystemRoot\System32\imageres.dll,110"
$script:IconEnable = "$env:SystemRoot\System32\shell32.dll,167"
$script:IconDisable = "$env:SystemRoot\System32\shell32.dll,131"
$script:IconStatus = "$env:SystemRoot\System32\shell32.dll,23"
$script:IconOpenLog = "$env:SystemRoot\System32\shell32.dll,70"

function Ensure-Path {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Remove-PathSafe {
    param([string]$Path)
    try {
        if (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path -LiteralPath $Path)) {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {}
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

Ensure-Path $script:StateDir

function Resolve-LogPath {
    param([string]$Candidate)

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        $Candidate = Join-Path $script:StateDir "windows-auto-hotspot.log"
    }

    try {
        $dir = Split-Path -Parent $Candidate
        Ensure-Path $dir
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

function Show-Notify {
    param(
        [string]$Title,
        [string]$Text
    )

    if (-not $script:IsInteractive) { return }

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop

        $ni = New-Object System.Windows.Forms.NotifyIcon
        $ni.Icon = [System.Drawing.SystemIcons]::Information
        $ni.Visible = $true
        $ni.BalloonTipTitle = $Title
        $ni.BalloonTipText = $Text
        $ni.ShowBalloonTip(2500)
        Start-Sleep -Milliseconds 2800
        $ni.Dispose()
    } catch {}
}

function Convert-ConfigValue {
    param([string]$Value)
    if ($null -eq $Value) { return $null }
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
        SourceUrl = ""
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

    if (-not $PSBoundParameters.ContainsKey("SourceUrl")) {
        $script:SourceUrl = [string]$cfg.SourceUrl
    } else {
        $script:SourceUrl = $SourceUrl
    }
}

Apply-Config

function Save-CurrentRuntimeConfig {
    $cfg = Load-Config
    $cfg.CheckIntervalSec = [int]$script:CheckIntervalSec
    $cfg.UpStableChecks = [int]$script:UpStableChecks
    $cfg.DownStableChecks = [int]$script:DownStableChecks
    $cfg.AdapterName = [string]$script:AdapterName
    $cfg.CooldownOnFailMin = [int]$script:CooldownOnFailMin
    $cfg.CooldownOffFailMin = [int]$script:CooldownOffFailMin
    $cfg.CooldownOnExceptionSec = [int]$script:CooldownOnExceptionSec
    $cfg.ForceOffWhenDisabled = [bool]$script:ForceOffWhenDisabled
    $cfg.LogPath = [string]$script:LogPath
    if (-not [string]::IsNullOrWhiteSpace($script:SourceUrl)) {
        $cfg.SourceUrl = [string]$script:SourceUrl
    }
    Save-Config $cfg
}

function Wait-AsyncOp {
    param(
        $Op,
        [int]$TimeoutSec = 30
    )

    if ($null -eq $Op) {
        return [pscustomobject]@{
            Ok = $false
            Result = $null
            Error = "Async operation is null."
        }
    }

    try {
        $hasStatus = $false
        try { $hasStatus = ($Op.PSObject.Properties.Name -contains "Status") } catch { $hasStatus = $false }

        if ($hasStatus) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            while ($true) {
                $statusText = ""
                try { $statusText = [string]$Op.Status } catch { $statusText = "" }

                if ($statusText -and $statusText -ne "Started") { break }

                if ($sw.Elapsed.TotalSeconds -ge $TimeoutSec) {
                    return [pscustomobject]@{
                        Ok = $false
                        Result = $null
                        Error = "Async timeout."
                    }
                }

                Start-Sleep -Milliseconds 100
            }
        }

        $res = $null
        $hasGetResults = $false
        try { $hasGetResults = ($Op.PSObject.Methods.Name -contains "GetResults") } catch { $hasGetResults = $false }

        if ($hasGetResults) {
            $res = $Op.GetResults()
        } else {
            $res = $Op
        }

        return [pscustomobject]@{
            Ok = $true
            Result = $res
            Error = $null
        }
    } catch {
        return [pscustomobject]@{
            Ok = $false
            Result = $null
            Error = $_.Exception.Message
        }
    }
}

function Get-EthernetState {
    $adapters = @()

    try {
        $all = @(Get-NetAdapter -ErrorAction SilentlyContinue)

        if ($script:AdapterName) {
            $all = @($all | Where-Object { $_.Name -eq $script:AdapterName })
        }

        $adapters = @($all | Where-Object {
            $_.Status -eq "Up" -and (
                $_.MediaType -eq "802.3" -or
                $_.NdisPhysicalMedium -eq 14
            )
        })
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
        IsUp = (@($adapters).Count -gt 0)
        Names = $names
    }
}

function Get-ConnectionProfileSafe {
    try {
        $ni = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]

        try {
            $p = $ni::GetInternetConnectionProfile()
            if ($null -ne $p) { return $p }
        } catch {}

        try {
            $profiles = $ni::GetConnectionProfiles()
            foreach ($x in $profiles) {
                try {
                    $lvl = $x.GetNetworkConnectivityLevel().ToString()
                    if ($lvl -ne "None") { return $x }
                } catch {}
            }
        } catch {}

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
        $wifi = @($all | Where-Object {
            $_.Status -ne "Disabled" -and (
                $_.InterfaceDescription -match "Wi-?Fi|Wireless|802\.11" -or
                $_.NdisPhysicalMedium -eq 9
            )
        })
        return (@($wifi).Count -gt 0)
    } catch {
        return $false
    }
}

function Get-TetheringCapabilityText {
    param($Mgr)
    try {
        $cap = $Mgr.TetheringCapability
        if ($null -eq $cap) { return "Unknown" }
        return [string]$cap
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
    try { $state = [string]$mgr.TetheringOperationalState } catch {}

    if ($Desired -eq "On") {
        if ($state -eq "On") { return $true }
        Write-Log "Turning hotspot ON..." "INFO"
        try {
            $r = Wait-AsyncOp ($mgr.StartTetheringAsync()) 30
            if (-not $r.Ok) {
                Write-Log ("Failed to start hotspot: " + $r.Error) "ERROR"
                return $false
            }

            $opStatus = ""
            $opMsg = ""
            try { $opStatus = [string]$r.Result.Status } catch {}
            try { $opMsg = [string]$r.Result.AdditionalErrorMessage } catch {}

            if ($opStatus -and $opStatus -ne "Success") {
                if ([string]::IsNullOrWhiteSpace($opMsg)) {
                    Write-Log ("Failed to start hotspot. Result: " + $opStatus) "ERROR"
                } else {
                    Write-Log ("Failed to start hotspot. Result: " + $opStatus + " | " + $opMsg) "ERROR"
                }
                return $false
            }

            Write-Log "Hotspot is ON." "OK"
            return $true
        } catch {
            Write-Log ("Failed to start hotspot: " + $_.Exception.Message) "ERROR"
            return $false
        }
    } else {
        if ($state -eq "Off") { return $true }
        Write-Log "Turning hotspot OFF..." "INFO"
        try {
            $r = Wait-AsyncOp ($mgr.StopTetheringAsync()) 30
            if (-not $r.Ok) {
                Write-Log ("Failed to stop hotspot: " + $r.Error) "ERROR"
                return $false
            }

            $opStatus = ""
            $opMsg = ""
            try { $opStatus = [string]$r.Result.Status } catch {}
            try { $opMsg = [string]$r.Result.AdditionalErrorMessage } catch {}

            if ($opStatus -and $opStatus -ne "Success") {
                if ([string]::IsNullOrWhiteSpace($opMsg)) {
                    Write-Log ("Failed to stop hotspot. Result: " + $opStatus) "ERROR"
                } else {
                    Write-Log ("Failed to stop hotspot. Result: " + $opStatus + " | " + $opMsg) "ERROR"
                }
                return $false
            }

            Write-Log "Hotspot is OFF." "OK"
            return $true
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

    if ([string]::IsNullOrWhiteSpace($ScriptPath)) { return }

    try {
        $procs = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue)
        foreach ($p in $procs) {
            $cmd = $null
            try { $cmd = [string]$p.CommandLine } catch { $cmd = "" }
            if ([string]::IsNullOrWhiteSpace($cmd)) { continue }

            if ($cmd -like "*$ScriptPath*" -and ($cmd -match '\s-Worker(\s|$)')) {
                try { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
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
        try { Remove-Item -LiteralPath $script:DisableFlagPath -Force -ErrorAction SilentlyContinue } catch {}
        Write-Log "Automation enabled by user." "OK"
    }
}

function Open-LogFile {
    try {
        if (-not (Test-Path -LiteralPath $script:LogPath)) {
            Write-Host "Log file not found: $script:LogPath" -ForegroundColor Yellow
            return
        }
        Start-Process -FilePath "notepad.exe" -ArgumentList "`"$script:LogPath`""
    } catch {
        Write-Host ("Failed to open log: " + $_.Exception.Message) -ForegroundColor Red
    }
}

function Get-PowerShellExePath {
    $ps1 = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path -LiteralPath $ps1) { return $ps1 }
    return "powershell.exe"
}

function Get-DesktopToggleStateName {
    if (Is-AutomationDisabled) { return "OFF" }
    return "ON"
}

function Get-DesktopToggleLinkPath {
    $publicDesktop = Join-Path $env:Public "Desktop"
    $state = Get-DesktopToggleStateName
    return (Join-Path $publicDesktop "$($script:DesktopToggleBaseName) ($state).lnk")
}

function Get-DesktopToggleOldNames {
    return @(
        "$($script:DesktopToggleBaseName).lnk",
        "$($script:DesktopToggleBaseName) (ON).lnk",
        "$($script:DesktopToggleBaseName) (OFF).lnk"
    )
}

function Get-IconLocation {
    param(
        [ValidateSet("ToggleOn","ToggleOff","Enable","Disable","Status","OpenLog")]
        [string]$Kind
    )

    switch ($Kind) {
        "ToggleOn"  { return $script:IconToggleOn }
        "ToggleOff" { return $script:IconToggleOff }
        "Enable"    { return $script:IconEnable }
        "Disable"   { return $script:IconDisable }
        "Status"    { return $script:IconStatus }
        "OpenLog"   { return $script:IconOpenLog }
    }
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
        if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) { $sc.WorkingDirectory = $WorkingDirectory }
        if (-not [string]::IsNullOrWhiteSpace($IconLocation)) { $sc.IconLocation = $IconLocation }
        $sc.Save()
    } catch {}
}

function Remove-Shortcuts {
    try {
        $commonStart = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
        $folder = Join-Path $commonStart $script:ShortcutFolderName
        Remove-PathSafe $folder
    } catch {}

    try {
        $publicDesktop = Join-Path $env:Public "Desktop"
        foreach ($n in (Get-DesktopToggleOldNames)) {
            $p = Join-Path $publicDesktop $n
            try { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } catch {}
        }
    } catch {}
}

function Create-Shortcuts {
    param([string]$InstalledScriptPath)

    if ([string]::IsNullOrWhiteSpace($InstalledScriptPath)) { return }
    if (-not (Test-Path -LiteralPath $InstalledScriptPath)) { return }

    $ps = Get-PowerShellExePath
    $commonStart = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    $folder = Join-Path $commonStart $script:ShortcutFolderName
    $publicDesktop = Join-Path $env:Public "Desktop"

    Ensure-Path $folder
    Ensure-Path $publicDesktop

    foreach ($n in (Get-DesktopToggleOldNames)) {
        $p = Join-Path $publicDesktop $n
        try { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } catch {}
    }

    $base = "-NoProfile -ExecutionPolicy Bypass -File `"$InstalledScriptPath`""

    $desktopTogglePath = Get-DesktopToggleLinkPath
    $toggleIconKind = if ((Get-DesktopToggleStateName) -eq "ON") { "ToggleOn" } else { "ToggleOff" }
    $toggleIcon = Get-IconLocation $toggleIconKind

    New-Shortcut -LinkPath $desktopTogglePath -TargetPath $ps -Arguments "$base -Toggle" -WorkingDirectory $env:WINDIR -IconLocation $toggleIcon

    New-Shortcut -LinkPath (Join-Path $folder "Toggle Automation.lnk") -TargetPath $ps -Arguments "$base -Toggle" -WorkingDirectory $env:WINDIR -IconLocation $toggleIcon
    New-Shortcut -LinkPath (Join-Path $folder "Enable Automation.lnk") -TargetPath $ps -Arguments "$base -Enable" -WorkingDirectory $env:WINDIR -IconLocation (Get-IconLocation "Enable")
    New-Shortcut -LinkPath (Join-Path $folder "Disable Automation.lnk") -TargetPath $ps -Arguments "$base -Disable" -WorkingDirectory $env:WINDIR -IconLocation (Get-IconLocation "Disable")
    New-Shortcut -LinkPath (Join-Path $folder "Status.lnk") -TargetPath $ps -Arguments "-NoExit $base -Status -NoDelay" -WorkingDirectory $env:WINDIR -IconLocation (Get-IconLocation "Status")
    New-Shortcut -LinkPath (Join-Path $folder "Open Log.lnk") -TargetPath $ps -Arguments "$base -OpenLog" -WorkingDirectory $env:WINDIR -IconLocation (Get-IconLocation "OpenLog")
}

function Refresh-ToggleShortcutVisual {
    try {
        Create-Shortcuts $script:InstalledScriptPath
    } catch {}
}

function Build-WorkerArgs {
    param([string]$InstalledScriptPath)

    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", "`"$InstalledScriptPath`"",
        "-Worker",
        "-Quiet",
        "-CheckIntervalSec", $script:CheckIntervalSec,
        "-UpStableChecks", $script:UpStableChecks,
        "-DownStableChecks", $script:DownStableChecks,
        "-CooldownOnFailMin", $script:CooldownOnFailMin,
        "-CooldownOffFailMin", $script:CooldownOffFailMin,
        "-CooldownOnExceptionSec", $script:CooldownOnExceptionSec,
        "-LogPath", "`"$script:LogPath`""
    )

    if (-not [string]::IsNullOrWhiteSpace($script:AdapterName)) {
        $args += @("-AdapterName", "`"$script:AdapterName`"")
    }

    if ($script:ForceOffWhenDisabled) {
        $args += @("-ForceOffWhenDisabled")
    }

    return $args
}

function New-TaskPrincipalSafe {
    param([string]$UserId)

    try {
        return (New-ScheduledTaskPrincipal -UserId $UserId -LogonType InteractiveToken -RunLevel Highest)
    } catch {
        try {
            return (New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Highest)
        } catch {
            return (New-ScheduledTaskPrincipal -UserId $UserId -RunLevel Highest)
        }
    }
}

function Register-OrRepairTask {
    param([string]$InstalledScriptPath)

    if (-not (Test-Path -LiteralPath $InstalledScriptPath)) {
        throw "Installed script not found: $InstalledScriptPath"
    }

    $userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $taskArgs = Build-WorkerArgs $InstalledScriptPath

    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 500

    Stop-OldMonitorProcess $InstalledScriptPath

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ($taskArgs -join " ")
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
    $principal = New-TaskPrincipalSafe $userId

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
            try { $st = (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State } catch { $st = "Unknown" }
            if ($st -eq "Running") {
                $started = $true
                break
            }
            Start-Sleep -Milliseconds 250
        } while ((Get-Date) -lt $deadline)
    } catch {}

    if (-not $started) {
        $fallbackArgs = Build-WorkerArgs $InstalledScriptPath
        Start-Process -FilePath "powershell.exe" -ArgumentList ($fallbackArgs -join " ") -WindowStyle Hidden
        Start-Sleep -Milliseconds 500
        try { $st = (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State } catch { $st = "Unknown" }
    }

    return $st
}

function Remove-TaskAndProcesses {
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 300
    try { Stop-OldMonitorProcess $script:InstalledScriptPath } catch {}
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
}

function Do-CleanUninstallCore {
    param([switch]$RemoveState)

    Remove-TaskAndProcesses
    Remove-Shortcuts
    Remove-PathSafe $InstallDir

    if ($RemoveState) {
        Remove-PathSafe $script:StateDir
    }
}

function Install-App {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to install." -ForegroundColor Red
        exit 1
    }

    Write-Host "Performing clean reinstall..." -ForegroundColor Yellow

    try {
        Do-CleanUninstallCore
    } catch {}

    Ensure-Path $InstallDir
    Ensure-Path $script:StateDir

    $srcPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($srcPath) -or -not (Test-Path -LiteralPath $srcPath)) {
        if ([string]::IsNullOrWhiteSpace($script:SourceUrl)) {
            Write-Host "This script has no local file path. Use -SourceUrl for install." -ForegroundColor Red
            exit 1
        }

        try {
            Invoke-WebRequest -UseBasicParsing -Uri $script:SourceUrl -OutFile $script:InstalledScriptPath
        } catch {
            Write-Host ("Download failed: " + $_.Exception.Message) -ForegroundColor Red
            exit 1
        }
    } else {
        try {
            Copy-Item -LiteralPath $srcPath -Destination $script:InstalledScriptPath -Force
        } catch {
            Write-Host ("Copy failed: " + $_.Exception.Message) -ForegroundColor Red
            exit 1
        }
    }

    $script:LogPath = Resolve-LogPath $script:LogPath

    Save-CurrentRuntimeConfig

    try {
        $st = Register-OrRepairTask $script:InstalledScriptPath
    } catch {
        Write-Host ("Task setup failed: " + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }

    Create-Shortcuts $script:InstalledScriptPath

    Write-Host "Task state: $st" -ForegroundColor Cyan
    Write-Host "Installed. Task created: $TaskName" -ForegroundColor Green
    Write-Host "Installed script: $script:InstalledScriptPath" -ForegroundColor Gray
    Write-Host "Logs: $script:LogPath" -ForegroundColor Cyan
    Write-Host "Start Menu folder: $script:ShortcutFolderName" -ForegroundColor Gray
    Write-Host "Desktop: one toggle shortcut (renames ON/OFF)" -ForegroundColor Gray
}

function Uninstall-App {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to uninstall." -ForegroundColor Red
        exit 1
    }

    Do-CleanUninstallCore -RemoveState

    Write-Host "Uninstalled. Task, shortcuts, files, and local state removed." -ForegroundColor Yellow
}

function Show-Status {
    $eth = Get-EthernetState
    $wifiPresent = Test-WifiAdapterPresent
    $disabled = Is-AutomationDisabled

    Write-Host ("Automation disabled: " + $disabled) -ForegroundColor Yellow
    Write-Host ("Wi-Fi adapter present: " + $wifiPresent) -ForegroundColor Cyan
    Write-Host ("Ethernet Up: " + $eth.IsUp) -ForegroundColor Cyan

    if (@($eth.Names).Count -gt 0) {
        Write-Host ("Ethernet adapters: " + ($eth.Names -join ", ")) -ForegroundColor Cyan
    } elseif (-not [string]::IsNullOrWhiteSpace($script:AdapterName)) {
        Write-Host ("Ethernet adapter filter: " + $script:AdapterName) -ForegroundColor Gray
    }

    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) {
        Write-Host "Hotspot: Unknown (no connection profile)" -ForegroundColor Yellow
    } else {
        $cap = Get-TetheringCapabilityText $mgr
        $hst = "Unknown"
        try { $hst = [string]$mgr.TetheringOperationalState } catch {}
        Write-Host ("Hotspot state: " + $hst) -ForegroundColor Green
        Write-Host ("Hotspot capability: " + $cap) -ForegroundColor Green
    }

    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Host ("Scheduled task: Present (" + $t.State + ")") -ForegroundColor Green
    } catch {
        Write-Host "Scheduled task: Not found" -ForegroundColor Red
    }

    Write-Host ("Install dir: " + $InstallDir) -ForegroundColor Gray
    Write-Host ("State dir: " + $script:StateDir) -ForegroundColor Gray
    Write-Host ("Config file: " + $script:ConfigPath) -ForegroundColor Gray
    Write-Host ("Log file: " + $script:LogPath) -ForegroundColor Gray
}

function Disable-Automation {
    Set-DisabledFlag $true
    if ($script:ForceOffWhenDisabled) { $null = Ensure-Hotspot "Off" }
    Refresh-ToggleShortcutVisual
    Show-Notify "Windows Auto Hotspot" "Automation disabled"
}

function Enable-Automation {
    Set-DisabledFlag $false
    Refresh-ToggleShortcutVisual
    Show-Notify "Windows Auto Hotspot" "Automation enabled"
}

function Toggle-Automation {
    if (Is-AutomationDisabled) {
        Set-DisabledFlag $false
        Refresh-ToggleShortcutVisual
        Show-Notify "Windows Auto Hotspot" "Automation enabled"
    } else {
        Set-DisabledFlag $true
        if ($script:ForceOffWhenDisabled) { $null = Ensure-Hotspot "Off" }
        Refresh-ToggleShortcutVisual
        Show-Notify "Windows Auto Hotspot" "Automation disabled"
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
    $script:SourceUrl = [string]$cfg.SourceUrl

    try {
        $st = Register-OrRepairTask $script:InstalledScriptPath
        Create-Shortcuts $script:InstalledScriptPath
        Write-Host "Task state: $st" -ForegroundColor Cyan
        Write-Host "Repair done." -ForegroundColor Green
    } catch {
        Write-Host ("Repair failed: " + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}

function Do-Update {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to update." -ForegroundColor Red
        exit 1
    }

    $url = $script:SourceUrl
    if (-not [string]::IsNullOrWhiteSpace($SourceUrl)) { $url = $SourceUrl }

    if ([string]::IsNullOrWhiteSpace($url)) {
        Write-Host "No SourceUrl found. Use -SourceUrl <url>." -ForegroundColor Red
        exit 1
    }

    Ensure-Path $InstallDir

    $tmp = Join-Path $env:TEMP ("windows-auto-hotspot.update." + [DateTime]::UtcNow.Ticks + ".ps1")

    try {
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp
    } catch {
        Write-Host ("Download failed: " + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }

    $ok = $false
    try {
        $content = Get-Content -LiteralPath $tmp -Raw -ErrorAction Stop
        if ($content -match "WindowsAutoHotspot" -and $content -match "function Ensure-Hotspot" -and $content -match "function Run-Worker") {
            $ok = $true
        }
    } catch {
        $ok = $false
    }

    if (-not $ok) {
        try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch {}
        Write-Host "Downloaded file does not look valid. Aborting." -ForegroundColor Red
        exit 1
    }

    try {
        Copy-Item -LiteralPath $tmp -Destination $script:InstalledScriptPath -Force
    } catch {
        Write-Host ("Update copy failed: " + $_.Exception.Message) -ForegroundColor Red
        try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch {}
        exit 1
    } finally {
        try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch {}
    }

    $script:SourceUrl = $url
    Save-CurrentRuntimeConfig

    Write-Host "Updated installed script." -ForegroundColor Green
    Do-Repair
}

function Run-Worker {
    $mutex = Acquire-SingleInstance
    if ($null -eq $mutex) { return }

    try {
        $script:LogPath = Resolve-LogPath $script:LogPath

        Write-Log "Windows Auto Hotspot worker started." "INFO"
        Write-Log "Interval: $script:CheckIntervalSec sec | UpStable: $script:UpStableChecks | DownStable: $script:DownStableChecks" "DEBUG"
        if (-not [string]::IsNullOrWhiteSpace($script:AdapterName)) { Write-Log "Adapter filter: $script:AdapterName" "DEBUG" }
        Write-Log "Log path: $script:LogPath" "DEBUG"

        $upCount = 0
        $downCount = 0
        $lastWanted = ""
        $cooldownUntil = Get-Date
        $lastEnvErrorKey = ""

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

                if (-not (Test-WifiAdapterPresent)) {
                    if ($lastEnvErrorKey -ne "NoWifi") {
                        Write-Log "No Wi-Fi adapter detected. Waiting..." "ERROR"
                        $lastEnvErrorKey = "NoWifi"
                    }
                    Start-Sleep -Seconds ([Math]::Max($script:CheckIntervalSec, 15))
                    continue
                }

                $mgrCheck = Get-TetheringManagerSafe
                if ($null -eq $mgrCheck) {
                    if ($lastEnvErrorKey -ne "NoMgr") {
                        Write-Log "Hotspot manager not available (no connection profile). Waiting..." "ERROR"
                        $lastEnvErrorKey = "NoMgr"
                    }
                    Start-Sleep -Seconds ([Math]::Max($script:CheckIntervalSec, 15))
                    continue
                }

                $cap = Get-TetheringCapabilityText $mgrCheck
                if ($cap -ne "Enabled" -and $cap -ne "Unknown") {
                    if ($lastEnvErrorKey -ne ("Cap:" + $cap)) {
                        Write-Log ("Hotspot not available. Capability: " + $cap + ". Waiting...") "ERROR"
                        $lastEnvErrorKey = ("Cap:" + $cap)
                    }
                    Start-Sleep -Seconds ([Math]::Max($script:CheckIntervalSec, 15))
                    continue
                }

                if ($lastEnvErrorKey) {
                    Write-Log "Hotspot environment check OK again." "OK"
                    $lastEnvErrorKey = ""
                }

                $eth = Get-EthernetState

                if ($eth.IsUp) {
                    $upCount++
                    $downCount = 0

                    if ($upCount -ge $script:UpStableChecks) {
                        if ($lastWanted -ne "On") {
                            $names = ""
                            if (@($eth.Names).Count -gt 0) { $names = ($eth.Names -join ", ") }
                            Write-Log ("Ethernet stable ON. " + $names).Trim() "OK"
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
        "Install" {
            Install-App
            break
        }

        "Uninstall" {
            Uninstall-App
            break
        }

        "Status" {
            Show-Status
            break
        }

        "Disable" {
            Disable-Automation
            break
        }

        "Enable" {
            Enable-Automation
            break
        }

        "Toggle" {
            Toggle-Automation
            break
        }

        "OpenLog" {
            Open-LogFile
            break
        }

        "Repair" {
            Do-Repair
            break
        }

        "Update" {
            Do-Update
            break
        }

        "Worker" {
            Run-Worker
            break
        }

        default {
            Write-Host "Usage:" -ForegroundColor Cyan
            Write-Host "  -Install    (Admin, clean reinstall)" -ForegroundColor Gray
            Write-Host "  -Uninstall  (Admin, remove task/files/state)" -ForegroundColor Gray
            Write-Host "  -Enable" -ForegroundColor Gray
            Write-Host "  -Disable" -ForegroundColor Gray
            Write-Host "  -Toggle" -ForegroundColor Gray
            Write-Host "  -Status" -ForegroundColor Gray
            Write-Host "  -OpenLog" -ForegroundColor Gray
            Write-Host "  -Repair     (Admin)" -ForegroundColor Gray
            Write-Host "  -Update     -SourceUrl <url> (Admin)" -ForegroundColor Gray
            Write-Host "" -ForegroundColor Gray
            Write-Host "Examples:" -ForegroundColor Cyan
            Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows-auto-hotspot.ps1 -Install -SourceUrl <raw_url>" -ForegroundColor Gray
            Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows-auto-hotspot.ps1 -Toggle" -ForegroundColor Gray
            Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows-auto-hotspot.ps1 -Status" -ForegroundColor Gray
            break
        }
    }
} catch {
    try {
        Write-Log ("Fatal error: " + $_.Exception.Message) "ERROR"
    } catch {}
    if (-not $Quiet) {
        Write-Host ("Fatal error: " + $_.Exception.Message) -ForegroundColor Red
    }
    exit 1
}
