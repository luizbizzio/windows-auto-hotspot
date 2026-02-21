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

    [Parameter(ParameterSetName = "Run", Mandatory = $true)]
    [switch]$Run,

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
$script:DesktopToggleName = "Windows Auto Hotspot Toggle.lnk"

$script:ToggleBaseName = "Windows Auto Hotspot Toggle"
$script:EnableShortcutName = "Enable Automation.lnk"
$script:DisableShortcutName = "Disable Automation.lnk"
$script:StatusShortcutName = "Status.lnk"
$script:OpenLogShortcutName = "Open Log.lnk"
$script:RepairShortcutName = "Repair.lnk"
$script:UpdateShortcutName = "Update.lnk"
$script:UninstallShortcutName = "Uninstall.lnk"

function Ensure-Path {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-UserDesktopPath {
    try {
        return [Environment]::GetFolderPath("Desktop")
    } catch {
        return (Join-Path $env:USERPROFILE "Desktop")
    }
}

function Get-UserStartMenuProgramsPath {
    try {
        return [Environment]::GetFolderPath("Programs")
    } catch {
        return (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs")
    }
}

function Get-StartMenuFolderPath {
    return (Join-Path (Get-UserStartMenuProgramsPath) $script:StartMenuFolderName)
}

function Get-DesktopToggleShortcutPath {
    return (Join-Path (Get-UserDesktopPath) $script:DesktopToggleName)
}

function Resolve-LogPath {
    param([string]$Candidate)

    try {
        Ensure-Path (Split-Path -Parent $Candidate)
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
    if (-not $PSBoundParameters.ContainsKey("ForceOffWhenDisabled")) { $script:ForceOffWhenDisabled = [bool]$cfg.ForceOffWhenDisabled } else { $script:ForceOffWhenDisabled = $true }
    if (-not $PSBoundParameters.ContainsKey("LogPath")) { $script:LogPath = Resolve-LogPath ([string]$cfg.LogPath) } else { $script:LogPath = Resolve-LogPath $LogPath }
    if (-not $PSBoundParameters.ContainsKey("SourceUrl")) { $script:SourceUrl = [string]$cfg.SourceUrl } else { $script:SourceUrl = $SourceUrl }
}

Apply-Config

function Get-EffectiveSourceUrl {
    if (-not [string]::IsNullOrWhiteSpace($SourceUrl)) { return $SourceUrl }
    if (-not [string]::IsNullOrWhiteSpace($script:SourceUrl)) { return $script:SourceUrl }
    return ""
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

function To-Array {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value)
}

function Get-EthernetState {
    $adapters = @()

    try {
        $all = To-Array (Get-NetAdapter -ErrorAction SilentlyContinue)

        if ($script:AdapterName) {
            $all = @($all | Where-Object { $_.Name -eq $script:AdapterName })
        }

        $adapters = @(
            $all | Where-Object {
                $_.Status -eq "Up" -and (
                    $_.MediaType -eq "802.3" -or
                    $_.InterfaceDescription -match "Ethernet|USB.*Ethernet|LAN"
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
        IsUp = (@($adapters).Count -gt 0)
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
        $all = To-Array (Get-NetAdapter -ErrorAction SilentlyContinue)
        $wifi = @(
            $all | Where-Object {
                $_.Status -ne "Disabled" -and (
                    $_.InterfaceDescription -match "Wi-?Fi|Wireless|802\.11" -or
                    $_.NdisPhysicalMedium -eq 9
                )
            }
        )
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
            if (-not $cmd) { continue }

            $matchRun = ($cmd -match '\s-Run(\s|$)')
            $matchName = $false

            if (-not [string]::IsNullOrWhiteSpace($ScriptPath)) {
                $matchName = ($cmd -like "*$ScriptPath*")
            }

            if (-not $matchName) {
                $matchName = ($cmd -like "*windows-auto-hotspot.ps1*")
            }

            if ($matchRun -and $matchName) {
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

    Update-ToggleShortcutIcon
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

function Resolve-IconLocation {
    param([string[]]$Candidates)

    foreach ($c in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $parts = $c.Split(",", 2)
        $dll = $parts[0]
        if (Test-Path -LiteralPath $dll) { return $c }
    }

    return ((Join-Path $env:SystemRoot "System32\shell32.dll") + ",44")
}

function Get-IconMap {
    $sysShell = Join-Path $env:SystemRoot "System32\shell32.dll"
    $sysImage = Join-Path $env:SystemRoot "System32\imageres.dll"
    $sysNetSh = Join-Path $env:SystemRoot "System32\netshell.dll"

    $toggleEnabled = Resolve-IconLocation @(
        ($sysNetSh + ",86"),
        ($sysNetSh + ",84"),
        ($sysImage + ",161"),
        ($sysShell + ",44")
    )

    $toggleDisabled = Resolve-IconLocation @(
        ($sysShell + ",132"),
        ($sysImage + ",101"),
        ($sysShell + ",109")
    )

    [pscustomobject]@{
        ToggleEnabled = $toggleEnabled
        ToggleDisabled = $toggleDisabled
        Enable = Resolve-IconLocation @(($sysShell + ",167"), ($sysImage + ",76"))
        Disable = Resolve-IconLocation @(($sysShell + ",132"), ($sysImage + ",100"))
        Status = Resolve-IconLocation @(($sysShell + ",23"), ($sysImage + ",75"))
        OpenLog = Resolve-IconLocation @(($sysShell + ",70"), ($sysImage + ",2"))
        Repair = Resolve-IconLocation @(($sysShell + ",239"), ($sysImage + ",79"))
        Update = Resolve-IconLocation @(($sysShell + ",238"), ($sysImage + ",78"))
        Uninstall = Resolve-IconLocation @(($sysShell + ",131"), ($sysImage + ",100"))
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
        if ($WorkingDirectory) { $sc.WorkingDirectory = $WorkingDirectory }
        if ($IconLocation) { $sc.IconLocation = $IconLocation }
        $sc.Save()
        return $true
    } catch {
        return $false
    }
}

function Update-ShortcutIcon {
    param(
        [string]$LinkPath,
        [string]$IconLocation
    )

    try {
        if (-not (Test-Path -LiteralPath $LinkPath)) { return }
        $wsh = New-Object -ComObject WScript.Shell
        $sc = $wsh.CreateShortcut($LinkPath)
        $sc.IconLocation = $IconLocation
        $sc.Save()
    } catch {}
}

function Update-ToggleShortcutIcon {
    $icons = Get-IconMap
    $icon = $icons.ToggleEnabled
    if (Is-AutomationDisabled) {
        $icon = $icons.ToggleDisabled
    }

    $desktopToggle = Get-DesktopToggleShortcutPath
    Update-ShortcutIcon -LinkPath $desktopToggle -IconLocation $icon

    $startToggle = Join-Path (Get-StartMenuFolderPath) ($script:ToggleBaseName + ".lnk")
    Update-ShortcutIcon -LinkPath $startToggle -IconLocation $icon
}

function Remove-Shortcuts {
    $desktopToggle = Get-DesktopToggleShortcutPath
    $startFolder = Get-StartMenuFolderPath

    try { Remove-Item -LiteralPath $desktopToggle -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item -LiteralPath $startFolder -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

function Create-Shortcuts {
    param([string]$InstalledScriptPath)

    $ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path -LiteralPath $ps)) {
        $ps = "powershell.exe"
    }

    $icons = Get-IconMap
    $desktop = Get-UserDesktopPath
    $startFolder = Get-StartMenuFolderPath

    Ensure-Path $desktop
    Ensure-Path $startFolder

    $base = "-NoProfile -ExecutionPolicy Bypass -File `"$InstalledScriptPath`""

    $toggleArgs = "$base -Toggle"
    $enableArgs = "$base -Enable"
    $disableArgs = "$base -Disable"
    $openLogArgs = "$base -OpenLog"
    $statusArgs = "-NoLogo -NoExit -ExecutionPolicy Bypass -File `"$InstalledScriptPath`" -Status"
    $repairArgs = "-NoLogo -NoExit -ExecutionPolicy Bypass -File `"$InstalledScriptPath`" -Repair"
    $uninstallArgs = "-NoLogo -NoExit -ExecutionPolicy Bypass -File `"$InstalledScriptPath`" -Uninstall"

    $effectiveSource = Get-EffectiveSourceUrl
    if (-not [string]::IsNullOrWhiteSpace($effectiveSource)) {
        $updateArgs = "-NoLogo -NoExit -ExecutionPolicy Bypass -File `"$InstalledScriptPath`" -Update -SourceUrl `"$effectiveSource`""
    } else {
        $updateArgs = "-NoLogo -NoExit -ExecutionPolicy Bypass -File `"$InstalledScriptPath`" -Update"
    }

    $toggleDesktopLink = Join-Path $desktop $script:DesktopToggleName
    $toggleStartLink = Join-Path $startFolder ($script:ToggleBaseName + ".lnk")

    $toggleIcon = $icons.ToggleEnabled
    if (Is-AutomationDisabled) { $toggleIcon = $icons.ToggleDisabled }

    New-Shortcut -LinkPath $toggleDesktopLink -TargetPath $ps -Arguments $toggleArgs -WorkingDirectory $env:WINDIR -IconLocation $toggleIcon | Out-Null
    New-Shortcut -LinkPath $toggleStartLink -TargetPath $ps -Arguments $toggleArgs -WorkingDirectory $env:WINDIR -IconLocation $toggleIcon | Out-Null

    New-Shortcut -LinkPath (Join-Path $startFolder $script:EnableShortcutName) -TargetPath $ps -Arguments $enableArgs -WorkingDirectory $env:WINDIR -IconLocation $icons.Enable | Out-Null
    New-Shortcut -LinkPath (Join-Path $startFolder $script:DisableShortcutName) -TargetPath $ps -Arguments $disableArgs -WorkingDirectory $env:WINDIR -IconLocation $icons.Disable | Out-Null
    New-Shortcut -LinkPath (Join-Path $startFolder $script:StatusShortcutName) -TargetPath $ps -Arguments $statusArgs -WorkingDirectory $env:WINDIR -IconLocation $icons.Status | Out-Null
    New-Shortcut -LinkPath (Join-Path $startFolder $script:OpenLogShortcutName) -TargetPath $ps -Arguments $openLogArgs -WorkingDirectory $env:WINDIR -IconLocation $icons.OpenLog | Out-Null
    New-Shortcut -LinkPath (Join-Path $startFolder $script:RepairShortcutName) -TargetPath $ps -Arguments $repairArgs -WorkingDirectory $env:WINDIR -IconLocation $icons.Repair | Out-Null
    New-Shortcut -LinkPath (Join-Path $startFolder $script:UpdateShortcutName) -TargetPath $ps -Arguments $updateArgs -WorkingDirectory $env:WINDIR -IconLocation $icons.Update | Out-Null
    New-Shortcut -LinkPath (Join-Path $startFolder $script:UninstallShortcutName) -TargetPath $ps -Arguments $uninstallArgs -WorkingDirectory $env:WINDIR -IconLocation $icons.Uninstall | Out-Null
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

function Get-ScheduledTaskStateSafe {
    try {
        return (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State.ToString()
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

    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

    $started = $false
    try {
        Start-ScheduledTask -TaskName $TaskName
        $deadline = (Get-Date).AddSeconds(6)
        do {
            $st = Get-ScheduledTaskStateSafe
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
            Start-Process -FilePath "powershell.exe" -ArgumentList ($p -join " ") -WindowStyle Hidden | Out-Null
        } catch {}
    }

    return (Get-ScheduledTaskStateSafe)
}

function Save-CurrentSettingsToConfig {
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

    $effectiveSource = Get-EffectiveSourceUrl
    if (-not [string]::IsNullOrWhiteSpace($effectiveSource)) {
        $cfg.SourceUrl = $effectiveSource
    }

    Save-Config $cfg
}

function Install-App {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to install." -ForegroundColor Red
        exit 1
    }

    Ensure-Path $InstallDir
    Ensure-Path $script:StateDir

    Save-CurrentSettingsToConfig

    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 300
    Stop-OldMonitorProcess $script:InstalledScriptPath
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    Remove-Shortcuts

    $srcPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($srcPath) -or -not (Test-Path -LiteralPath $srcPath)) {
        $effectiveSource = Get-EffectiveSourceUrl
        if ([string]::IsNullOrWhiteSpace($effectiveSource)) {
            Write-Host "This script has no file path. Use -SourceUrl to install from URL." -ForegroundColor Red
            exit 1
        }
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $effectiveSource -OutFile $script:InstalledScriptPath
        } catch {
            Write-Host ("Download failed: " + $_.Exception.Message) -ForegroundColor Red
            exit 1
        }
    } else {
        Copy-Item -LiteralPath $srcPath -Destination $script:InstalledScriptPath -Force
    }

    $state = Register-OrRepairTask $script:InstalledScriptPath
    Create-Shortcuts $script:InstalledScriptPath
    Update-ToggleShortcutIcon

    Write-Host "Task state: $state" -ForegroundColor Cyan
    Write-Host "Installed/Reinstalled successfully." -ForegroundColor Green
    Write-Host "Task: $TaskName" -ForegroundColor Gray
    Write-Host "Log: $script:LogPath" -ForegroundColor Gray
    Write-Host "Desktop toggle shortcut: $(Get-DesktopToggleShortcutPath)" -ForegroundColor Gray
    Write-Host "Start Menu folder: $(Get-StartMenuFolderPath)" -ForegroundColor Gray
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

    Remove-Shortcuts

    try { Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item -LiteralPath $script:StateDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}

    Write-Host "Uninstalled. Task, shortcuts, installed files, and state files were removed." -ForegroundColor Yellow
}

function Show-Status {
    Write-Host "" -ForegroundColor Gray
    Write-Host "Windows Auto Hotspot Status" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Gray

    $eth = Get-EthernetState
    Write-Host ("Ethernet Up: " + $eth.IsUp) -ForegroundColor Cyan
    if (@($eth.Names).Count -gt 0) {
        Write-Host ("Ethernet Adapters: " + (@($eth.Names) -join ", ")) -ForegroundColor Cyan
    }

    $wifiPresent = Test-WifiAdapterPresent
    Write-Host ("Wi-Fi Adapter Present: " + $wifiPresent) -ForegroundColor Cyan

    Write-Host ("Automation Disabled: " + (Is-AutomationDisabled)) -ForegroundColor Yellow
    Write-Host ("Disable Flag: " + $script:DisableFlagPath) -ForegroundColor Gray

    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) {
        Write-Host "Hotspot: Unknown (no connection profile)" -ForegroundColor Yellow
    } else {
        $cap = Get-TetheringCapabilityText $mgr
        $hst = "Unknown"
        try { $hst = $mgr.TetheringOperationalState.ToString() } catch {}
        Write-Host ("Hotspot State: " + $hst) -ForegroundColor Green
        Write-Host ("Hotspot Capability: " + $cap) -ForegroundColor Green
    }

    $taskState = Get-ScheduledTaskStateSafe
    if ($taskState -eq "NotFound") {
        Write-Host "Scheduled Task: Not found" -ForegroundColor Red
    } else {
        Write-Host ("Scheduled Task: Present (" + $taskState + ")") -ForegroundColor Green
    }

    Write-Host ("Installed Script: " + $script:InstalledScriptPath) -ForegroundColor Gray
    Write-Host ("Config: " + $script:ConfigPath) -ForegroundColor Gray
    Write-Host ("Log: " + $script:LogPath) -ForegroundColor Gray
    Write-Host "" -ForegroundColor Gray
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

    Save-CurrentSettingsToConfig

    Remove-Shortcuts
    $state = Register-OrRepairTask $script:InstalledScriptPath
    Create-Shortcuts $script:InstalledScriptPath
    Update-ToggleShortcutIcon

    Write-Host "Task state: $state" -ForegroundColor Cyan
    Write-Host "Repair done." -ForegroundColor Green
}

function Do-Update {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to update." -ForegroundColor Red
        exit 1
    }

    $effectiveSource = Get-EffectiveSourceUrl
    if ([string]::IsNullOrWhiteSpace($effectiveSource)) {
        Write-Host "No SourceUrl available. Use -Update -SourceUrl <raw script url>." -ForegroundColor Red
        exit 1
    }

    Ensure-Path $InstallDir

    $tmp = Join-Path $env:TEMP ("windows-auto-hotspot.update." + [DateTime]::UtcNow.Ticks + ".ps1")
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $effectiveSource -OutFile $tmp
    } catch {
        Write-Host ("Download failed: " + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }

    $ok = $false
    try {
        $content = Get-Content -LiteralPath $tmp -Raw -ErrorAction Stop
        if ($content -match "WindowsAutoHotspot" -or $content -match "Windows Auto Hotspot") {
            if ($content -match "Register-OrRepairTask" -and $content -match "Run-Monitor") {
                $ok = $true
            }
        }
    } catch {}

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

    $cfg = Load-Config
    $cfg.SourceUrl = $effectiveSource
    Save-Config $cfg

    Write-Host "Updated installed script." -ForegroundColor Green
    Do-Repair
}

function Run-Monitor {
    $mutex = Acquire-SingleInstance
    if ($null -eq $mutex) { return }

    try {
        $script:LogPath = Resolve-LogPath $script:LogPath

        Write-Log "Windows Auto Hotspot started." "INFO"
        Write-Log "Interval: $script:CheckIntervalSec sec | UpStable: $script:UpStableChecks | DownStable: $script:DownStableChecks" "DEBUG"
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

                if (-not (Test-WifiAdapterPresent)) {
                    Write-Log "No Wi-Fi adapter detected. Waiting..." "ERROR"
                    Start-Sleep -Seconds ([Math]::Max(15, $script:CheckIntervalSec))
                    continue
                }

                $mgr = Get-TetheringManagerSafe
                if ($null -eq $mgr) {
                    Write-Log "Hotspot manager not available (no connection profile). Waiting..." "ERROR"
                    Start-Sleep -Seconds ([Math]::Max(15, $script:CheckIntervalSec))
                    continue
                }

                $cap = Get-TetheringCapabilityText $mgr
                if ($cap -ne "Enabled" -and $cap -ne "Unknown") {
                    Write-Log "Hotspot not available. Capability: $cap. Waiting..." "ERROR"
                    Start-Sleep -Seconds ([Math]::Max(15, $script:CheckIntervalSec))
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

switch ($PSCmdlet.ParameterSetName) {
    "Install"   { Install-App; break }
    "Uninstall" { Uninstall-App; break }
    "Status"    { Show-Status; break }
    "Disable"   { Disable-Automation; break }
    "Enable"    { Enable-Automation; break }
    "Toggle"    { Toggle-Automation; break }
    "OpenLog"   { Open-LogFile; break }
    "Repair"    { Do-Repair; break }
    "Update"    { Do-Update; break }
    "Run"       { Run-Monitor; break }
    default {
        Write-Host "" -ForegroundColor Gray
        Write-Host "Windows Auto Hotspot" -ForegroundColor Cyan
        Write-Host "" -ForegroundColor Gray
        Write-Host "Commands:" -ForegroundColor Cyan
        Write-Host "  -Install    (Admin, clean reinstall)" -ForegroundColor Gray
        Write-Host "  -Uninstall  (Admin)" -ForegroundColor Gray
        Write-Host "  -Status" -ForegroundColor Gray
        Write-Host "  -Enable" -ForegroundColor Gray
        Write-Host "  -Disable" -ForegroundColor Gray
        Write-Host "  -Toggle" -ForegroundColor Gray
        Write-Host "  -OpenLog" -ForegroundColor Gray
        Write-Host "  -Repair     (Admin)" -ForegroundColor Gray
        Write-Host "  -Update     (Admin, uses saved SourceUrl or -SourceUrl)" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        Write-Host "Examples:" -ForegroundColor Cyan
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Install" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Status" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Toggle" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Repair" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Update -SourceUrl <raw-url>" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        break
    }
}
