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

    [Parameter(ParameterSetName = "OpenLog", Mandatory = $true)]
    [switch]$OpenLog,

    [Parameter(ParameterSetName = "Doctor", Mandatory = $true)]
    [switch]$Doctor,

    [Parameter(ParameterSetName = "Update", Mandatory = $true)]
    [switch]$Update,

    [Parameter(ParameterSetName = "Repair", Mandatory = $true)]
    [switch]$Repair,

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

$script:AppName = "Windows Auto Hotspot"
$script:StateDir = Join-Path $env:LOCALAPPDATA "WindowsAutoHotspot"
$script:DisableFlagPath = Join-Path $script:StateDir "hotspot.disabled"
$script:ConfigPath = Join-Path $script:StateDir "config.json"
$script:InstalledScriptPath = Join-Path $InstallDir "windows-auto-hotspot.ps1"
$script:StartMenuFolderName = "Windows Auto Hotspot"
$script:DesktopToggleShortcutName = "Hotspot Toggle.lnk"

function Ensure-Path {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Resolve-LogPath {
    param([string]$Candidate)

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        $Candidate = Join-Path $script:StateDir "windows-auto-hotspot.log"
    }

    try {
        Ensure-Path (Split-Path -Parent $Candidate)
        if (-not (Test-Path -LiteralPath $Candidate)) {
            New-Item -ItemType File -Path $Candidate -Force | Out-Null
        }
        Add-Content -LiteralPath $Candidate -Value "" -Encoding UTF8 -ErrorAction Stop
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

    if ($null -eq $Value) { return $null }

    if ($Value -match '^(?i:true|false)$') {
        return [bool]::Parse($Value)
    }

    $i = 0
    if ([int]::TryParse($Value, [ref]$i)) {
        return $i
    }

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

    if (-not (Test-Path -LiteralPath $script:ConfigPath)) {
        return $d
    }

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
    $Cfg | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
}

function Apply-Config {
    $cfg = Load-Config

    if (-not $PSBoundParameters.ContainsKey("CheckIntervalSec")) { $script:CheckIntervalSec = [int]$cfg.CheckIntervalSec } else { $script:CheckIntervalSec = [int]$CheckIntervalSec }
    if (-not $PSBoundParameters.ContainsKey("UpStableChecks")) { $script:UpStableChecks = [int]$cfg.UpStableChecks } else { $script:UpStableChecks = [int]$UpStableChecks }
    if (-not $PSBoundParameters.ContainsKey("DownStableChecks")) { $script:DownStableChecks = [int]$cfg.DownStableChecks } else { $script:DownStableChecks = [int]$DownStableChecks }
    if (-not $PSBoundParameters.ContainsKey("AdapterName")) { $script:AdapterName = [string]$cfg.AdapterName } else { $script:AdapterName = [string]$AdapterName }
    if (-not $PSBoundParameters.ContainsKey("CooldownOnFailMin")) { $script:CooldownOnFailMin = [int]$cfg.CooldownOnFailMin } else { $script:CooldownOnFailMin = [int]$CooldownOnFailMin }
    if (-not $PSBoundParameters.ContainsKey("CooldownOffFailMin")) { $script:CooldownOffFailMin = [int]$cfg.CooldownOffFailMin } else { $script:CooldownOffFailMin = [int]$CooldownOffFailMin }
    if (-not $PSBoundParameters.ContainsKey("CooldownOnExceptionSec")) { $script:CooldownOnExceptionSec = [int]$cfg.CooldownOnExceptionSec } else { $script:CooldownOnExceptionSec = [int]$CooldownOnExceptionSec }

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
        $script:SourceUrl = [string]$SourceUrl
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
            $all = @($all | Where-Object { $_.Name -eq $script:AdapterName })
        }

        $adapters = @($all | Where-Object { $_.Status -eq "Up" -and $_.MediaType -eq "802.3" })
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
        IsUp  = ($adapters.Count -gt 0)
        Names = $names
    }
}

function Get-ConnectionProfileSafe {
    try {
        $ni = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]
        $p = $ni::GetInternetConnectionProfile()
        if ($null -ne $p) { return $p }

        $profiles = $ni::GetConnectionProfiles()
        foreach ($x in @($profiles)) {
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
                $_.Status -ne "Disabled" -and (
                    $_.InterfaceDescription -match "Wi-?Fi|Wireless|802\.11" -or
                    $_.Name -match "Wi-?Fi|Wireless|WLAN" -or
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
        $procs = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue)
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

    Update-ToggleShortcutVisual
}

function Open-LogFile {
    try {
        if (-not (Test-Path -LiteralPath $script:LogPath)) { return }
        Start-Process -FilePath "notepad.exe" -ArgumentList "`"$script:LogPath`""
    } catch {}
}

function Get-EnabledIcon {
    $candidates = @(
        (Join-Path $env:SystemRoot "System32\netshell.dll") + ",0",
        (Join-Path $env:SystemRoot "System32\shell32.dll") + ",44",
        (Join-Path $env:SystemRoot "System32\imageres.dll") + ",160"
    )
    foreach ($c in $candidates) {
        $dll = ($c -split ",")[0]
        if (Test-Path -LiteralPath $dll) { return $c }
    }
    return $null
}

function Get-DisabledIcon {
    $candidates = @(
        (Join-Path $env:SystemRoot "System32\imageres.dll") + ",101",
        (Join-Path $env:SystemRoot "System32\shell32.dll") + ",131",
        (Join-Path $env:SystemRoot "System32\shell32.dll") + ",109"
    )
    foreach ($c in $candidates) {
        $dll = ($c -split ",")[0]
        if (Test-Path -LiteralPath $dll) { return $c }
    }
    return (Get-EnabledIcon)
}

function New-Shortcut {
    param(
        [string]$LinkPath,
        [string]$TargetPath,
        [string]$Arguments,
        [string]$WorkingDirectory,
        [string]$IconLocation,
        [string]$Description
    )

    try {
        Ensure-Path (Split-Path -Parent $LinkPath)
        $wsh = New-Object -ComObject WScript.Shell
        $sc = $wsh.CreateShortcut($LinkPath)
        $sc.TargetPath = $TargetPath
        $sc.Arguments = $Arguments
        if ($WorkingDirectory) { $sc.WorkingDirectory = $WorkingDirectory }
        if ($IconLocation) { $sc.IconLocation = $IconLocation }
        if ($Description) { $sc.Description = $Description }
        $sc.Save()
    } catch {}
}

function Get-DesktopToggleShortcutPath {
    return (Join-Path (Join-Path $env:Public "Desktop") $script:DesktopToggleShortcutName)
}

function Get-StartMenuFolderPath {
    return (Join-Path (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs") $script:StartMenuFolderName)
}

function Update-ToggleShortcutVisual {
    try {
        if (-not (Test-Path -LiteralPath $script:InstalledScriptPath)) { return }

        $ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
        if (-not (Test-Path -LiteralPath $ps)) { $ps = "powershell.exe" }

        $baseArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$script:InstalledScriptPath`""
        $disabled = Is-AutomationDisabled

        $icon = if ($disabled) { Get-DisabledIcon } else { Get-EnabledIcon }
        $desc = if ($disabled) { "Automation disabled. Click to toggle." } else { "Automation enabled. Click to toggle." }

        $desktopLink = Get-DesktopToggleShortcutPath
        New-Shortcut $desktopLink $ps "$baseArgs -Toggle" $env:WINDIR $icon $desc

        $startFolder = Get-StartMenuFolderPath
        $toggleLink = Join-Path $startFolder "Toggle Hotspot Automation.lnk"
        if (Test-Path -LiteralPath $startFolder) {
            New-Shortcut $toggleLink $ps "$baseArgs -Toggle" $env:WINDIR $icon $desc
        }
    } catch {}
}

function Create-Shortcuts {
    param([string]$InstalledScriptPath)

    $ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path -LiteralPath $ps)) { $ps = "powershell.exe" }

    $startFolder = Get-StartMenuFolderPath
    Ensure-Path $startFolder

    $publicDesktop = Join-Path $env:Public "Desktop"
    $baseArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$InstalledScriptPath`""

    $enabledIcon = Get-EnabledIcon
    $disabledIcon = Get-DisabledIcon

    New-Shortcut (Join-Path $startFolder "Toggle Hotspot Automation.lnk")   $ps "$baseArgs -Toggle"   $env:WINDIR $enabledIcon  "Toggle automation"
    New-Shortcut (Join-Path $startFolder "Enable Hotspot Automation.lnk")   $ps "$baseArgs -Enable"   $env:WINDIR $enabledIcon  "Enable automation"
    New-Shortcut (Join-Path $startFolder "Disable Hotspot Automation.lnk")  $ps "$baseArgs -Disable"  $env:WINDIR $disabledIcon "Disable automation"
    New-Shortcut (Join-Path $startFolder "Status.lnk")                      $ps "$baseArgs -Status"   $env:WINDIR $enabledIcon  "Show status"
    New-Shortcut (Join-Path $startFolder "Repair.lnk")                      $ps "$baseArgs -Repair"   $env:WINDIR $enabledIcon  "Repair task and shortcuts"
    New-Shortcut (Join-Path $startFolder "Update.lnk")                      $ps "$baseArgs -Update"   $env:WINDIR $enabledIcon  "Update installed script"
    New-Shortcut (Join-Path $startFolder "Doctor.lnk")                      $ps "$baseArgs -Doctor"   $env:WINDIR $enabledIcon  "Diagnostics"
    New-Shortcut (Join-Path $startFolder "Open Log.lnk")                    $ps "$baseArgs -OpenLog"  $env:WINDIR $enabledIcon  "Open log"
    New-Shortcut (Join-Path $startFolder "Uninstall.lnk")                   $ps "$baseArgs -Uninstall" $env:WINDIR $disabledIcon "Uninstall"

    New-Shortcut (Join-Path $publicDesktop $script:DesktopToggleShortcutName) $ps "$baseArgs -Toggle" $env:WINDIR $enabledIcon "Toggle automation"

    Update-ToggleShortcutVisual
}

function Remove-Shortcuts {
    $startFolder = Get-StartMenuFolderPath
    $desktopLink = Get-DesktopToggleShortcutPath

    try { Remove-Item -LiteralPath $desktopLink -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item -LiteralPath $startFolder -Recurse -Force -ErrorAction SilentlyContinue } catch {}
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
        $deadline = (Get-Date).AddSeconds(5)
        do {
            $st = (Get-ScheduledTask -TaskName $TaskName).State
            if ($st -eq "Running") {
                $started = $true
                break
            }
            Start-Sleep -Milliseconds 250
        } while ((Get-Date) -lt $deadline)
    } catch {}

    if (-not $started) {
        $p = Build-TaskArgs $InstalledScriptPath
        Start-Process -FilePath "powershell.exe" -ArgumentList ($p -join " ") -WindowStyle Hidden
        try { $st = (Get-ScheduledTask -TaskName $TaskName).State } catch {}
    }

    return $st
}

function Clean-InstallArtifacts {
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 300
    try { Stop-OldMonitorProcess $script:InstalledScriptPath } catch {}
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Remove-Shortcuts } catch {}
}

function Save-CurrentConfig {
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
    if (-not [string]::IsNullOrWhiteSpace($SourceUrl)) {
        $cfg.SourceUrl = [string]$SourceUrl
    } elseif (-not [string]::IsNullOrWhiteSpace($script:SourceUrl)) {
        $cfg.SourceUrl = [string]$script:SourceUrl
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
    $script:LogPath = Resolve-LogPath $script:LogPath

    Save-CurrentConfig

    Clean-InstallArtifacts

    $srcPath = $PSCommandPath

    if ([string]::IsNullOrWhiteSpace($srcPath) -or -not (Test-Path -LiteralPath $srcPath)) {
        $effectiveSource = $SourceUrl
        if ([string]::IsNullOrWhiteSpace($effectiveSource)) {
            $effectiveSource = $script:SourceUrl
        }

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

    $st = Register-OrRepairTask $script:InstalledScriptPath
    Create-Shortcuts $script:InstalledScriptPath
    Update-ToggleShortcutVisual

    Write-Host "Task state: $st" -ForegroundColor Cyan
    Write-Host "Installed. Task created: $TaskName" -ForegroundColor Green
    Write-Host "Logs: $script:LogPath" -ForegroundColor Cyan
    Write-Host "Start Menu: $($script:StartMenuFolderName)" -ForegroundColor Gray
    Write-Host "Desktop shortcut: $($script:DesktopToggleShortcutName)" -ForegroundColor Gray
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

    Write-Host "Uninstalled. Task removed and files deleted." -ForegroundColor Yellow
}

function Show-Status {
    $eth = Get-EthernetState
    $disabled = Is-AutomationDisabled

    Write-Host ("Automation disabled: " + $disabled) -ForegroundColor Yellow
    Write-Host ("Config: " + $script:ConfigPath) -ForegroundColor Gray

    Write-Host ("Ethernet Up: " + $eth.IsUp) -ForegroundColor Cyan
    if (@($eth.Names).Count -gt 0) {
        Write-Host ("Adapters: " + (@($eth.Names) -join ", ")) -ForegroundColor Cyan
    }

    $wifiPresent = Test-WifiAdapterPresent
    Write-Host ("Wi-Fi present: " + $wifiPresent) -ForegroundColor Cyan

    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) {
        Write-Host "Hotspot: Unknown (no connection profile)" -ForegroundColor Yellow
    } else {
        $cap = Get-TetheringCapabilityText $mgr
        $hst = "Unknown"
        try { $hst = $mgr.TetheringOperationalState.ToString() } catch {}
        Write-Host ("Hotspot: " + $hst + " | Capability: " + $cap) -ForegroundColor Green
    }

    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Host ("Scheduled task: Present (" + $t.State + ")") -ForegroundColor Green
    } catch {
        Write-Host "Scheduled task: Not found" -ForegroundColor Red
    }

    Write-Host ("Installed script: " + $script:InstalledScriptPath) -ForegroundColor Gray
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
                            $namesText = ""
                            if (@($eth.Names).Count -gt 0) { $namesText = (@($eth.Names) -join ", ") }
                            Write-Log "Ethernet stable ON. $namesText" "OK"
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

function Disable-Automation {
    Set-DisabledFlag $true
    if ($script:ForceOffWhenDisabled) { $null = Ensure-Hotspot "Off" }
    Write-Host "Automation disabled." -ForegroundColor Yellow
}

function Enable-Automation {
    Set-DisabledFlag $false
    Write-Host "Automation enabled." -ForegroundColor Green
}

function Toggle-Automation {
    if (Is-AutomationDisabled) {
        Set-DisabledFlag $false
        Write-Host "Automation enabled." -ForegroundColor Green
    } else {
        Set-DisabledFlag $true
        if ($script:ForceOffWhenDisabled) { $null = Ensure-Hotspot "Off" }
        Write-Host "Automation disabled." -ForegroundColor Yellow
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
    $script:SourceUrl = [string]$cfg.SourceUrl

    $st = Register-OrRepairTask $script:InstalledScriptPath
    Create-Shortcuts $script:InstalledScriptPath
    Update-ToggleShortcutVisual

    Write-Host "Task state: $st" -ForegroundColor Cyan
    Write-Host "Repair done." -ForegroundColor Green
}

function Do-Update {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to update." -ForegroundColor Red
        exit 1
    }

    $effectiveSource = $SourceUrl
    if ([string]::IsNullOrWhiteSpace($effectiveSource)) {
        $cfg = Load-Config
        $effectiveSource = [string]$cfg.SourceUrl
    }

    if ([string]::IsNullOrWhiteSpace($effectiveSource)) {
        Write-Host "Use -SourceUrl to update from URL (or install once with -SourceUrl)." -ForegroundColor Red
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
        if ($content -match "WindowsAutoHotspot" -and $content -match "Run-Monitor" -and $content -match "Get-EthernetState") {
            $ok = $true
        }
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

    $cfg = Load-Config
    $cfg.SourceUrl = $effectiveSource
    Save-Config $cfg

    Write-Host "Updated installed script." -ForegroundColor Green
    Do-Repair
}

function Invoke-MainSafe {
    try {
        switch ($PSCmdlet.ParameterSetName) {
            "Install"   { Install-App; break }
            "Uninstall" { Uninstall-App; break }
            "Status"    { Show-Status; break }
            "Run"       { Run-Monitor; break }
            "Disable"   { Disable-Automation; break }
            "Enable"    { Enable-Automation; break }
            "Toggle"    { Toggle-Automation; break }
            "OpenLog"   { Open-LogFile; break }
            "Doctor"    { Show-Doctor; break }
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
                Write-Host "  -Update     -SourceUrl <url> (needs Admin)" -ForegroundColor Gray
                Write-Host "  -Doctor" -ForegroundColor Gray
                Write-Host "  -OpenLog" -ForegroundColor Gray
                Write-Host "" -ForegroundColor Gray
                Write-Host "Examples:" -ForegroundColor Cyan
                Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Install" -ForegroundColor Gray
                Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Install -SourceUrl https://raw.githubusercontent.com/luizbizzio/windows-auto-hotspot/main/windows_auto_hotspot.ps1" -ForegroundColor Gray
                Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Toggle" -ForegroundColor Gray
                Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Repair" -ForegroundColor Gray
                Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Update -SourceUrl https://raw.githubusercontent.com/luizbizzio/windows-auto-hotspot/main/windows_auto_hotspot.ps1" -ForegroundColor Gray
                break
            }
        }
    } catch {
        $msg = $_.Exception.Message
        try { Write-Log ("Fatal error: " + $msg) "ERROR" } catch {}
        if (-not $Quiet) {
            Write-Host ("Fatal error: " + $msg) -ForegroundColor Red
        }
        exit 1
    }
}

Invoke-MainSafe
