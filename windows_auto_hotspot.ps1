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

$script:AppName = "Windows Auto Hotspot"
$script:StateDir = Join-Path $env:LOCALAPPDATA "WindowsAutoHotspot"
$script:DisableFlagPath = Join-Path $script:StateDir "hotspot.disabled"
$script:ConfigPath = Join-Path $script:StateDir "config.json"
$script:InstalledScriptPath = Join-Path $InstallDir "windows-auto-hotspot.ps1"
$script:StartMenuFolder = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Windows Auto Hotspot"
$script:DesktopToggleBaseName = "Hotspot Toggle"

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
        Ensure-Path (Split-Path -Parent $Candidate)
        if (-not (Test-Path -LiteralPath $Candidate)) {
            New-Item -ItemType File -Path $Candidate -Force | Out-Null
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

function Show-Toast {
    param(
        [string]$Title,
        [string]$Body
    )

    try {
        $titleEsc = [System.Security.SecurityElement]::Escape([string]$Title)
        $bodyEsc = [System.Security.SecurityElement]::Escape([string]$Body)

        $xmlText = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>$titleEsc</text>
      <text>$bodyEsc</text>
    </binding>
  </visual>
</toast>
"@

        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml($xmlText)

        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Windows PowerShell")
        $notifier.Show($toast)
    } catch {}
}

function Convert-ConfigValue {
    param([string]$Value)
    if ($Value -match '^(?i:true|false)$') { return [bool]::Parse($Value) }
    $n = 0
    if ([int]::TryParse($Value, [ref]$n)) { return $n }
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
        $script:SourceUrl = [string]$SourceUrl
    }
}

Apply-Config

function Persist-CurrentConfig {
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
    $cfg.SourceUrl = [string]$script:SourceUrl
    Save-Config $cfg
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
        IsUp = (@($adapters).Count -gt 0)
        Names = $names
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
        $wifi = @($all | Where-Object {
            $_.Status -ne "Disabled" -and (
                $_.InterfaceDescription -match "Wi-?Fi|Wireless|802\.11" -or
                ($_.NdisPhysicalMedium -eq 9)
            )
        })
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

function Stop-MonitorProcesses {
    param([string]$ScriptPath)

    try {
        $procs = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue)
        foreach ($p in $procs) {
            $cmd = [string]$p.CommandLine
            if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
            if ($cmd -like "*$ScriptPath*" -and $cmd -match '(^|\s)-Run(\s|$)') {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}

function Is-AutomationDisabled {
    return (Test-Path -LiteralPath $script:DisableFlagPath)
}

function Get-DesktopToggleShortcutPathEnabled {
    return (Join-Path $env:Public "Desktop\$($script:DesktopToggleBaseName) [ENABLED].lnk")
}

function Get-DesktopToggleShortcutPathDisabled {
    return (Join-Path $env:Public "Desktop\$($script:DesktopToggleBaseName) [DISABLED].lnk")
}

function Get-IconMap {
    $win = Join-Path $env:SystemRoot "System32"
    [pscustomobject]@{
        ToggleBase = (Join-Path $win "pnidui.dll") + ",0"
        ToggleEnabled = (Join-Path $win "imageres.dll") + ",101"
        ToggleDisabled = (Join-Path $win "imageres.dll") + ",109"
        Enable = (Join-Path $win "shell32.dll") + ",167"
        Disable = (Join-Path $win "shell32.dll") + ",131"
        Status = (Join-Path $win "shell32.dll") + ",23"
        OpenLog = (Join-Path $win "shell32.dll") + ",70"
        Repair = (Join-Path $win "shell32.dll") + ",316"
        Uninstall = (Join-Path $win "shell32.dll") + ",132"
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

function Remove-ShortcutIfExists {
    param([string]$Path)
    try {
        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

function Update-DesktopToggleShortcut {
    if (-not (Test-Path -LiteralPath $script:InstalledScriptPath)) { return }

    $icons = Get-IconMap
    $ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $baseArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$($script:InstalledScriptPath)`""
    $linkEnabled = Get-DesktopToggleShortcutPathEnabled
    $linkDisabled = Get-DesktopToggleShortcutPathDisabled

    Remove-ShortcutIfExists $linkEnabled
    Remove-ShortcutIfExists $linkDisabled

    if (Is-AutomationDisabled) {
        $link = $linkDisabled
        $icon = $icons.ToggleDisabled
    } else {
        $link = $linkEnabled
        $icon = $icons.ToggleEnabled
    }

    $null = New-Shortcut -LinkPath $link -TargetPath $ps -Arguments "$baseArgs -Toggle" -WorkingDirectory $env:WINDIR -IconLocation $icon
}

function Create-Shortcuts {
    param([string]$InstalledScriptPath)

    $ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $icons = Get-IconMap
    $baseArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$InstalledScriptPath`""
    Ensure-Path $script:StartMenuFolder

    New-Shortcut (Join-Path $script:StartMenuFolder "Enable Automation.lnk")   $ps "$baseArgs -Enable"  $env:WINDIR $icons.Enable | Out-Null
    New-Shortcut (Join-Path $script:StartMenuFolder "Disable Automation.lnk")  $ps "$baseArgs -Disable" $env:WINDIR $icons.Disable | Out-Null
    New-Shortcut (Join-Path $script:StartMenuFolder "Toggle Automation.lnk")   $ps "$baseArgs -Toggle"  $env:WINDIR $icons.ToggleBase | Out-Null
    New-Shortcut (Join-Path $script:StartMenuFolder "Status.lnk")              $ps "-NoExit $baseArgs -Status" $env:WINDIR $icons.Status | Out-Null
    New-Shortcut (Join-Path $script:StartMenuFolder "Open Log.lnk")            $ps "$baseArgs -OpenLog" $env:WINDIR $icons.OpenLog | Out-Null
    New-Shortcut (Join-Path $script:StartMenuFolder "Repair.lnk")              $ps "$baseArgs -Repair" $env:WINDIR $icons.Repair | Out-Null
    New-Shortcut (Join-Path $script:StartMenuFolder "Uninstall.lnk")           $ps "$baseArgs -Uninstall" $env:WINDIR $icons.Uninstall | Out-Null

    Update-DesktopToggleShortcut
}

function Remove-Shortcuts {
    Remove-ShortcutIfExists (Get-DesktopToggleShortcutPathEnabled)
    Remove-ShortcutIfExists (Get-DesktopToggleShortcutPathDisabled)

    try {
        if (Test-Path -LiteralPath $script:StartMenuFolder) {
            Remove-Item -LiteralPath $script:StartMenuFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {}
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

function Set-DisabledFlag {
    param([bool]$Disabled)

    Ensure-Path $script:StateDir

    if ($Disabled) {
        Set-Content -LiteralPath $script:DisableFlagPath -Value "disabled" -Encoding UTF8
        Write-Log "Automation disabled by user." "WARN"
        Update-DesktopToggleShortcut
        Show-Toast -Title $script:AppName -Body "Automation disabled"
    } else {
        Remove-Item -LiteralPath $script:DisableFlagPath -Force -ErrorAction SilentlyContinue
        Write-Log "Automation enabled by user." "OK"
        Update-DesktopToggleShortcut
        Show-Toast -Title $script:AppName -Body "Automation enabled"
    }
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
    Start-Sleep -Milliseconds 300
    Stop-MonitorProcesses $InstalledScriptPath

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

    $state = "Unknown"
    $started = $false

    try {
        Start-ScheduledTask -TaskName $TaskName
        $deadline = (Get-Date).AddSeconds(8)
        do {
            try { $state = (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State } catch { $state = "Unknown" }
            if ($state -eq "Running") {
                $started = $true
                break
            }
            Start-Sleep -Milliseconds 250
        } while ((Get-Date) -lt $deadline)
    } catch {}

    if (-not $started) {
        $manualArgs = Build-TaskArgs $InstalledScriptPath
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList ($manualArgs -join " ") -WindowStyle Hidden
        } catch {}
        try { $state = (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State } catch {}
    }

    return $state
}

function Remove-AllInstallArtifacts {
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 300
    try { Stop-MonitorProcesses $script:InstalledScriptPath } catch {}
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    Remove-Shortcuts
    try {
        if (Test-Path -LiteralPath $InstallDir) {
            Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {}
    try {
        if (Test-Path -LiteralPath $script:StateDir) {
            Remove-Item -LiteralPath $script:StateDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

function Install-App {
    if (-not (Test-Admin)) {
        Write-Host "Run PowerShell as Administrator to install." -ForegroundColor Red
        exit 1
    }

    Remove-AllInstallArtifacts

    Ensure-Path $InstallDir
    Ensure-Path $script:StateDir

    if ($PSBoundParameters.ContainsKey("SourceUrl")) {
        $script:SourceUrl = $SourceUrl
    }

    $srcPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($srcPath) -or -not (Test-Path -LiteralPath $srcPath)) {
        if ([string]::IsNullOrWhiteSpace($script:SourceUrl)) {
            Write-Host "No local script path and no -SourceUrl provided." -ForegroundColor Red
            exit 1
        }
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $script:SourceUrl -OutFile $script:InstalledScriptPath
        } catch {
            Write-Host ("Download failed: " + $_.Exception.Message) -ForegroundColor Red
            exit 1
        }
    } else {
        Copy-Item -LiteralPath $srcPath -Destination $script:InstalledScriptPath -Force
    }

    $script:LogPath = Resolve-LogPath $script:LogPath

    if (-not $PSBoundParameters.ContainsKey("ForceOffWhenDisabled")) {
        $script:ForceOffWhenDisabled = $true
    }

    Persist-CurrentConfig

    $state = Register-OrRepairTask $script:InstalledScriptPath
    Create-Shortcuts $script:InstalledScriptPath

    Write-Host "Task state: $state" -ForegroundColor Cyan
    Write-Host "Installed (clean reinstall). Task created: $TaskName" -ForegroundColor Green
    Write-Host "Logs: $script:LogPath" -ForegroundColor Cyan
    Write-Host "Start Menu folder: Windows Auto Hotspot" -ForegroundColor Gray
    Write-Host "Desktop shortcut: one Toggle shortcut" -ForegroundColor Gray

    Show-Toast -Title $script:AppName -Body "Installed and running"
}

function Uninstall-App {
    if (-not (Test-Admin)) {
        Write-Host "Run PowerShell as Administrator to uninstall." -ForegroundColor Red
        exit 1
    }

    Remove-AllInstallArtifacts

    Write-Host "Uninstalled. Task, files, config and shortcuts removed." -ForegroundColor Yellow
    Show-Toast -Title $script:AppName -Body "Uninstalled"
}

function Show-Status {
    Write-Host "Windows Auto Hotspot Status" -ForegroundColor Cyan
    Write-Host ("Automation disabled: " + (Is-AutomationDisabled)) -ForegroundColor Yellow
    Write-Host ("Config file: " + $script:ConfigPath) -ForegroundColor Gray
    Write-Host ("Log file: " + $script:LogPath) -ForegroundColor Gray
    Write-Host ("Install dir: " + $InstallDir) -ForegroundColor Gray
    Write-Host ""

    $wifiPresent = Test-WifiAdapterPresent
    Write-Host ("Wi-Fi adapter present: " + $wifiPresent) -ForegroundColor Cyan

    $eth = Get-EthernetState
    Write-Host ("Ethernet Up: " + $eth.IsUp) -ForegroundColor Cyan
    if (@($eth.Names).Count -gt 0) {
        Write-Host ("Ethernet adapters: " + (@($eth.Names) -join ", ")) -ForegroundColor Cyan
    }

    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) {
        Write-Host "Hotspot manager: unavailable (no connection profile)" -ForegroundColor Yellow
    } else {
        $cap = Get-TetheringCapabilityText $mgr
        $hst = "Unknown"
        try { $hst = $mgr.TetheringOperationalState.ToString() } catch {}
        Write-Host ("Hotspot state: " + $hst) -ForegroundColor Green
        Write-Host ("Hotspot capability: " + $cap) -ForegroundColor Green
    }

    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Host ("Scheduled task: Present (" + $t.State + ")") -ForegroundColor Green
    } catch {
        Write-Host "Scheduled task: Not found" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "Desktop toggle shortcut is renamed based on state." -ForegroundColor Gray
    Write-Host "If Status is opened from Start Menu shortcut, it stays open." -ForegroundColor Gray
}

function Disable-Automation {
    Set-DisabledFlag $true
    if ($script:ForceOffWhenDisabled) {
        $null = Ensure-Hotspot "Off"
    }
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
        if ($script:ForceOffWhenDisabled) {
            $null = Ensure-Hotspot "Off"
        }
        Write-Host "Automation disabled." -ForegroundColor Yellow
    }
}

function Do-Repair {
    if (-not (Test-Admin)) {
        Write-Host "Run PowerShell as Administrator to repair." -ForegroundColor Red
        exit 1
    }

    if (-not (Test-Path -LiteralPath $script:InstalledScriptPath)) {
        Write-Host "Installed script not found. Run -Install first." -ForegroundColor Red
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

    Persist-CurrentConfig

    $state = Register-OrRepairTask $script:InstalledScriptPath
    Create-Shortcuts $script:InstalledScriptPath

    Write-Host "Task state: $state" -ForegroundColor Cyan
    Write-Host "Repair done." -ForegroundColor Green
    Show-Toast -Title $script:AppName -Body "Repair completed"
}

function Do-Update {
    if (-not (Test-Admin)) {
        Write-Host "Run PowerShell as Administrator to update." -ForegroundColor Red
        exit 1
    }

    $url = $null
    if (-not [string]::IsNullOrWhiteSpace($SourceUrl)) {
        $url = $SourceUrl
    } elseif (-not [string]::IsNullOrWhiteSpace($script:SourceUrl)) {
        $url = $script:SourceUrl
    }

    if ([string]::IsNullOrWhiteSpace($url)) {
        Write-Host "No source URL known. Use -Update -SourceUrl <raw ps1 url>." -ForegroundColor Red
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
        if ($content -match "WindowsAutoHotspot" -and $content -match "Run-Monitor" -and $content -match "Install-App") {
            $ok = $true
        }
    } catch {
        $ok = $false
    }

    if (-not $ok) {
        try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch {}
        Write-Host "Downloaded file failed validation. Aborting update." -ForegroundColor Red
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

    $script:SourceUrl = $url
    Persist-CurrentConfig

    Write-Host "Updated installed script." -ForegroundColor Green
    Do-Repair
    Show-Toast -Title $script:AppName -Body "Updated successfully"
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
                    if ($script:ForceOffWhenDisabled) {
                        $null = Ensure-Hotspot "Off"
                    }
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
        Write-Host "Usage:" -ForegroundColor Cyan
        Write-Host "  -Install    (Admin, clean reinstall)" -ForegroundColor Gray
        Write-Host "  -Uninstall  (Admin, remove everything)" -ForegroundColor Gray
        Write-Host "  -Status" -ForegroundColor Gray
        Write-Host "  -Enable" -ForegroundColor Gray
        Write-Host "  -Disable" -ForegroundColor Gray
        Write-Host "  -Toggle" -ForegroundColor Gray
        Write-Host "  -OpenLog" -ForegroundColor Gray
        Write-Host "  -Repair    (Admin)" -ForegroundColor Gray
        Write-Host "  -Update    -SourceUrl <raw ps1 url> (Admin)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Examples:" -ForegroundColor Cyan
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Install -SourceUrl <raw_url>" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Toggle" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Status" -ForegroundColor Gray
        break
    }
}
