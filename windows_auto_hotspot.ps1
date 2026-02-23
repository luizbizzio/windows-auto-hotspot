[CmdletBinding(DefaultParameterSetName = "Help")]
param(
    [Parameter(ParameterSetName = "Install", Mandatory = $true)]
    [switch]$Install,

    [Parameter(ParameterSetName = "Uninstall", Mandatory = $true)]
    [switch]$Uninstall,

    [Parameter(ParameterSetName = "Status", Mandatory = $true)]
    [switch]$Status,

    [Parameter(ParameterSetName = "Enable", Mandatory = $true)]
    [switch]$Enable,

    [Parameter(ParameterSetName = "Disable", Mandatory = $true)]
    [switch]$Disable,

    [Parameter(ParameterSetName = "Toggle", Mandatory = $true)]
    [switch]$Toggle,

    [Parameter(ParameterSetName = "OpenLog", Mandatory = $true)]
    [switch]$OpenLog,

    [Parameter(ParameterSetName = "Run", Mandatory = $true)]
    [switch]$Run,

    [string]$TaskName = "WindowsAutoHotspot",

    [string]$InstallDir = "$env:ProgramData\WindowsAutoHotspot",

    [string]$LogPath,

    [ValidateRange(1, 3600)]
    [int]$CheckIntervalSec = 5,

    [ValidateRange(1, 100)]
    [int]$UpStableChecks = 2,

    [ValidateRange(1, 100)]
    [int]$DownStableChecks = 2,

    [string]$AdapterName,

    [ValidateRange(0, 1440)]
    [int]$CooldownOnFailMin = 5,

    [ValidateRange(0, 1440)]
    [int]$CooldownOffFailMin = 2,

    [ValidateRange(1, 3600)]
    [int]$CooldownOnExceptionSec = 30,

    [switch]$ForceOffWhenDisabled,

    [switch]$Quiet,

    [switch]$NoDelay,

    [string]$SourceUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:CliBoundParameters = @{}
foreach ($k in $PSBoundParameters.Keys) {
    $script:CliBoundParameters[$k] = $PSBoundParameters[$k]
}

$script:StateDir = Join-Path $env:LOCALAPPDATA "WindowsAutoHotspot"
$script:DisableFlagPath = Join-Path $script:StateDir "hotspot.disabled"
$script:ConfigPath = Join-Path $script:StateDir "config.json"
$script:InstalledScriptPath = Join-Path $InstallDir "windows-auto-hotspot.ps1"
$script:DesktopToggleShortcutName = "Windows Auto Hotspot Toggle.lnk"
$script:StartMenuFolderName = "Windows Auto Hotspot"

function Initialize-Path {
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
        $parent = Split-Path -Parent $Candidate
        Initialize-Path $parent
        if (-not (Test-Path -LiteralPath $Candidate)) {
            New-Item -ItemType File -Path $Candidate -Force | Out-Null
        }
        return $Candidate
    } catch {
        $fallback = Join-Path $script:StateDir "windows-auto-hotspot.log"
        try {
            Initialize-Path (Split-Path -Parent $fallback)
            if (-not (Test-Path -LiteralPath $fallback)) {
                New-Item -ItemType File -Path $fallback -Force | Out-Null
            }
        } catch {}
        return $fallback
    }
}

function Start-ElevatedSelf {
    if (Test-Admin) { return }

    $self = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($self) -or -not (Test-Path -LiteralPath $self)) {
        Write-Host "Run as Administrator." -ForegroundColor Red
        exit 1
    }

    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $self
    )

    foreach ($k in $script:CliBoundParameters.Keys) {
        $v = $script:CliBoundParameters[$k]

        if ($v -is [System.Management.Automation.SwitchParameter]) {
            if ($v.IsPresent) { $argList += "-$k" }
        } elseif ($null -ne $v) {
            $argList += "-$k"
            $argList += [string]$v
        }
    }

    try {
        $argLine = ($argList | ForEach-Object {
            if ($_ -match '\s') { '"' + ($_ -replace '"','""') + '"' } else { $_ }
        }) -join ' '

        $p = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argLine -PassThru -Wait
        exit $p.ExitCode
    } catch {
        Write-Host "Elevation canceled." -ForegroundColor Yellow
        exit 1
    }
}

Initialize-Path $script:StateDir

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

function Start-UiPause {
    if ($NoDelay) { return }
    if (-not $script:IsInteractive) { return }
    Start-Sleep -Milliseconds 250
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
        Initialize-Path (Split-Path -Parent $script:LogPath)
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
        Start-UiPause
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

function Get-Config {
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
    Initialize-Path $script:StateDir
    $Cfg | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
}

function Set-ConfigRuntime {
    $cfg = Get-Config

    if (-not $script:CliBoundParameters.ContainsKey("CheckIntervalSec")) { $script:CheckIntervalSec = [int]$cfg.CheckIntervalSec } else { $script:CheckIntervalSec = $CheckIntervalSec }
    if (-not $script:CliBoundParameters.ContainsKey("UpStableChecks")) { $script:UpStableChecks = [int]$cfg.UpStableChecks } else { $script:UpStableChecks = $UpStableChecks }
    if (-not $script:CliBoundParameters.ContainsKey("DownStableChecks")) { $script:DownStableChecks = [int]$cfg.DownStableChecks } else { $script:DownStableChecks = $DownStableChecks }
    if (-not $script:CliBoundParameters.ContainsKey("AdapterName")) { $script:AdapterName = [string]$cfg.AdapterName } else { $script:AdapterName = $AdapterName }
    if (-not $script:CliBoundParameters.ContainsKey("CooldownOnFailMin")) { $script:CooldownOnFailMin = [int]$cfg.CooldownOnFailMin } else { $script:CooldownOnFailMin = $CooldownOnFailMin }
    if (-not $script:CliBoundParameters.ContainsKey("CooldownOffFailMin")) { $script:CooldownOffFailMin = [int]$cfg.CooldownOffFailMin } else { $script:CooldownOffFailMin = $CooldownOffFailMin }
    if (-not $script:CliBoundParameters.ContainsKey("CooldownOnExceptionSec")) { $script:CooldownOnExceptionSec = [int]$cfg.CooldownOnExceptionSec } else { $script:CooldownOnExceptionSec = $CooldownOnExceptionSec }

    if (-not $script:CliBoundParameters.ContainsKey("ForceOffWhenDisabled")) {
        $script:ForceOffWhenDisabled = [bool]$cfg.ForceOffWhenDisabled
    } else {
        $script:ForceOffWhenDisabled = [bool]$ForceOffWhenDisabled
    }

    if (-not $script:CliBoundParameters.ContainsKey("LogPath")) {
        $script:LogPath = Resolve-LogPath ([string]$cfg.LogPath)
    } else {
        $script:LogPath = Resolve-LogPath $LogPath
    }
}

Set-ConfigRuntime

function Test-WifiAdapterPresent {
    try {
        $all = @(Get-NetAdapter -ErrorAction SilentlyContinue)
        $wifi = @(
            $all | Where-Object {
                $_ -and $_.Status -ne "Disabled" -and (
                    $_.InterfaceDescription -match "Wi-?Fi|Wireless|802\.11" -or
                    $_.NdisPhysicalMedium -eq 9
                )
            }
        )
        return ($wifi.Count -gt 0)
    } catch {
        return $false
    }
}

function Get-EthernetState {
    $adapters = @()

    try {
        $all = @(Get-NetAdapter -ErrorAction SilentlyContinue)
        if ($script:AdapterName) {
            $all = @($all | Where-Object { $_.Name -eq $script:AdapterName })
        }

        $adapters = @(
            $all | Where-Object {
                $_ -and $_.Status -eq "Up" -and (
                    $_.MediaType -eq "802.3" -or
                    $_.NdisPhysicalMedium -eq 14
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
        IsUp = ($adapters.Count -gt 0)
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
        $connectionProfile = Get-ConnectionProfileSafe
        if ($null -eq $connectionProfile) { return $null }

        $tm = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]
        return $tm::CreateFromConnectionProfile($connectionProfile)
    } catch {
        return $null
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

function Get-HotspotStateSafe {
    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) { return "Unknown" }
    try { return $mgr.TetheringOperationalState.ToString() } catch { return "Unknown" }
}

function Wait-HotspotState {
    param(
        [ValidateSet("On","Off")]
        [string]$Desired,
        [int]$TimeoutSec = 20
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)

    while ((Get-Date) -lt $deadline) {
        $state = Get-HotspotStateSafe
        if ($state -eq $Desired) { return $true }
        Start-Sleep -Milliseconds 250
    }

    return $false
}

function Set-HotspotState {
    param(
        [ValidateSet("On","Off")]
        [string]$Desired,
        [int]$TimeoutSec = 20
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
            $null = $mgr.StartTetheringAsync()
        } catch {
            Write-Log ("Failed to start hotspot: " + $_.Exception.Message) "ERROR"
            return $false
        }

        $ok = Wait-HotspotState -Desired "On" -TimeoutSec $TimeoutSec
        if ($ok) {
            Write-Log "Hotspot is ON." "OK"
            return $true
        }

        $final = Get-HotspotStateSafe
        Write-Log "Start hotspot timeout. Current state: $final" "ERROR"
        return $false
    }

    if ($state -eq "Off") { return $true }
    Write-Log "Turning hotspot OFF..." "INFO"
    try {
        $null = $mgr.StopTetheringAsync()
    } catch {
        Write-Log ("Failed to stop hotspot: " + $_.Exception.Message) "ERROR"
        return $false
    }

    $ok = Wait-HotspotState -Desired "Off" -TimeoutSec $TimeoutSec
    if ($ok) {
        Write-Log "Hotspot is OFF." "OK"
        return $true
    }

    $final2 = Get-HotspotStateSafe
    Write-Log "Stop hotspot timeout. Current state: $final2" "ERROR"
    return $false
}

function Enter-SingleInstanceLock {
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
        $escaped = [regex]::Escape($ScriptPath)

        foreach ($p in $procs) {
            $cmd = $p.CommandLine
            if ([string]::IsNullOrWhiteSpace($cmd)) { continue }

            if ($cmd -match $escaped -and $cmd -match '(^|\s)-Run(\s|$)') {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}

function Test-AutomationDisabled {
    return (Test-Path -LiteralPath $script:DisableFlagPath)
}

function Set-DisabledFlag {
    param([bool]$Disabled)

    Initialize-Path $script:StateDir

    if ($Disabled) {
        Set-Content -LiteralPath $script:DisableFlagPath -Value "disabled" -Encoding UTF8
        Write-Log "Automation disabled by user." "WARN"
    } else {
        Remove-Item -LiteralPath $script:DisableFlagPath -Force -ErrorAction SilentlyContinue
        Write-Log "Automation enabled by user." "OK"
    }

    Update-ToggleDesktopShortcut
}

function Show-LogFile {
    try {
        if (-not (Test-Path -LiteralPath $script:LogPath)) {
            Write-Host "Log not found: $script:LogPath" -ForegroundColor Yellow
            return
        }
        Start-Process -FilePath "notepad.exe" -ArgumentList "`"$script:LogPath`""
    } catch {
        Write-Host ("Failed to open log: " + $_.Exception.Message) -ForegroundColor Red
    }
}

function Start-TaskNow {
    try {
        Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    } catch {}
}

function Set-DesiredHotspotStateNow {
    if (Test-AutomationDisabled) {
        Write-Log "Automation is disabled." "WARN"
        if ($script:ForceOffWhenDisabled) {
            $null = Set-HotspotState "Off" 8
        }
        return
    }

    $eth = Get-EthernetState
    if ($eth.IsUp) {
        $names = ""
        if (@($eth.Names).Count -gt 0) { $names = (@($eth.Names) -join ", ") }
        Write-Log "Immediate apply: Ethernet ON. $names" "INFO"
        $null = Set-HotspotState "On" 12
    } else {
        Write-Log "Immediate apply: Ethernet OFF." "INFO"
        $null = Set-HotspotState "Off" 8
    }
}

function New-Shortcut {
    param(
        [string]$LinkPath,
        [string]$TargetPath,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string]$IconLocation
    )

    try {
        Initialize-Path (Split-Path -Parent $LinkPath)
        $wsh = New-Object -ComObject WScript.Shell
        $sc = $wsh.CreateShortcut($LinkPath)
        $sc.TargetPath = $TargetPath
        $sc.Arguments = ($Arguments -join " ")
        if ($WorkingDirectory) { $sc.WorkingDirectory = $WorkingDirectory }
        if ($IconLocation) { $sc.IconLocation = $IconLocation }
        $sc.Save()
    } catch {}
}

function Get-IconMap {
    $imageres = Join-Path $env:SystemRoot "System32\imageres.dll"
    $shell32 = Join-Path $env:SystemRoot "System32\SHELL32.dll"
    $uninstall = Join-Path $env:SystemRoot "System32\msiexec.exe"
    [pscustomobject]@{
        Toggle = "$shell32,243"
        Enable = "$imageres,101"
        Disable = "$imageres,100"
        Status = "$imageres,144"
        Log = "$imageres,97"
        Uninstall = "$uninstall,0"
        Folder = "$shell32,243"
    }
}

function New-Shortcuts {
    param([string]$InstalledScriptPath)

    $ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $icons = Get-IconMap

    $commonStart = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    $folder = Join-Path $commonStart $script:StartMenuFolderName
    Initialize-Path $folder

    $publicDesktop = Join-Path $env:Public "Desktop"

    $toggleBase = @(
        "-NoProfile","-ExecutionPolicy","Bypass","-WindowStyle","Hidden","-File","`"$InstalledScriptPath`"","-Toggle"
    )

    $enableBase = @(
        "-NoProfile","-ExecutionPolicy","Bypass","-WindowStyle","Hidden","-File","`"$InstalledScriptPath`"","-Enable"
    )

    $disableBase = @(
        "-NoProfile","-ExecutionPolicy","Bypass","-WindowStyle","Hidden","-File","`"$InstalledScriptPath`"","-Disable"
    )

    $openLogBase = @(
        "-NoProfile","-ExecutionPolicy","Bypass","-WindowStyle","Hidden","-File","`"$InstalledScriptPath`"","-OpenLog"
    )

    $statusBase = @(
        "-NoProfile","-ExecutionPolicy","Bypass","-NoExit","-File","`"$InstalledScriptPath`"","-Status"
    )

    $uninstallBase = @(
        "-NoProfile","-ExecutionPolicy","Bypass","-File","`"$InstalledScriptPath`"","-Uninstall"
    )

    New-Shortcut (Join-Path $folder "WAH - Toggle.lnk") $ps $toggleBase $env:WINDIR $icons.Toggle
    New-Shortcut (Join-Path $folder "WAH - Enable.lnk") $ps $enableBase $env:WINDIR $icons.Enable
    New-Shortcut (Join-Path $folder "WAH - Disable.lnk") $ps $disableBase $env:WINDIR $icons.Disable
    New-Shortcut (Join-Path $folder "WAH - Status.lnk") $ps $statusBase $env:WINDIR $icons.Status
    New-Shortcut (Join-Path $folder "WAH - Open Log.lnk") $ps $openLogBase $env:WINDIR $icons.Log
    New-Shortcut (Join-Path $folder "WAH - Uninstall.lnk") $ps $uninstallBase $env:WINDIR $icons.Uninstall

    New-Shortcut (Join-Path $publicDesktop $script:DesktopToggleShortcutName) $ps $toggleBase $env:WINDIR $icons.Toggle
    Update-ToggleDesktopShortcut
}

function Update-ToggleDesktopShortcut {
    try {
        $publicDesktop = Join-Path $env:Public "Desktop"
        $lnk = Join-Path $publicDesktop $script:DesktopToggleShortcutName
        if (-not (Test-Path -LiteralPath $lnk)) { return }

        $wsh = New-Object -ComObject WScript.Shell
        $sc = $wsh.CreateShortcut($lnk)

        $icons = Get-IconMap
        if (Test-AutomationDisabled) {
            $sc.Description = "Windows Auto Hotspot Toggle (currently disabled)"
            $sc.IconLocation = $icons.Disable
        } else {
            $sc.Description = "Windows Auto Hotspot Toggle (currently enabled)"
            $sc.IconLocation = $icons.Toggle
        }

        $sc.Save()
    } catch {}
}

function Remove-Shortcuts {
    $commonStart = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    $folder = Join-Path $commonStart $script:StartMenuFolderName
    $publicDesktop = Join-Path $env:Public "Desktop"

    try { Remove-Item -LiteralPath (Join-Path $publicDesktop $script:DesktopToggleShortcutName) -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

function Get-TaskArgs {
    param([string]$InstalledScriptPath)

    $taskArgsList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", "`"$InstalledScriptPath`"",
        "-Run",
        "-Quiet",
        "-NoDelay",
        "-CheckIntervalSec", $script:CheckIntervalSec,
        "-UpStableChecks", $script:UpStableChecks,
        "-DownStableChecks", $script:DownStableChecks,
        "-CooldownOnFailMin", $script:CooldownOnFailMin,
        "-CooldownOffFailMin", $script:CooldownOffFailMin,
        "-CooldownOnExceptionSec", $script:CooldownOnExceptionSec,
        "-LogPath", "`"$script:LogPath`""
    )

    if ($script:AdapterName) {
        $taskArgsList += @("-AdapterName", "`"$script:AdapterName`"")
    }

    if ($script:ForceOffWhenDisabled) {
        $taskArgsList += @("-ForceOffWhenDisabled")
    }

    return $taskArgsList
}

function Register-Task {
    param([string]$InstalledScriptPath)

    $userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $taskArgs = Get-TaskArgs $InstalledScriptPath

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ($taskArgs -join " ")
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Highest

    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Days 3650) `
        -MultipleInstances IgnoreNew `
        -RestartCount 30 `
        -RestartInterval (New-TimeSpan -Minutes 1)

    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

    try { Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}

    try { return (Get-ScheduledTask -TaskName $TaskName).State } catch { return "Unknown" }
}

function Install-App {
    if (-not (Test-Admin)) { Start-ElevatedSelf }

    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to install." -ForegroundColor Red
        exit 1
    }

    Initialize-Path $InstallDir
    Initialize-Path $script:StateDir

    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 300
    try { Stop-OldMonitorProcess $script:InstalledScriptPath } catch {}
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    Remove-Shortcuts

    $srcPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($srcPath) -or -not (Test-Path -LiteralPath $srcPath)) {
        if ([string]::IsNullOrWhiteSpace($SourceUrl)) {
            Write-Host "This script has no file path. Use -SourceUrl to install from URL." -ForegroundColor Red
            exit 1
        }

        try {
            $uri = [Uri]$SourceUrl
            if ($uri.Scheme -ne "https") {
                Write-Host "SourceUrl must use HTTPS." -ForegroundColor Red
                exit 1
            }
        } catch {
            Write-Host "Invalid SourceUrl." -ForegroundColor Red
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

    $cfg = Get-Config
    $cfg.CheckIntervalSec = $script:CheckIntervalSec
    $cfg.UpStableChecks = $script:UpStableChecks
    $cfg.DownStableChecks = $script:DownStableChecks
    $cfg.AdapterName = $script:AdapterName
    $cfg.CooldownOnFailMin = $script:CooldownOnFailMin
    $cfg.CooldownOffFailMin = $script:CooldownOffFailMin
    $cfg.CooldownOnExceptionSec = $script:CooldownOnExceptionSec
    $cfg.ForceOffWhenDisabled = [bool]$script:ForceOffWhenDisabled
    $cfg.LogPath = $script:LogPath
    Save-Config $cfg

    Set-DisabledFlag -Disabled:$false

    $st = Register-Task $script:InstalledScriptPath
    New-Shortcuts $script:InstalledScriptPath

    Write-Host "Task state: $st" -ForegroundColor Cyan
    Write-Host "Installed (clean reinstall)." -ForegroundColor Green
    Write-Host "Task: $TaskName" -ForegroundColor Gray
    Write-Host "Logs: $script:LogPath" -ForegroundColor Gray
    Write-Host "Config: $script:ConfigPath" -ForegroundColor Gray
    Write-Host "Desktop shortcut: $script:DesktopToggleShortcutName" -ForegroundColor Gray
    Write-Host "Start Menu folder: $script:StartMenuFolderName" -ForegroundColor Gray
}

function Uninstall-App {
    if (-not (Test-Admin)) { Start-ElevatedSelf }

    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to uninstall." -ForegroundColor Red
        exit 1
    }

    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 300

    try { Stop-OldMonitorProcess $script:InstalledScriptPath } catch {}
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

    Write-Host "Uninstalled. Task, files, state and shortcuts removed." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
}

function Show-StatusInfo {
    $eth = Get-EthernetState
    Write-Host ("Ethernet Up: " + $eth.IsUp) -ForegroundColor Cyan
    if ($eth.Names -and @($eth.Names).Count -gt 0) {
        Write-Host ("Adapters: " + (@($eth.Names) -join ", ")) -ForegroundColor Cyan
    }

    $disabled = Test-AutomationDisabled
    if ($disabled) {
        Write-Host "Automation: DISABLED" -ForegroundColor Red
    } else {
        Write-Host "Automation: ENABLED" -ForegroundColor Green
    }

    Write-Host ("Log file: " + $script:LogPath) -ForegroundColor Gray
    Write-Host ("Config file: " + $script:ConfigPath) -ForegroundColor Gray
    Write-Host ("Wi-Fi present: " + (Test-WifiAdapterPresent)) -ForegroundColor Gray

    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) {
        Write-Host "Hotspot: Unknown (no connection profile)" -ForegroundColor Yellow
    } else {
        $cap = Get-TetheringCapabilityText $mgr
        $st = "Unknown"
        try { $st = $mgr.TetheringOperationalState.ToString() } catch {}

        if ($st -eq "On") {
            Write-Host ("Hotspot: " + $st + " | Capability: " + $cap) -ForegroundColor Green
        } elseif ($st -eq "Off") {
            Write-Host ("Hotspot: " + $st + " | Capability: " + $cap) -ForegroundColor Yellow
        } else {
            Write-Host ("Hotspot: " + $st + " | Capability: " + $cap) -ForegroundColor Cyan
        }
    }

    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $taskState = [string]$t.State
        $taskColor = "Green"

        switch ($taskState) {
            "Running"  { $taskColor = "Green" }
            "Ready"    { $taskColor = "Cyan" }
            "Queued"   { $taskColor = "Yellow" }
            "Disabled" { $taskColor = "Red" }
            default    { $taskColor = "Yellow" }
        }

        Write-Host ("Scheduled task: Present (" + $taskState + ")") -ForegroundColor $taskColor
    } catch {
        Write-Host "Scheduled task: Not found" -ForegroundColor Red
    }

    if ($script:IsInteractive) {
        Write-Host ""
        Write-Host "Press Enter to close..." -ForegroundColor DarkGray
        [void][Console]::ReadLine()
    }
}

function Start-MonitorLoop {
    $mutex = Enter-SingleInstanceLock
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

        Write-Log "Windows Auto Hotspot monitor started." "INFO"
        Write-Log "Interval: $script:CheckIntervalSec sec | UpStable: $script:UpStableChecks | DownStable: $script:DownStableChecks" "DEBUG"
        if ($script:AdapterName) { Write-Log "Adapter filter: $script:AdapterName" "DEBUG" }

        $upCount = 0
        $downCount = 0
        $lastWanted = ""
        $cooldownUntil = Get-Date

        while ($true) {
            try {
                if (Test-AutomationDisabled) {
                    if ($script:ForceOffWhenDisabled) { $null = Set-HotspotState "Off" 6 }
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

                        $ok = Set-HotspotState "On" 12
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

                        $ok = Set-HotspotState "Off" 8
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
    Start-TaskNow

    if ($script:ForceOffWhenDisabled) {
        $null = Set-HotspotState "Off" 8
    }

    Write-Log "Disable requested. Monitor will keep hotspot OFF while disabled." "DEBUG"
}

function Enable-Automation {
    Set-DisabledFlag $false
    Start-TaskNow
    Set-DesiredHotspotStateNow
    Write-Log "Enable requested. State applied immediately." "DEBUG"
}

function Invoke-AutomationToggle {
    if (Test-AutomationDisabled) {
        Enable-Automation
    } else {
        Disable-Automation
    }
}

function Show-Usage {
    Write-Host "Usage:" -ForegroundColor Cyan
    Write-Host "  -Install       (needs Admin, clean reinstall)" -ForegroundColor Gray
    Write-Host "  -Uninstall     (needs Admin)" -ForegroundColor Gray
    Write-Host "  -Status" -ForegroundColor Gray
    Write-Host "  -Enable" -ForegroundColor Gray
    Write-Host "  -Disable" -ForegroundColor Gray
    Write-Host "  -Toggle" -ForegroundColor Gray
    Write-Host "  -OpenLog" -ForegroundColor Gray
    Write-Host "  -Run" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Cyan
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Install" -ForegroundColor Gray
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Toggle" -ForegroundColor Gray
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Status" -ForegroundColor Gray
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Run -Quiet -NoDelay" -ForegroundColor Gray
}

switch ($PSCmdlet.ParameterSetName) {
    "Install"   { Install-App; break }
    "Uninstall" { Uninstall-App; break }
    "Status"    { Show-StatusInfo; break }
    "Enable"    { Enable-Automation; break }
    "Disable"   { Disable-Automation; break }
    "Toggle"    { Invoke-AutomationToggle; break }
    "OpenLog"   { Show-LogFile; break }
    "Run"       { Start-MonitorLoop; break }
    default     { Show-Usage; break }
}
