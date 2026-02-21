[CmdletBinding(DefaultParameterSetName = "Help")]
param(
    [Parameter(ParameterSetName = "Install", Mandatory = $true)]
    [switch]$Install,

    [Parameter(ParameterSetName = "Uninstall", Mandatory = $true)]
    [switch]$Uninstall,

    [Parameter(ParameterSetName = "Enable", Mandatory = $true)]
    [switch]$Enable,

    [Parameter(ParameterSetName = "Disable", Mandatory = $true)]
    [switch]$Disable,

    [Parameter(ParameterSetName = "Toggle", Mandatory = $true)]
    [switch]$Toggle,

    [Parameter(ParameterSetName = "Repair", Mandatory = $true)]
    [switch]$Repair,

    [Parameter(ParameterSetName = "Update", Mandatory = $true)]
    [switch]$Update,

    [Parameter(ParameterSetName = "Run", Mandatory = $true)]
    [switch]$Run,

    [Parameter(ParameterSetName = "Status", Mandatory = $true)]
    [switch]$Status,

    [string]$TaskName = "WindowsAutoHotspot",
    [string]$InstallDir = "$env:ProgramData\WindowsAutoHotspot",
    [string]$AdapterName,
    [int]$CheckIntervalSec = 5,
    [int]$UpStableChecks = 2,
    [int]$DownStableChecks = 2,
    [switch]$Quiet,
    [switch]$NoDelay,
    [string]$SourceUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:StateDir = Join-Path $env:LOCALAPPDATA "WindowsAutoHotspot"
$script:DisableFlagPath = Join-Path $script:StateDir "hotspot.disabled"
$script:LogPath = Join-Path $script:StateDir "windows-auto-hotspot.log"
$script:InstalledScriptPath = Join-Path $InstallDir "windows-auto-hotspot.ps1"

$script:PublicDesktopToggleShortcut = Join-Path (Join-Path $env:Public "Desktop") "Windows Auto Hotspot Toggle.lnk"
$script:StartMenuFolder = Join-Path (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs") "Windows Auto Hotspot"
$script:StartMenuToggleShortcut = Join-Path $script:StartMenuFolder "Windows Auto Hotspot Toggle.lnk"

$script:PowerShellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

$script:IconEnabledCandidates = @(
    (Join-Path $env:SystemRoot "System32\netshell.dll") + ",86",
    (Join-Path $env:SystemRoot "System32\imageres.dll") + ",159",
    (Join-Path $env:SystemRoot "System32\shell32.dll") + ",44"
)

$script:IconDisabledCandidates = @(
    (Join-Path $env:SystemRoot "System32\netshell.dll") + ",85",
    (Join-Path $env:SystemRoot "System32\imageres.dll") + ",160",
    (Join-Path $env:SystemRoot "System32\shell32.dll") + ",132"
)

function Ensure-Path {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Resolve-LogPath {
    Ensure-Path (Split-Path -Parent $script:LogPath)
    if (-not (Test-Path -LiteralPath $script:LogPath)) {
        New-Item -ItemType File -Path $script:LogPath -Force | Out-Null
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

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","OK","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts [$Level] $Message"

    try {
        Resolve-LogPath
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

function Get-FirstValidIcon {
    param([string[]]$Candidates)

    foreach ($c in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $parts = $c.Split(",", 2)
        if ($parts.Count -lt 1) { continue }
        $dll = $parts[0]
        if (Test-Path -LiteralPath $dll) { return $c }
    }

    return (Join-Path $env:SystemRoot "System32\shell32.dll") + ",44"
}

function Get-ToggleIcon {
    param([bool]$Enabled)

    if ($Enabled) {
        return (Get-FirstValidIcon $script:IconEnabledCandidates)
    }

    return (Get-FirstValidIcon $script:IconDisabledCandidates)
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

    Update-ToggleShortcuts
}

function New-OrUpdate-Shortcut {
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

function Remove-ShortcutIfExists {
    param([string]$Path)
    try {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Update-ToggleShortcuts {
    $installedPath = $script:InstalledScriptPath
    if (-not (Test-Path -LiteralPath $installedPath)) { return }

    $enabled = -not (Is-AutomationDisabled)
    $icon = Get-ToggleIcon $enabled
    $stateText = if ($enabled) { "Enabled" } else { "Disabled" }

    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$installedPath`" -Toggle"

    New-OrUpdate-Shortcut -LinkPath $script:PublicDesktopToggleShortcut -TargetPath $script:PowerShellExe -Arguments $args -WorkingDirectory $env:WINDIR -IconLocation $icon -Description "Toggle Windows Auto Hotspot automation ($stateText)"
    New-OrUpdate-Shortcut -LinkPath $script:StartMenuToggleShortcut -TargetPath $script:PowerShellExe -Arguments $args -WorkingDirectory $env:WINDIR -IconLocation $icon -Description "Toggle Windows Auto Hotspot automation ($stateText)"
}

function Create-ToggleShortcuts {
    Ensure-Path $script:StartMenuFolder
    Update-ToggleShortcuts
}

function Remove-Shortcuts {
    Remove-ShortcutIfExists $script:PublicDesktopToggleShortcut
    Remove-ShortcutIfExists $script:StartMenuToggleShortcut

    try {
        if (Test-Path -LiteralPath $script:StartMenuFolder) {
            $remaining = @(Get-ChildItem -LiteralPath $script:StartMenuFolder -Force -ErrorAction SilentlyContinue)
            if ($remaining.Length -eq 0) {
                Remove-Item -LiteralPath $script:StartMenuFolder -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
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
            $cmd = $p.CommandLine
            if ($cmd -and $cmd -like "*$ScriptPath*" -and $cmd -like "* -Run*") {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}

function Get-EthernetState {
    $all = @()
    $adapters = @()

    try {
        $all = @(Get-NetAdapter -ErrorAction SilentlyContinue)
        if ($script:AdapterName) {
            $all = @($all | Where-Object { $_.Name -eq $script:AdapterName })
        }

        $adapters = @($all | Where-Object {
            $_.Status -eq "Up" -and (
                $_.MediaType -eq "802.3" -or
                $_.InterfaceDescription -match "Ethernet"
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
        IsUp = ($adapters.Length -gt 0)
        Names = $names
    }
}

function Test-WifiAdapterPresent {
    try {
        $all = @(Get-NetAdapter -ErrorAction SilentlyContinue)
        $wifi = @($all | Where-Object {
            $_.Status -ne "Disabled" -and (
                $_.InterfaceDescription -match "Wi-?Fi|Wireless|802\.11" -or
                $_.Name -match "Wi-?Fi|WLAN" -or
                $_.NdisPhysicalMedium -eq 9
            )
        })
        return ($wifi.Length -gt 0)
    } catch {
        return $false
    }
}

function Get-ConnectionProfileSafe {
    try {
        $ni = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]

        $p = $ni::GetInternetConnectionProfile()
        if ($null -ne $p) { return $p }

        $profiles = @($ni::GetConnectionProfiles())
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

function Get-TetheringCapabilityText {
    param($Mgr)

    try {
        if ($null -eq $Mgr) { return "Unavailable" }
        $cap = $Mgr.TetheringCapability
        if ($null -eq $cap) { return "Unknown" }
        return $cap.ToString()
    } catch {
        return "Unknown"
    }
}

function Wait-AsyncOp {
    param(
        $Op,
        [int]$TimeoutSec = 30
    )

    $sw = [Diagnostics.Stopwatch]::StartNew()

    while ($true) {
        $status = $null
        try { $status = $Op.Status.ToString() } catch { $status = "Unknown" }

        if ($status -ne "Started") { break }
        if ($sw.Elapsed.TotalSeconds -ge $TimeoutSec) { break }

        Start-Sleep -Milliseconds 100
    }

    $final = "Unknown"
    try { $final = $Op.Status.ToString() } catch {}

    if ($final -eq "Completed") {
        try { $null = $Op.GetResults() } catch {}
        return $true
    }

    if ($final -eq "Error") {
        try {
            Write-Log ("Async error. Code: " + $Op.ErrorCode) "ERROR"
        } catch {
            Write-Log "Async error." "ERROR"
        }
        return $false
    }

    Write-Log "Async timeout." "ERROR"
    return $false
}

function Ensure-Hotspot {
    param(
        [ValidateSet("On","Off")]
        [string]$Desired
    )

    $mgr = Get-TetheringManagerSafe
    if ($null -eq $mgr) {
        Write-Log "Hotspot manager not available." "ERROR"
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
    }

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

function Build-TaskArgs {
    param([string]$InstalledScriptPath)

    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", "`"$InstalledScriptPath`"",
        "-Run",
        "-Quiet",
        "-CheckIntervalSec", $CheckIntervalSec,
        "-UpStableChecks", $UpStableChecks,
        "-DownStableChecks", $DownStableChecks
    )

    if ($script:AdapterName) {
        $args += @("-AdapterName", "`"$script:AdapterName`"")
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

    $state = "Unknown"
    try {
        Start-ScheduledTask -TaskName $TaskName
        Start-Sleep -Milliseconds 700
        $state = (Get-ScheduledTask -TaskName $TaskName).State
    } catch {
        $p = Build-TaskArgs $InstalledScriptPath
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList ($p -join " ") -WindowStyle Hidden
        } catch {}
        try { $state = (Get-ScheduledTask -TaskName $TaskName).State } catch {}
    }

    return $state
}

function Install-App {
    if (-not (Test-Admin)) {
        Write-Host "Run as Administrator to install." -ForegroundColor Red
        exit 1
    }

    Ensure-Path $InstallDir
    Ensure-Path $script:StateDir
    Resolve-LogPath

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
    Create-ToggleShortcuts

    Write-Host ("Task state: " + $st) -ForegroundColor Cyan
    Write-Host ("Installed. Task created: " + $TaskName) -ForegroundColor Green
    Write-Host ("Logs: " + $script:LogPath) -ForegroundColor Cyan
    Write-Host ("Desktop shortcut: " + $script:PublicDesktopToggleShortcut) -ForegroundColor Gray
    Write-Host ("Start Menu shortcut: " + $script:StartMenuToggleShortcut) -ForegroundColor Gray
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

    Ensure-Path $script:StateDir
    Resolve-LogPath

    $st = Register-OrRepairTask $script:InstalledScriptPath
    Create-ToggleShortcuts

    Write-Host ("Task state: " + $st) -ForegroundColor Cyan
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
        if ($content -match "WindowsAutoHotspot" -or $content -match "Windows Auto Hotspot") {
            if ($content -match "Run-Monitor" -and $content -match "Toggle") {
                $ok = $true
            }
        }
    } catch {}

    if (-not $ok) {
        try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch {}
        Write-Host "Downloaded file does not look valid. Aborting." -ForegroundColor Red
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

function Disable-Automation {
    Ensure-Path $script:StateDir
    Resolve-LogPath
    Set-DisabledFlag $true
    $null = Ensure-Hotspot "Off"
    Write-Host "Automation disabled." -ForegroundColor Yellow
}

function Enable-Automation {
    Ensure-Path $script:StateDir
    Resolve-LogPath
    Set-DisabledFlag $false
    Write-Host "Automation enabled." -ForegroundColor Green
}

function Toggle-Automation {
    Ensure-Path $script:StateDir
    Resolve-LogPath

    if (Is-AutomationDisabled) {
        Set-DisabledFlag $false
        Write-Host "Automation enabled." -ForegroundColor Green
    } else {
        Set-DisabledFlag $true
        $null = Ensure-Hotspot "Off"
        Write-Host "Automation disabled and hotspot turned off." -ForegroundColor Yellow
    }
}

function Show-Status {
    Ensure-Path $script:StateDir
    Resolve-LogPath

    $eth = Get-EthernetState
    $disabled = Is-AutomationDisabled
    $wifi = Test-WifiAdapterPresent
    $mgr = Get-TetheringManagerSafe

    Write-Host ("Automation: " + ($(if ($disabled) { "Disabled" } else { "Enabled" }))) -ForegroundColor $(if ($disabled) { "Yellow" } else { "Green" })
    Write-Host ("Wi-Fi adapter present: " + $wifi) -ForegroundColor Cyan
    Write-Host ("Ethernet up: " + $eth.IsUp) -ForegroundColor Cyan

    if ($eth.Names -and $eth.Names.Length -gt 0) {
        Write-Host ("Ethernet adapters: " + ($eth.Names -join ", ")) -ForegroundColor Cyan
    }

    if ($null -eq $mgr) {
        Write-Host "Hotspot manager: Unavailable" -ForegroundColor Yellow
    } else {
        $cap = Get-TetheringCapabilityText $mgr
        $hst = "Unknown"
        try { $hst = $mgr.TetheringOperationalState.ToString() } catch {}
        Write-Host ("Hotspot: " + $hst + " | Capability: " + $cap) -ForegroundColor Green
    }

    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Host ("Task: Present (" + $t.State + ")") -ForegroundColor Green
    } catch {
        Write-Host "Task: Not found" -ForegroundColor Red
    }

    Write-Host ("Log file: " + $script:LogPath) -ForegroundColor Gray
    Write-Host ("Desktop shortcut: " + $script:PublicDesktopToggleShortcut) -ForegroundColor Gray
}

function Run-Monitor {
    $mutex = Acquire-SingleInstance
    if ($null -eq $mutex) { return }

    try {
        Ensure-Path $script:StateDir
        Resolve-LogPath

        Write-Log "Windows Auto Hotspot monitor started." "INFO"
        Write-Log ("Interval: " + $CheckIntervalSec + " sec | UpStable: " + $UpStableChecks + " | DownStable: " + $DownStableChecks) "DEBUG"
        if ($script:AdapterName) { Write-Log ("Adapter filter: " + $script:AdapterName) "DEBUG" }

        $upCount = 0
        $downCount = 0
        $lastWanted = ""
        $lastPrecheckIssue = ""

        while ($true) {
            try {
                if (Is-AutomationDisabled) {
                    if ($lastPrecheckIssue -ne "disabled") {
                        Write-Log "Automation is disabled. Monitor will not force hotspot ON." "WARN"
                        $lastPrecheckIssue = "disabled"
                    }

                    $null = Ensure-Hotspot "Off"
                    Start-Sleep -Seconds $CheckIntervalSec
                    continue
                }

                if (-not (Test-WifiAdapterPresent)) {
                    if ($lastPrecheckIssue -ne "no_wifi") {
                        Write-Log "No Wi-Fi adapter detected. Waiting..." "ERROR"
                        $lastPrecheckIssue = "no_wifi"
                    }
                    Start-Sleep -Seconds ([Math]::Max(5, $CheckIntervalSec))
                    continue
                }

                $mgr = Get-TetheringManagerSafe
                if ($null -eq $mgr) {
                    if ($lastPrecheckIssue -ne "no_mgr") {
                        Write-Log "Hotspot manager not available. Waiting..." "ERROR"
                        $lastPrecheckIssue = "no_mgr"
                    }
                    Start-Sleep -Seconds ([Math]::Max(5, $CheckIntervalSec))
                    continue
                }

                $cap = Get-TetheringCapabilityText $mgr
                if ($cap -ne "Enabled" -and $cap -ne "Unknown") {
                    if ($lastPrecheckIssue -ne ("cap:" + $cap)) {
                        Write-Log ("Hotspot not available. Capability: " + $cap + ". Waiting...") "ERROR"
                        $lastPrecheckIssue = ("cap:" + $cap)
                    }
                    Start-Sleep -Seconds ([Math]::Max(5, $CheckIntervalSec))
                    continue
                }

                if ($lastPrecheckIssue) {
                    Write-Log "Precheck passed." "OK"
                    $lastPrecheckIssue = ""
                }

                $eth = Get-EthernetState

                if ($eth.IsUp) {
                    $upCount++
                    $downCount = 0

                    if ($upCount -ge $UpStableChecks) {
                        if ($lastWanted -ne "On") {
                            $names = ""
                            if ($eth.Names -and $eth.Names.Length -gt 0) { $names = ($eth.Names -join ", ") }
                            Write-Log ("Ethernet stable ON. " + $names) "OK"
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
            } catch {
                Write-Log ("Monitor error: " + $_.Exception.Message) "ERROR"
            }

            Start-Sleep -Seconds $CheckIntervalSec
        }
    } finally {
        try { $mutex.ReleaseMutex() } catch {}
        try { $mutex.Dispose() } catch {}
    }
}

switch ($PSCmdlet.ParameterSetName) {
    "Install"   { Install-App; break }
    "Uninstall" { Uninstall-App; break }
    "Enable"    { Enable-Automation; break }
    "Disable"   { Disable-Automation; break }
    "Toggle"    { Toggle-Automation; break }
    "Repair"    { Do-Repair; break }
    "Update"    { Do-Update; break }
    "Status"    { Show-Status; break }
    "Run"       { Run-Monitor; break }
    default {
        Write-Host "Usage:" -ForegroundColor Cyan
        Write-Host "  -Install    (needs Admin)" -ForegroundColor Gray
        Write-Host "  -Uninstall  (needs Admin)" -ForegroundColor Gray
        Write-Host "  -Enable" -ForegroundColor Gray
        Write-Host "  -Disable" -ForegroundColor Gray
        Write-Host "  -Toggle" -ForegroundColor Gray
        Write-Host "  -Repair     (needs Admin)" -ForegroundColor Gray
        Write-Host "  -Update -SourceUrl <url> (needs Admin)" -ForegroundColor Gray
        Write-Host "  -Status" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        Write-Host "Examples:" -ForegroundColor Cyan
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Install" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Toggle" -ForegroundColor Gray
        Write-Host "  powershell -ExecutionPolicy Bypass -File .\windows_auto_hotspot.ps1 -Repair" -ForegroundColor Gray
        break
    }
}
