# SPDX-FileCopyrightText: Copyright (c) 2024-2026 Luiz Bizzio
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

function Log-Message {
    param ($message, $color)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$timestamp - $message" -ForegroundColor $color
}

function Await-Operation {
    param ($asyncOperation)
    while ($asyncOperation.Status -eq "Started") {
        Start-Sleep -Milliseconds 100
    }
    return $asyncOperation
}

Log-Message "Starting Windows Auto Hotspot... Let's get your devices connected!" "Cyan"
Start-Sleep -Seconds 2

$checkInterval = 10
$lastStatus = ""

while ($true) {
    $ethernetAdapter = Get-NetAdapter | Where-Object { $_.MediaType -eq "802.3" -and $_.Status -eq "Up" }
    
    if ($ethernetAdapter) {
        if ($lastStatus -ne "EthernetConnected") {
            Log-Message "Ethernet detected! Adapter name: $($ethernetAdapter.Name)" "Green"
            $lastStatus = "EthernetConnected"
        }

        $connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()

        if ($connectionProfile -ne $null) {
            $tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)

            if ($tetheringManager.TetheringOperationalState -eq "Off") {
                Log-Message "Activating Hotspot..." "Yellow"
                $startOperation = $tetheringManager.StartTetheringAsync()
                Await-Operation $startOperation
                Log-Message "Hotspot is now active! Your devices can connect!" "Green"
            }
        }
    } else {
        if ($lastStatus -ne "EthernetDisconnected") {
            Log-Message "No Ethernet connection detected." "Red"
            $lastStatus = "EthernetDisconnected"
        }
    }

    Start-Sleep -Seconds $checkInterval
}

