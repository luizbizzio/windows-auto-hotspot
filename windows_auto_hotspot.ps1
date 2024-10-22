$connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
$tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)

function Await-Operation {
    param ($asyncOperation)
    while ($asyncOperation.Status -eq "Started") { Start-Sleep -Milliseconds 100 }
    return $asyncOperation
}

while ($true) {
    $ethernet = Get-NetAdapter | Where-Object { $_.MediaType -eq "802.3" -and $_.Status -eq "Up" }

    if ($ethernet) {
        if ($tetheringManager.TetheringOperationalState -eq "Off") {
            $startOperation = $tetheringManager.StartTetheringAsync()
            Await-Operation $startOperation
        }
    } else {
        if ($tetheringManager.TetheringOperationalState -eq "On") {
            $stopOperation = $tetheringManager.StopTetheringAsync()
            Await-Operation $stopOperation
        }
    }
    
    Start-Sleep -Seconds 10
}
