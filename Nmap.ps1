###############################        NMAP   Script    ###########################################
<#
.SYNOPSIS
    A PowerShell script to perform a multi-stage Nmap scan for network discovery and enumeration.

.DESCRIPTION
    This script automates a three-step network scanning process:
    1. Ping scan to find live hosts within a given subnet.
    2. A fast, all-ports scan on live hosts to identify open ports.
    3. A detailed service and script scan on the identified open ports.
    All final results are consolidated into a single set of Nmap output files.

.PARAMETER Subnet
    The target IP address range in CIDR notation (e.g., "192.168.1.0/24").

.PARAMETER Segment
    A descriptive name for the network segment, used in the output filename (e.g., "Core", "DMZ").

.PARAMETER Vlan
    The VLAN number or identifier, used in the output filename (e.g., "101", "Servers").

.EXAMPLE
    .\Start-NmapScan.ps1 -Subnet "10.10.20.0/24" -Segment "Internal" -Vlan "20"
#>
param(
    [Parameter(Mandatory=$true, HelpMessage="Enter the target subnet in CIDR notation, e.g., '10.0.0.0/24'")]
    [string]$Subnet,

    [Parameter(Mandatory=$true, HelpMessage="Enter a name for the network segment, e.g., 'Core'")]
    [string]$Segment,

    [Parameter(Mandatory=$true, HelpMessage="Enter the VLAN number, e.g., '101'")]
    [string]$Vlan
)

# --- Configuration ---
# Define the base name for the final output files
$outputBaseName = "STS_${Segment}_${Vlan}"
# Define names for temporary files used during the script
$liveHostsFile = ".\temp_live_hosts.txt"
$portsFile = ".\temp_hosts_with_ports.csv"

# --- Pre-Scan Cleanup ---
# Remove old output files from a previous run to ensure a fresh report
Write-Host "Checking for and removing old output files..."
if (Test-Path "${outputBaseName}.nmap") { Remove-Item "${outputBaseName}.nmap" }
if (Test-Path "${outputBaseName}.gnmap") { Remove-Item "${outputBaseName}.gnmap" }
if (Test-Path "${outputBaseName}.xml") { Remove-Item "${outputBaseName}.xml" }

# --- Step 1: Find Live Hosts ---
Write-Host "[+] Step 1: Performing ping scan on '$Subnet' to find live hosts..."
nmap -sn $Subnet -oG - | Select-String "Status: Up" | ForEach-Object { ($_ -split ' ')[1] } | Set-Content -Path $liveHostsFile

# Check if any live hosts were found before proceeding
if (-not (Test-Path $liveHostsFile) -or (Get-Content $liveHostsFile).Length -eq 0) {
    Write-Warning "No live hosts found in '$Subnet'. Stopping script."
    return
}
Write-Host "--> Found $((Get-Content $liveHostsFile).Count) live hosts."

# --- Step 2: Find Open Ports on Live Hosts ---
Write-Host "[+] Step 2: Scanning for all open ports on live hosts. This may take a while..."
nmap -p- -T4 --min-rate 1000 --open -iL $liveHostsFile -oG - | Select-String "/open/" | ForEach-Object {
    $ip = ($_ -split ' ')[1]
    $ports = ($_ -split 'Ports: ')[1].Trim() -split ', ' | ForEach-Object { ($_ -split '/')[0] } | Join-String -Separator ','
    [PSCustomObject]@{ IP = $ip; Ports = $ports }
} | Export-Csv -Path $portsFile -NoTypeInformation

# Check if any open ports were found before proceeding
if (-not (Test-Path $portsFile) -or (Get-Content $portsFile).Length -lt 2) {
    Write-Warning "No open ports found on any of the live hosts. Stopping script."
    Remove-Item $liveHostsFile -ErrorAction SilentlyContinue
    return
}
Write-Host "--> Open port scan complete."

# --- Step 3: Detailed Scan on Specific Ports ---
Write-Host "[+] Step 3: Performing detailed service and script scan."
Write-Host "--> Output will be appended to '${outputBaseName}.*'"
$targets = Import-Csv $portsFile
foreach ($target in $targets) {
    Write-Host "    Scanning $($target.IP) on ports $($target.Ports)..."
    nmap -sC -sV -vV --append-output -p $target.Ports $target.IP -oA $outputBaseName
}
Write-Host "--> Detailed scan complete."

# --- Cleanup ---
Write-Host "[+] Cleaning up temporary files..."
Remove-Item $liveHostsFile -ErrorAction SilentlyContinue
Remove-Item $portsFile -ErrorAction SilentlyContinue
Write-Host "[+] Script finished successfully."

###############################        END NMAP  Script    ###########################################
################################################################################################
