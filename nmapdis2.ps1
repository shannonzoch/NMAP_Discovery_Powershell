<#
.SYNOPSIS
    Automates a three-phased Nmap scan against a target subnet for efficient and thorough artifact collection.

.DESCRIPTION
    This script streamlines network scanning by breaking the process into three phases:
    1. A fast TCP SYN scan across all 65,535 ports on all hosts in the subnet to identify open TCP ports.
    2. A scan for the most common UDP ports on all hosts to identify open UDP services.
    3. A detailed service version detection (-sV) and default script enumeration (-sC) scan targeted
       only at the open ports discovered across the subnet in the first two phases.

    This method is significantly faster and more efficient than a single, all-encompassing Nmap command.
    All scan outputs are saved to a uniquely named folder for easy review using a user-provided base filename.

.PARAMETER Subnet
    The target subnet to scan, in CIDR notation (e.g., 192.168.1.0/24). This is a mandatory parameter.

.PARAMETER BaseFileName
    A descriptive base name for all output files (e.g., my-favorite-switch-vlan2). This is a mandatory parameter.

.PARAMETER TopUdpPorts
    The number of top UDP ports to scan in Phase 2. The default is 200, which covers most common services.

.PARAMETER MinRate
    The minimum packet rate for the initial TCP scan in Phase 1. Higher values are faster but can be less reliable
    on unstable networks or may trigger network security alerts. The default is 1000.

.PARAMETER NmapPath
    The full path to the nmap.exe executable. If not provided, the script assumes 'nmap.exe' is in the system's PATH.

.PARAMETER OutputDirectory
    The base directory where a new folder for scan results will be created. The default is the current directory.

.EXAMPLE
    .\run-phased-nmap-scan.ps1 -Subnet 192.168.1.0/24 -BaseFileName corp-vlan10-scan

    This command scans the 192.168.1.0/24 subnet. A new directory like 'scan_192.168.1.0_24_20251017T091000'
    will be created, containing files like 'corp-vlan10-scan-tcpfast.nmap', 'corp-vlan10-scan-udpinitial.nmap', etc.

.NOTES
    Requires Nmap to be installed on the system. Download from https://nmap.org/download.html
    The script must be run with sufficient privileges to perform raw socket SYN scans (e.g., as an Administrator).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Subnet,

    [Parameter(Mandatory = $true)]
    [string]$BaseFileName,

    [Parameter(Mandatory = $false)]
    [int]$TopUdpPorts = 200,

    [Parameter(Mandatory = $false)]
    [int]$MinRate = 1000,

    [Parameter(Mandatory = $false)]
    [string]$NmapPath = "nmap",

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = "."
)

# --- PRE-FLIGHT CHECKS ---
Write-Verbose "Starting pre-flight checks."

# Verify Nmap is accessible
try {
    Get-Command $NmapPath -ErrorAction Stop | Out-Null
    Write-Verbose "Nmap executable found at '$NmapPath'."
}
catch {
    Write-Error "Nmap not found. Please ensure Nmap is installed and in your system's PATH, or specify the path using the -NmapPath parameter."
    return
}

# --- SETUP ---
# Sanitize subnet name for use in file paths
$sanitizedSubnet = $Subnet -replace '[^a-zA-Z0-9.-]', '_'
$timestamp = Get-Date -Format "yyyyMMddTHHmmss"
$sessionName = "scan_${sanitizedSubnet}_${timestamp}"
$sessionPath = Join-Path -Path $OutputDirectory -ChildPath $sessionName

# Create a dedicated directory for this scan session's output
try {
    if (-not (Test-Path -Path $sessionPath)) {
        New-Item -Path $sessionPath -ItemType Directory -ErrorAction Stop | Out-Null
        Write-Host "[+] Created output directory: $sessionPath" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to create output directory '$sessionPath'. Please check permissions."
    return
}


# --- FUNCTION TO PARSE NMAP GREPABLE OUTPUT ---
function Parse-NmapGrepableOutput {
    param(
        [string]$FilePath,
        [string]$Protocol
    )
    
    if (-not (Test-Path $FilePath)) {
        Write-Warning "Grepable output file not found: $FilePath"
        return @()
    }

    $openPorts = [System.Collections.Generic.List[string]]::new()
    $content = Get-Content -Path $FilePath
    
    # Regex to find port number and status, e.g., "80/open/tcp" or "53/open|filtered/udp"
    $regex = "(\d+)\/open.*?\/${Protocol}"

    # In a multi-host scan, each host with open ports will have a "Ports:" section
    foreach ($line in $content) {
        if ($line -match "Ports:") {
            $matches = [regex]::Matches($line, $regex)
            foreach ($match in $matches) {
                if (-not $openPorts.Contains($match.Groups[1].Value)) {
                    $openPorts.Add($match.Groups[1].Value)
                }
            }
        }
    }
    
    return $openPorts
}

# --- EXECUTION ---

# --- PHASE 1: Fast TCP Port Scan ---
Write-Host "`n[PHASE 1] Starting fast TCP scan for all ports on subnet $Subnet..." -ForegroundColor Cyan
$tcpOutputFileBase = Join-Path -Path $sessionPath -ChildPath "$($BaseFileName)-tcpfast"
$nmapArgsTcp = "-sS -p- --min-rate $MinRate -T4 -oA `"$tcpOutputFileBase`" $Subnet"
Write-Verbose "Executing: $NmapPath $nmapArgsTcp"
Invoke-Expression "$NmapPath $nmapArgsTcp"

$openTcpPorts = Parse-NmapGrepableOutput -FilePath "$($tcpOutputFileBase).gnmap" -Protocol "tcp"
if ($openTcpPorts.Count -gt 0) {
    Write-Host "[+] Found $($openTcpPorts.Count) unique open TCP port(s) across the subnet: $($openTcpPorts -join ', ')" -ForegroundColor Green
}
else {
    Write-Host "[-] No open TCP ports found on the subnet." -ForegroundColor Yellow
}


# --- PHASE 2: Common UDP Port Scan ---
Write-Host "`n[PHASE 2] Starting scan for top $TopUdpPorts UDP ports on subnet $Subnet..." -ForegroundColor Cyan
$udpOutputFileBase = Join-Path -Path $sessionPath -ChildPath "$($BaseFileName)-udpinitial"
$nmapArgsUdp = "-sU --top-ports $TopUdpPorts -T4 -oA `"$udpOutputFileBase`" $Subnet"
Write-Verbose "Executing: $NmapPath $nmapArgsUdp"
Invoke-Expression "$NmapPath $nmapArgsUdp"

$openUdpPorts = Parse-NmapGrepableOutput -FilePath "$($udpOutputFileBase).gnmap" -Protocol "udp"
if ($openUdpPorts.Count -gt 0) {
    Write-Host "[+] Found $($openUdpPorts.Count) unique open UDP port(s) across the subnet: $($openUdpPorts -join ', ')" -ForegroundColor Green
}
else {
    Write-Host "[-] No open UDP ports found on the subnet." -ForegroundColor Yellow
}


# --- PHASE 3: Detailed Service Scan on Discovered Ports ---
if ($openTcpPorts.Count -eq 0 -and $openUdpPorts.Count -eq 0) {
    Write-Host "`n[INFO] No open ports were discovered in Phase 1 or 2. Skipping detailed scan." -ForegroundColor Yellow
    Write-Host "Scan session complete. All logs are in: $sessionPath"
    return
}

Write-Host "`n[PHASE 3] Starting detailed service scan on discovered open ports across $Subnet..." -ForegroundColor Cyan
$finalOutputFileBase = Join-Path -Path $sessionPath -ChildPath "$($BaseFileName)-combined"

# Dynamically build the port string for the final scan
$portStringParts = [System.Collections.Generic.List[string]]::new()
if ($openTcpPorts.Count -gt 0) {
    $portStringParts.Add("T:$($openTcpPorts -join ',')")
}
if ($openUdpPorts.Count -gt 0) {
    $portStringParts.Add("U:$($openUdpPorts -join ',')")
}
$finalPortString = $portStringParts -join ','

$nmapArgsFinal = "-sV -sC -p $finalPortString -oA `"$finalOutputFileBase`" $Subnet"
Write-Verbose "Executing: $NmapPath $nmapArgsFinal"
Invoke-Expression "$NmapPath $nmapArgsFinal"


# --- COMPLETION ---
Write-Host "`n[COMPLETE] Scan session finished." -ForegroundColor Green
Write-Host "Final, detailed scan reports have been saved to the '$sessionPath' directory."
Write-Host "Files created: $($finalOutputFileBase).nmap, .xml, .gnmap"

