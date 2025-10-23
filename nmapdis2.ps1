<#
.SYNOPSIS
    Automates a three-phased Nmap scan against a target subnet or a list of hosts from a file.

.DESCRIPTION
    This script streamlines network scanning by breaking the process into three phases:
    1. A fast TCP SYN scan across all 65,535 ports on all targets to identify open TCP ports.
    2. A scan for the most common UDP ports on all targets to identify open or open|filtered UDP services.
    3. A detailed service version detection (-sV) and default script enumeration (-sC) scan targeted
       only at the open ports discovered across the targets in the first two phases.

    The script requires either a -Subnet (e.g., 192.168.1.0/24) or an -InputList (e.g., ./my-hosts.txt).

    By default, the script automatically detects and excludes the machine running the scan from the targets.
    All scan outputs are saved to a uniquely named folder for easy review using a user-provided base filename.
    The script will output the total run time upon completion.

.VERSION
    2.2.0

.CHANGES
    [2025-10-23] v2.2.0
    - Updated version number to 2.2.0.

    [2025-10-23] v1.1.0
    - Reworked output directory naming to use [BaseFileName][Date]S[ScanNumber] format (e.g., vlan-scan20251023S001).
    - Added .VERSION and .CHANGES log to the script header.

    [2025-10-22] v1.0.1
    - Fixed regex in Parse-NmapGrepableOutput to correctly find 'open|filtered' UDP ports.

.PARAMETER Subnet
    The target subnet to scan, in CIDR notation (e.g., 192.168.1.0/24). This is a mandatory parameter
    in the 'SubnetScan' parameter set. Cannot be used with -InputList.

.PARAMETER InputList
    The path to a file containing a list of target hosts (one per line). This is a mandatory parameter
    in the 'ListScan' parameter set. Cannot be used with -Subnet.

.PARAMETER BaseFileName
    A descriptive base name for all output files (e.g., my-favorite-switch-vlan2). This is a mandatory parameter.

.PARAMETER IncludeScanner
    If specified, the script will NOT exclude the local scanning machine from the Nmap scans. The default
    behavior is to always exclude the scanner.

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

    This command scans the 192.168.1.0/24 subnet and automatically excludes the scanning machine.
    A new directory will be created, containing files like 'corp-vlan10-scan-tcpfast.nmap', etc.

.EXAMPLE
    .\run-phased-nmap-scan.ps1 -InputList C:\scans\server-list.txt -BaseFileName critical-servers-scan

    This command scans only the hosts specified in the 'server-list.txt' file and saves the results
    with the base name 'critical-servers-scan'.

.NOTES
    Requires Nmap to be installed on the system. Download from https://nmap.org/download.html
    The script must be run with sufficient privileges to perform raw socket SYN scans (e.g., as an Administrator).
#>
[CmdletBinding(DefaultParameterSetName = "SubnetScan")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "SubnetScan")]
    [string]$Subnet,

    [Parameter(Mandatory = $true, ParameterSetName = "ListScan")]
    [ValidateScript({
        if (-not (Test-Path -Path $_ -PathType Leaf)) {
            throw "Input file not found: $_"
        }
        return $true
    })]
    [string]$InputList,

    [Parameter(Mandatory = $true)]
    [string]$BaseFileName,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeScanner,

    [Parameter(Mandatory = $false)]
    [int]$TopUdpPorts = 200,

    [Parameter(Mandatory = $false)]
    [int]$MinRate = 1000,

    [Parameter(Mandatory = $false)]
    [string]$NmapPath = "nmap",

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = "."
)

# Start timer for total run time calculation
$startTime = Get-Date

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
$targetArgument = ""
$sessionNameIdentifier = ""

if ($PSCmdlet.ParameterSetName -eq "SubnetScan") {
    $targetArgument = $Subnet
    # Sanitize subnet name for use in file paths
    $sessionNameIdentifier = $Subnet -replace '[^a-zA-Z0-9.-]', '_'
    Write-Verbose "Scan target type: Subnet ($Subnet)"
}
elseif ($PSCmdlet.ParameterSetName -eq "ListScan") {
    $targetArgument = "-iL `"$InputList`""
    # Use a sanitized version of the input file name for the directory
    $sessionNameIdentifier = (Get-Item $InputList).BaseName -replace '[^a-zA-Z0-9.-]', '_'
    Write-Verbose "Scan target type: Input List ($InputList)"
}

# New folder naming logic: [BaseFileName][Date]S[ScanNumber]
$dateStamp = Get-Date -Format "yyyyMMdd"
$searchPattern = "$($BaseFileName)$($dateStamp)S*"

# Find existing scan folders for today with the same base name
$existingScans = Get-ChildItem -Path $OutputDirectory -Directory -Filter $searchPattern -ErrorAction SilentlyContinue

$maxScanNum = 0
if ($existingScans) {
    foreach ($scanFolder in $existingScans) {
        # Match the S001, S002, etc. part
        $match = [regex]::Match($scanFolder.Name, "$($BaseFileName)$($dateStamp)S(\d{3})$")
        if ($match.Success) {
            $currentScanNum = [int]$match.Groups[1].Value
            if ($currentScanNum -gt $maxScanNum) {
                $maxScanNum = $currentScanNum
            }
        }
    }
}

$newScanNum = $maxScanNum + 1
$newScanNumString = "{0:D3}" -f $newScanNum # Format as 3 digits (001, 002, etc.)

$sessionName = "$($BaseFileName)$($dateStamp)S$($newScanNumString)"
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

# Determine if the scanner's own IP should be excluded (default behavior)
$excludeArgument = ""
if (-not $IncludeScanner.IsPresent) {
    Write-Verbose "Attempting to find local IP addresses to exclude from the scan (default behavior)."
    try {
        # Get all non-loopback, preferred IPv4 addresses for the local machine
        $localIpAddresses = Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred | Where-Object { $_.InterfaceAlias -notlike "Loopback*" } | Select-Object -ExpandProperty IPAddress
        
        if ($localIpAddresses) {
            $excludeList = $localIpAddresses -join ','
            $excludeArgument = "--exclude $excludeList"
            Write-Host "[+] Excluding scanner's IP(s) from scan: $excludeList (Use -IncludeScanner to override)" -ForegroundColor Green
        } else {
            Write-Warning "Could not determine a local IP address to exclude."
        }
    } catch {
        Write-Warning "An error occurred while trying to determine the local IP address: $_"
    }
} else {
    Write-Host "[+] The -IncludeScanner flag was specified. The local machine will be included in the scan." -ForegroundColor Yellow
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
    
    # Regex to find port number and status.
    # This now correctly captures "open" (for TCP) and "open|filtered" (common for UDP)
    $regex = "(\d+)\/(open\|filtered|open).*?\/${Protocol}"

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
Write-Host "`n[PHASE 1] Starting fast TCP scan for all ports on targets: $targetArgument" -ForegroundColor Cyan
$tcpOutputFileBase = Join-Path -Path $sessionPath -ChildPath "$($BaseFileName)-tcpfast"
$nmapArgsTcp = "-sS -p- --min-rate $MinRate -T4 $excludeArgument -oA `"$tcpOutputFileBase`" $targetArgument"
Write-Verbose "Executing: $NmapPath $nmapArgsTcp"
Invoke-Expression "$NmapPath $nmapArgsTcp"

$openTcpPorts = Parse-NmapGrepableOutput -FilePath "$($tcpOutputFileBase).gnmap" -Protocol "tcp"
if ($openTcpPorts.Count -gt 0) {
    Write-Host "[+] Found $($openTcpPorts.Count) unique open TCP port(s) across all targets: $($openTcpPorts -join ', ')" -ForegroundColor Green
}
else {
    Write-Host "[-] No open TCP ports found on the targets." -ForegroundColor Yellow
}


# --- PHASE 2: Common UDP Port Scan ---
Write-Host "`n[PHASE 2] Starting scan for top $TopUdpPorts UDP ports on targets: $targetArgument" -ForegroundColor Cyan
$udpOutputFileBase = Join-Path -Path $sessionPath -ChildPath "$($BaseFileName)-udpinitial"
$nmapArgsUdp = "-sU --top-ports $TopUdpPorts -T4 $excludeArgument -oA `"$udpOutputFileBase`" $targetArgument"
Write-Verbose "Executing: $NmapPath $nmapArgsUdp"
Invoke-Expression "$NmapPath $nmapArgsUdim"

$openUdpPorts = Parse-NmapGrepableOutput -FilePath "$($udpOutputFileBase).gnmap" -Protocol "udp"
if ($openUdpPorts.Count -gt 0) {
    Write-Host "[+] Found $($openUdpPorts.Count) unique open UDP port(s) across all targets: $($openUdpPorts -join ', ')" -ForegroundColor Green
}
else {
    Write-Host "[-] No open UDP ports found on the targets." -ForegroundColor Yellow
}


# --- PHASE 3: Detailed Service Scan on Discovered Ports ---
if ($openTcpPorts.Count -eq 0 -and $openUdpPorts.Count -eq 0) {
    Write-Host "`n[INFO] No open ports were discovered in Phase 1 or 2. Skipping detailed scan." -ForegroundColor Yellow
    Write-Host "Scan session complete. All logs are in: $sessionPath"
    # Even if we skip phase 3, we still need to calculate and show the total run time.
}
else {
    Write-Host "`n[PHASE 3] Starting detailed service scan on discovered open ports across targets: $targetArgument" -ForegroundColor Cyan
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
    
    $nmapArgsFinal = "-sV -sC -p $finalPortString $excludeArgument -oA `"$finalOutputFileBase`" $targetArgument"
    Write-Verbose "Executing: $NmapPath $nmapArgsFinal"
    Invoke-Expression "$NmapPath $nmapArgsFinal"
}


# --- COMPLETION ---
Write-Host "`n[COMPLETE] Scan session finished." -ForegroundColor Green
Write-Host "All scan reports have been saved to the '$sessionPath' directory."

# Calculate and display total run time
$endTime = Get-Date
$runTime = $endTime - $startTime
$runTimeString = "{0:D2}h:{1:D2}m:{2:D2}s" -f $runTime.Hours, $runTime.Minutes, $runTime.Seconds
Write-Host "Total script run time: $runTimeString" -ForegroundColor Green
