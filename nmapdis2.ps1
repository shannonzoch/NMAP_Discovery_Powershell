<#
.SYNOPSIS
    Automates a three-phased, per-host Nmap scan against a target subnet or a list of hosts from a file.

.DESCRIPTION
    This script streamlines network scanning by breaking the process into three phases:
    1. A fast TCP SYN scan across all 65,535 ports on all targets to identify open TCP ports.
    2. A scan for the most common UDP ports on all targets to identify open or open|filtered UDP services.
    3. A detailed service version detection (-sV) and default script enumeration (-sC) scan targeted
       ONLY at the specific open ports previously discovered on each individual IP address. This per-host
       approach significantly improves efficiency and speed for the most time-intensive phase.

    The script requires either a -Subnet (e.g., 192.168.1.0/24) or an -InputList (e.g., ./my-hosts.txt).

    By default, the script automatically detects and excludes the machine running the scan from the targets.
    All scan outputs are saved to a uniquely named folder using the format [BaseFileName][Date]_[Time]
    for easy review using a user-provided base filename.
    The script will output the total run time upon completion.

.VERSION
    2.3.6

.CHANGES
    [2025-11-10] v2.3.6
    - CRITICAL FIX: Renamed loop variable in XML consolidation (Phase 3) from `$host` to `$node`. The variable `$host` is a
      read-only system variable in PowerShell, which caused a "cannot overwrite variable" error.
    - ROBUSTNESS: Added sanitization for the -BaseFileName parameter to remove invalid file/path characters (e.g., /,\,:)
      which could cause the script to fail when creating the output directory or saving files.
    - BUGFIX: Corrected runtime string format from `{2:DD}s` to `{2:ss}s`.

    [2025-11-05] v2.3.5
    - CRITICAL FIX: Fixed PowerShell string interpolation error: "Variable reference is not valid. ':' was not followed by valid variable character."
      Corrected `$ip:` to `${ip}:` in the Write-Host and Write-Warning lines in Phase 3 to properly delimit the variable name.

    [2025-11-05] v2.3.4
    - CRITICAL FIX: Refactored target argument handling for -Subnet and -InputList. Replaced the unreliable
      `-split ' '` logic with a dedicated array (`$targetArgumentArray`) built during SETUP. This fixes potential
      failures when passing the -iL parameter.
    - LOGIC FIX: Added a guardrail in Phase 3 to check for hosts with no open ports (e.g., if they went offline
      between phases) and skip them to prevent empty Nmap commands.

    [2025-11-05] v2.3.3
    - CRITICAL FIX: Replaced all instances of Invoke-Expression with the array-based call operator (&) and explicit argument arrays. This eliminates complex string quoting issues (like the "not followed by a valid variable name character" error) and drastically improves script robustness against paths/variables containing spaces.

    [2025-11-05] v2.3.2
    - FEATURE: Added generation of a <BaseFileName>-hosts.txt file containing all detected IP addresses after discovery scans (Phase 1 & 2) are complete.

    [2025-11-05] v2.3.1
    - FEATURE/FIX: Implemented robust XML consolidation for Phase 3. The script now parses individual temporary XML files,
      extracts all <host> nodes, and injects them into a single, valid <nmaprun> document, fixing the multi-root XML error.

    [2025-11-05] v2.3.0
    - MAJOR FEATURE/FIX: Rewrote parsing logic to associate discovered open ports with specific IP addresses.
    - PHASE 3 Rework: Replaced the single, subnet-wide final scan with a targeted 'per-host' loop, ensuring -sV and -sC
      scripts only run against ports already found open on that specific IP. This greatly improves efficiency.

    [2025-11-05] v2.2.2
    - FIXED BUG: Ensured the -sU flag is correctly passed to the final combined scan (Phase 3) when UDP ports are present,
      preventing Nmap from ignoring the 'U:' port specifier.

    [2025-11-05] v2.2.1
    - FIXED BUG: Corrected a typo that prevented the UDP scan (Phase 2) from running correctly when parameters were supplied interactively.
    - FEATURE: Updated output directory naming to use [BaseFileName][Date]_[Time] format (e.g., vlan-scan20251105_091530).

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
    A new directory will be created, containing files like 'corp-vlan10-scan20251105_091530/corp-vlan10-scan-tcpfast.nmap', etc.

.EXAMPLE
    .\run-phased-nmap-scan.ps1 -InputList C:\scans\server-list.txt -BaseFileName critical-servers-scan

    This command scans only the hosts specified in the 'server-list.txt' file and saves the.
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

# Sanitize BaseFileName to remove invalid path characters
$invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
$regexInvalidChars = [regex]::Escape($invalidChars)
$BaseFileName = $BaseFileName -replace "[$regexInvalidChars]", '_'
Write-Verbose "Sanitized BaseFileName to: $BaseFileName"

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
$targetArgumentArray = @() # Use an array for Nmap target arguments
$sessionNameIdentifier = ""

if ($PSCmdlet.ParameterSetName -eq "SubnetScan") {
    $targetArgumentArray = @($Subnet)
    # Sanitize subnet name for use in file paths
    $sessionNameIdentifier = $Subnet -replace '[^a-zA-Z0-9.-]', '_'
    Write-Verbose "Scan target type: Subnet ($Subnet)"
}
elseif ($PSCmdlet.ParameterSetName -eq "ListScan") {
    $targetArgumentArray = @("-iL", $InputList)
    # Use a sanitized version of the input file name for the directory
    $sessionNameIdentifier = (Get-Item $InputList).BaseName -replace '[^a-zA-Z0-9.-]', '_'
    Write-Verbose "Scan target type: Input List ($InputList)"
}

# New folder naming logic: [BaseFileName][Date]_[Time]
$dateTimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"

$sessionName = "$($BaseFileName)$($dateTimeStamp)"
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
$excludeArgumentArray = @() # Use an array for the exclude argument
if (-not $IncludeScanner.IsPresent) {
    Write-Verbose "Attempting to find local IP addresses to exclude from the scan (default behavior)."
    try {
        # Get all non-loopback, preferred IPv4 addresses for the local machine
        $localIpAddresses = Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred | Where-Object { $_.InterfaceAlias -notlike "Loopback*" } | Select-Object -ExpandProperty IPAddress
        
        if ($localIpAddresses) {
            $excludeList = $localIpAddresses -join ','
            $excludeArgumentArray = @("--exclude", $excludeList)
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
        return @{}
    }

    # Dictionary to store results: { 'IP_Address' = @{ 'tcp' = @('port1', ...); 'udp' = @('port1', ...) } }
    $openPortsPerIp = @{}
    $content = Get-Content -Path $FilePath
    
    # Regex to find the Host IP address and all relevant ports in the Ports line
    # Matches: IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) and Port: (\d+)\/(open\|filtered|open).*?\/${Protocol}
    $hostRegex = "^Host: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    $portRegex = "(\d+)\/(open\|filtered|open).*?\/${Protocol}"
    
    $currentIP = $null

    foreach ($line in $content) {
        # 1. Capture the Host IP
        if ($line -match $hostRegex) {
            $currentIP = $Matches[1]
            # Initialize the IP entry if it doesn't exist
            if (-not $openPortsPerIp.ContainsKey($currentIP)) {
                $openPortsPerIp[$currentIP] = @{}
                $openPortsPerIp[$currentIP]["tcp"] = [System.Collections.Generic.List[string]]::new()
                $openPortsPerIp[$currentIP]["udp"] = [System.Collections.Generic.List[string]]::new()
            }
        }
        
        # 2. Capture the Ports line
        if ($line -match "Ports:" -and $currentIP -ne $null) {
            $matches = [regex]::Matches($line, $portRegex)
            foreach ($match in $matches) {
                $port = $match.Groups[1].Value
                
                # We need to explicitly check if the port list is for the correct protocol
                if ($line -match "${port}\/(open\|filtered|open).*?\/${Protocol}" -and -not $openPortsPerIp[$currentIP][$Protocol].Contains($port)) {
                     $openPortsPerIp[$currentIP][$Protocol].Add($port)
                }
            }
        }
    }
    
    return $openPortsPerIp
}

# --- EXECUTION ---

# Dictionary to hold final discovered ports per IP, consolidating TCP and UDP
# Structure: { '10.0.0.1' = @{ 'tcp' = @('22', '80'); 'udp' = @('53') } }
$masterTargetPorts = @{}
# Array to hold all <host> XML nodes for final consolidation
$allHostNodes = [System.Collections.ArrayList]::new()


# --- PHASE 1: Fast TCP Port Scan ---
Write-Host "`n[PHASE 1] Starting fast TCP scan for all ports on targets: $($targetArgumentArray -join ' ')" -ForegroundColor Cyan
$tcpOutputFileBase = Join-Path -Path $sessionPath -ChildPath "$($BaseFileName)-tcpfast"

# Build argument array for safe execution
$nmapArgsTcpArray = @("-sS", "-p-", "--min-rate", "$MinRate", "-T4")
if ($excludeArgumentArray.Count -gt 0) { $nmapArgsTcpArray += $excludeArgumentArray }
$nmapArgsTcpArray += @("-oA", $tcpOutputFileBase)
$nmapArgsTcpArray += $targetArgumentArray # Add target(s)

Write-Verbose "Executing: $NmapPath $($nmapArgsTcpArray -join ' ')"
# Execute Nmap using the call operator (&)
& $NmapPath @nmapArgsTcpArray

$tcpPortsPerIp = Parse-NmapGrepableOutput -FilePath "$($tcpOutputFileBase).gnmap" -Protocol "tcp"
$tcpPortCount = 0

foreach ($ip in $tcpPortsPerIp.Keys) {
    $masterTargetPorts[$ip] = @{}
    $masterTargetPorts[$ip]["tcp"] = $tcpPortsPerIp[$ip]["tcp"]
    $masterTargetPorts[$ip]["udp"] = [System.Collections.Generic.List[string]]::new() # Initialize UDP list
    $tcpPortCount += $masterTargetPorts[$ip]["tcp"].Count
}

if ($tcpPortCount -gt 0) {
    Write-Host "[+] Found $tcpPortCount unique open TCP port(s) across $($tcpPortsPerIp.Count) host(s)." -ForegroundColor Green
}
else {
    Write-Host "[-] No open TCP ports found on the targets." -ForegroundColor Yellow
}


# --- PHASE 2: Common UDP Port Scan ---
Write-Host "`n[PHASE 2] Starting scan for top $TopUdpPorts UDP ports on targets: $($targetArgumentArray -join ' ')" -ForegroundColor Cyan
$udpOutputFileBase = Join-Path -Path $sessionPath -ChildPath "$($BaseFileName)-udpinitial"

# Build argument array for safe execution
$nmapArgsUdpArray = @("-sU", "--top-ports", "$TopUdpPorts", "-T4")
if ($excludeArgumentArray.Count -gt 0) { $nmapArgsUdpArray += $excludeArgumentArray }
$nmapArgsUdpArray += @("-oA", $udpOutputFileBase)
$nmapArgsUdpArray += $targetArgumentArray # Add target(s)

Write-Verbose "Executing: $NmapPath $($nmapArgsUdpArray -join ' ')"
# Execute Nmap using the call operator (&)
& $NmapPath @nmapArgsUdpArray

$udpPortsPerIp = Parse-NmapGrepableOutput -FilePath "$($udpOutputFileBase).gnmap" -Protocol "udp"
$udpPortCount = 0

foreach ($ip in $udpPortsPerIp.Keys) {
    # If the IP is new (no open TCP ports), initialize it
    if (-not $masterTargetPorts.ContainsKey($ip)) {
        $masterTargetPorts[$ip] = @{}
        $masterTargetPorts[$ip]["tcp"] = [System.Collections.Generic.List[string]]::new() # Initialize TCP list
    }
    # Add UDP ports
    $masterTargetPorts[$ip]["udp"] = $udpPortsPerIp[$ip]["udp"]
    $udpPortCount += $masterTargetPorts[$ip]["udp"].Count
}

if ($udpPortCount -gt 0) {
    Write-Host "[+] Found $udpPortCount unique open UDP port(s) across $($udpPortsPerIp.Count) host(s)." -ForegroundColor Green
}
else {
    Write-Host "[-] No open UDP ports found on the targets." -ForegroundColor Yellow
}

# --- CREATE HOSTS.TXT FILE ---
$hostsFile = Join-Path -Path $sessionPath -ChildPath "$($BaseFileName)-hosts.txt"
$uniqueIPs = $masterTargetPorts.Keys | Sort-Object

if ($uniqueIPs.Count -gt 0) {
    $uniqueIPs | Out-File -FilePath $hostsFile -Force -Encoding ASCII
    Write-Host "[+] Wrote list of $($uniqueIPs.Count) active hosts to: $hostsFile" -ForegroundColor Green
} else {
    Write-Host "[-] No active hosts detected to write to hosts.txt." -ForegroundColor Yellow
}

$totalTargets = $masterTargetPorts.Count

# --- PHASE 3: Detailed Service Scan on Discovered Ports (Per-Host) ---
if ($totalTargets -eq 0) {
    Write-Host "`n[INFO] No targets with open ports were discovered. Skipping detailed scan." -ForegroundColor Yellow
    Write-Host "Scan session complete. All logs are in: $sessionPath"
}
else {
    Write-Host "`n[PHASE 3] Starting detailed, per-host service scan on $totalTargets discovered targets." -ForegroundColor Cyan
    $finalOutputFileBase = Join-Path -Path $sessionPath -ChildPath "$($BaseFileName)-combined"

    # Define final file paths
    $finalNmapFile = "$($finalOutputFileBase).nmap"
    $finalXmlFile = "$($finalOutputFileBase).xml"
    $finalGrepableFile = "$($finalOutputFileBase).gnmap"
    
    # Initialize the combined text output files
    "" | Out-File -FilePath $finalNmapFile -Force
    "" | Out-File -FilePath $finalGrepableFile -Force
    
    $scanCount = 0
    foreach ($ip in $masterTargetPorts.Keys) {
        $scanCount++
        $tcpPorts = $masterTargetPorts[$ip]["tcp"]
        $udpPorts = $masterTargetPorts[$ip]["udp"]
        
        # LOGIC FIX: Check if there are actually any ports to scan for this IP
        if ($tcpPorts.Count -eq 0 -and $udpPorts.Count -eq 0) {
            # FIX: Use ${ip} to delimit variable name
            Write-Warning "    [Target $scanCount/$totalTargets] Skipping ${ip}: No open ports were found in discovery."
            continue
        }
        
        # FIX: Use ${ip} to delimit variable name
        Write-Host "    [Target $scanCount/$totalTargets] Scanning ${ip}: T: $($tcpPorts.Count) port(s), U: $($udpPorts.Count) port(s)" -ForegroundColor Yellow

        $portStringParts = [System.Collections.Generic.List[string]]::new()
        $nmapArgsFinalArray = @() # Use array for arguments

        if ($tcpPorts.Count -gt 0) {
            $portStringParts.Add("T:$($tcpPorts -join ',')")
            $nmapArgsFinalArray += "-sS"
        }
        if ($udpPorts.Count -gt 0) {
            $portStringParts.Add("U:$($udpPorts -join ',')")
            $nmapArgsFinalArray += "-sU"
        }
        
        $finalPortString = $portStringParts -join ','
        
        # Build the Nmap command for this single IP
        $tempOutputFileBase = Join-Path -Path $sessionPath -ChildPath "temp_$($ip.Replace('.', '_'))"
        
        # Add core arguments: -sV, -sC, -p, -oA, temp_base, and IP
        $nmapArgsFinalArray += @("-sV", "-sC", "-p", $finalPortString, "-oA", $tempOutputFileBase, $ip)
        Write-Verbose "Executing: $NmapPath $($nmapArgsFinalArray -join ' ')"
        
        # Run the Nmap command using the call operator (&)
        & $NmapPath @nmapArgsFinalArray
        
        # --- Consolidation: Nmap/Grepable (Simple Append) ---
        Get-Content "$($tempOutputFileBase).nmap" -ErrorAction SilentlyContinue | Add-Content -Path $finalNmapFile
        Get-Content "$($tempOutputFileBase).gnmap" -ErrorAction SilentlyContinue | Add-Content -Path $finalGrepableFile

        # --- Consolidation: XML (Aggregate Host Nodes) ---
        $tempXmlPath = "$($tempOutputFileBase).xml"
        if (Test-Path $tempXmlPath) {
            try {
                [xml]$tempXml = Get-Content $tempXmlPath -Raw
                # Check if 'host' nodes exist and add them to the master list
                if ($tempXml.nmaprun.host) {
                    # Handle multiple hosts (array) or single host (object)
                    if ($tempXml.nmaprun.host -is [array]) {
                        $tempXml.nmaprun.host | ForEach-Object { $allHostNodes.Add($_) | Out-Null }
                    } else {
                        $allHostNodes.Add($tempXml.nmaprun.host) | Out-Null
                    }
                }
            }
            catch {
                Write-Warning "Could not parse XML for IP $ip. Skipping host node aggregation for this scan."
            }
        }
        
        # Clean up temporary text files
        Remove-Item "$($tempOutputFileBase).nmap" -Force -ErrorAction SilentlyContinue
        Remove-Item "$($tempOutputFileBase).gnmap" -Force -ErrorAction SilentlyContinue
    }
    
    # --- FINAL XML ASSEMBLY (After all hosts are scanned) ---
    Write-Host "Consolidating all host data into the final XML report..." -ForegroundColor Yellow
    
    # Use the first successfully generated XML file as a template for the header/footer structure
    $sampleXmlFile = Get-ChildItem -Path $sessionPath -Filter "temp_*.xml" | Select-Object -First 1 -ExpandProperty FullName
    
    if (-not $sampleXmlFile) {
        Write-Warning "No valid XML template found. Skipping final XML file generation."
    } else {
        [xml]$masterXml = Get-Content $sampleXmlFile -Raw
        
        # Get the parent of the host node, which is <nmaprun>
        $nmaprunNode = $masterXml.SelectSingleNode("/nmaprun")
        
        # Remove all existing children hosts from the template
        $hostNodes = $nmaprunNode.SelectNodes("host")
        # FIX: Renamed variable from $host (read-only) to $node
        foreach ($node in $hostNodes) {
            $nmaprunNode.RemoveChild($node) | Out-Null
        }
        
        # Add all aggregated host nodes
        foreach ($hostNode in $allHostNodes) {
            # ImportNode is necessary to move a node from one document to another
            $nmaprunNode.AppendChild($masterXml.ImportNode($hostNode, $true)) | Out-Null
        }

        # Save the consolidated, valid XML document
        $masterXml.Save($finalXmlFile)
        Write-Host "[+] Consolidated XML report saved to: $finalXmlFile" -ForegroundColor Green
    }
    
    # Clean up all remaining temporary XML files
    Get-ChildItem -Path $sessionPath -Filter "temp_*.xml" | Remove-Item -Force -ErrorAction SilentlyContinue
    
    Write-Host "`n[PHASE 3 COMPLETE] Detailed results for all hosts consolidated into: $($BaseFileName)-combined files." -ForegroundColor Green
}


# --- COMPLETION ---
Write-Host "`n[COMPLETE] Scan session finished." -ForegroundColor Green
Write-Host "All scan reports have been saved to the '$sessionPath' directory."

# Calculate and display total run time
$endTime = Get-Date
$runTime = $endTime - $startTime
# FIX: Corrected format specifier for seconds from DD to ss
$runTimeString = "{0:D2}h:{1:D2}m:{2:ss}s" -f $runTime.Hours, $runTime.Minutes, $runTime.Seconds
Write-Host "Total script run time: $runTimeString" -ForegroundColor Green
