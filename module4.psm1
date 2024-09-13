function Get-SuspiciousProcesses {
    <#
    .SYNOPSIS
    Look for suspicious processes based on high CPU usage or names associated with malware.
    
    .PARAMETER CpuThreshold
    The CPU threshold that considers a process suspicious (in percentage).

    .PARAMETER KnownBadProcessNames
    List of names of known or suspected malicious processes.

    .EXAMPLE
    Get-SuspiciousProcesses -CpuThreshold 50 -KnownBadProcessNames @("badprocess.exe", "malware.exe")
    
    .DESCRIPTION
    Checks running processes and alerts if they exceed a certain CPU threshold or if their names match known malicious processes.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$CpuThreshold,

        [Parameter(Mandatory = $false)]
        [string[]]$KnownBadProcessNames = @("badprocess.exe", "malware.exe", "suspicious.exe")
    )
    
    try {
        # Activate strict mode
        Set-StrictMode -Version Latest

        # Get all running processes
        $processes = Get-Process

        # Check processes with high CPU usage
        $highCpuProcesses = $processes | Where-Object { $_.CPU -gt $CpuThreshold }

        if ($highCpuProcesses) {
            Write-Host "Processes using more than $CpuThreshold% CPU:"
            $highCpuProcesses | ForEach-Object {
                try {
                    Write-Host "$($.Name) - CPU: $($.CPU)"
                }
                catch {
                    Write-Error "Error retrieving process information: $_"
                }
            }
        } else {
            Write-Host "No processes exceed $CpuThreshold% CPU."
        }

        # Search for known malicious processes
        $badProcesses = $processes | Where-Object {
            try {
                $KnownBadProcessNames -contains $_.Name
            }
            catch {
                Write-Error "Error checking process name: $_"
            }
        }

        if ($badProcesses) {
            Write-Host "Known suspicious processes running:"
            $badProcesses | ForEach-Object {
                try {
                    Write-Host "$($_.Name) is running. Consider investigating."
                }
                catch {
                    Write-Error "Error retrieving suspicious process information: $_"
                }
            }
        } else {
            Write-Host "No known suspicious processes are running."
        }
    }
    catch {
        Write-Error "Error al buscar procesos sospechosos: $_"
    }
}

# Export function
Export-ModuleMember -Function Get-SuspiciousProcesses
