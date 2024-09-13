function Get-SuspiciousProcesses {
    <#
    .SYNOPSIS
    Look for suspicious processes based on high CPU usage or names commonly associated with malware.

    .PARAMETER CpuThreshold
    Defines the CPU usage limit (in percentage) to consider a process suspicious.

    .PARAMETER KnownBadProcessNames
    Provides a list of process names that are known to be malicious or dubious.

    .EXAMPLE
    Get-SuspiciousProcesses -CpuThreshold 50 -KnownBadProcessNames @("badprocess.exe", "malware.exe")

    .DESCRIPTION
    This module analyzes processes that exceed a specified CPU usage level or whose names match a list of processes commonly used by malware.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$CpuThreshold,

        [Parameter(Mandatory = $false)]
        [string[]]$KnownBadProcessNames = @("badprocess.exe", "malware.exe", "suspicious.exe")
    )
    
    try {
        # Enable strict mode for script execution
        Set-StrictMode -Version Latest

        # Get all active processes
        $processes = Get-Process

        # Buscar procesos con alto uso de CPU
        $highCpuProcesses = $processes | Where-Object { $_.CPU -gt $CpuThreshold }
        
        # Mostrar los procesos que exceden el umbral de CPU
        if ($highCpuProcesses) {
            Write-Host "Processes using more than $CpuThreshold% CPU:"
            $highCpuProcesses | ForEach-Object {
                Write-Host "$($.Name) - CPU: $($.CPU)"
            }
        } else {
            Write-Host "No processes exceed $CpuThreshold% CPU."
        }

        # Buscar procesos cuyo nombre coincida con la lista de procesos conocidos como maliciosos
        $badProcesses = $processes | Where-Object { $KnownBadProcessNames -contains $_.Name }

        # Mostrar los procesos conocidos por ser sospechosos
        if ($badProcesses) {
            Write-Host "Known suspicious processes running:"
            $badProcesses | ForEach-Object {
                Write-Host "$($_.Name) is running. Consider investigating."
            }
        } else {
            Write-Host "No known suspicious processes are running."
        }
    }
    catch {
        Write-Error "Error al buscar procesos sospechosos: $_"
    }
}
