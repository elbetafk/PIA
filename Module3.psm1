function Get-SystemResourceUsage {
    <#
    .SYNOPSIS
    Muestra el uso de recursos del sistema: CPU (en porcentaje), Memoria, Disco, y Red.
    
    .EXAMPLE
    Get-SystemResourceUsage
    #>
    
    try {
        # Modo estricto
        Set-StrictMode -Version Latest
        
        # Uso de CPU
        $cpu = Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object Average
        
        # Uso de Memoria
        $memory = Get-WmiObject Win32_OperatingSystem
        $totalMemory = [math]::Round($memory.TotalVisibleMemorySize/1MB,2)
        $freeMemory = [math]::Round($memory.FreePhysicalMemory/1MB,2)
        $usedMemory = $totalMemory - $freeMemory
        
        # Uso de Disco
        $disk = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3"
        
        # Uso de Red
        $network = Get-NetAdapter | Select-Object Name, Status, LinkSpeed
        
        # Salida
        [PSCustomObject]@{
            CPU_Usage = "$($cpu.Average)%"
            Memory_Usage = "$usedMemory MB de $totalMemory MB"
            Disk_Usage = $disk | Select-Object DeviceID, Size, FreeSpace
            Network_Adapters = $network
        }
    }
    catch {
        Write-Error "Error al obtener el uso de recursos del sistema: $_"
    }
}