function Show-Menu {
    param (
        [string]$Title = "Menú Principal"
    )
    Write-Host "~~~~~~~~~~~~~~~~~~~~~~"
    Write-Host "$Title"
    Write-Host "~~~~~~~~~~~~~~~~~~~~~~"
    Write-Host "1. Verificar hash de archivo con VirusTotal"
    Write-Host "2. Listar archivos ocultos"
    Write-Host "3. Ver uso de recursos del sistema"
    Write-Host "4. Revisón de procesos sospechosos"
    Write-Host "5. Salir"
}

function Main {
    Set-StrictMode -Version Latest
    
    do {
        Show-Menu
        $choice = Read-Host "Seleccione una opción"
        
        switch ($choice) {
            1 {
                $filePath = Read-Host "Ingrese la ruta del archivo: "
                Get-FileHashAndCheckVirusTotal -FilePath $filePath
            }
            2 {
                $folderPath = Read-Host "Ingrese la ruta de la carpeta: "
                Get-HiddenFiles -FolderPath $folderPath
            }
            3 {
                Get-SystemResourceUsage
            }
            4 {
                Get-SuspiciousProcesses
            }
            5 {
                Write-Host "Saliendo"
            }
            default {
                Write-Host "Opción no válida, por favor seleccione nuevamente."
            }
        }
    } while ($choice -ne 5)
}

# Run the main script
Main
