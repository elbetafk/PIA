function Get-FileHashAndCheckVirusTotal {
    <#
    .SYNOPSIS
    Gets the hash of a file and queries it in the VirusTotal API
    
    .PARAMETER FilePath
    Full file path

    .EXAMPLE
    Get-FileHashAndCheckVirusTotal -FilePath "C:\archivo.exe"
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        Set-StrictMode -Version Latest
      
        if (-not (Test-Path -Path $FilePath)) {
            throw "El archivo no existe: $FilePath"
        }

        #Verify file HASHES
        $fileHash = Get-FileHash -Path $FilePath -Algorithm SHA256

        #Verify the file in the API
        $apiKey = "776c91a8ce50fae44dec156bfe4012be639c09e15eed0fce70a945c57c74db26"
        $url = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$($fileHash.Hash)"

        # Sends a REST API request to the specified URL using the GET method
        $response = Invoke-RestMethod -Uri $url -Method Get
        $response
    }
    catch {
        Write-Error "Error al procesar el archivo: $_"
    }
}
