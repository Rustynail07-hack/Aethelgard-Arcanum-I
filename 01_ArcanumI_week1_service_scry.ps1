<#
.SYNOPSIS
    Scrys Windows services to identify Automatic services that are Stopped.
.DESCRIPTION
    Enumerates all Windows services, identifies services with StartupType 'Automatic' 
    but Status 'Stopped', and outputs both human-readable and machine-readable formats.
    Conforms to Aethelgard Ethical Codex - read-only operations only.
.EXAMPLE
    .\01_ArcanumI_week1_service_scry.ps1
    Runs the script with default parameters
.EXAMPLE
    .\01_ArcanumI_week1_service_scry.ps1 -FileName "myservices.json"
    Saves output to custom JSON file
#>

param(
    [string]$FileName = ".\service_scry_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').json",
    [switch]$VerboseOutput
)

try {
    Write-Host "Aethelgard Service Scry: Checking services..." -ForegroundColor Yellow

    # Core service enumeration logic
    $problems = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
                Where-Object {$_.StartMode -eq 'Auto' -and $_.State -eq 'Stopped'}

    # Human-readable output
    Write-Host "Found $($problems.Count) problematic services" -ForegroundColor Red
    if ($problems.Count -gt 0) {
        $problems | Format-Table Name, DisplayName, StartMode, State -AutoSize
    } else {
        Write-Host "No Automatic services found in Stopped state." -ForegroundColor Green
    }

    # Machine-readable JSON output
    $problems | Select-Object Name, DisplayName, StartMode, State | ConvertTo-Json | Out-File $FileName
    Write-Host "Results saved to: $FileName" -ForegroundColor Green

}
catch {
    Write-Host "ERROR: Service enumeration failed - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "Service scry complete. Ethical Codex maintained." -ForegroundColor Cyan