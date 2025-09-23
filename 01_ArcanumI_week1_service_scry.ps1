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

function Get-ServiceRiskLevel {
    param($ServiceName, $DisplayName)
    

# In the Get-ServiceRiskLevel function, ADD these patterns:

# Add more critical security services
$criticalServices = @("WinDefend", "SecurityCenter", "EventLog", "WindowsFirewall", "MPSSVC", 
                     "WdNisSvc", "Sense", "SENSE", "WdBoot", "WdFilter", "TermService",
                     "RemoteRegistry", "WinHttpAutoProxySvc", "LanmanServer")

# Add more high-risk infrastructure services  
$highServices = @("DNS", "DHCP", "Spooler", "LanmanServer", "Netlogon", "RpcSs",
                  "Dnscache", "SamSs", "LSASS", "BITS", "CryptSvc", "DcomLaunch",
                  "EventSystem", "Netman", "Schedule", "SessionEnv", "TapiSrv")
    # Critical: Security services
    $criticalServices = @("WinDefend", "SecurityCenter", "EventLog", "WindowsFirewall", "MPSSVC")
    
    # High: Infrastructure services  
    $highServices = @("DNS", "DHCP", "Spooler", "LanmanServer", "Netlogon", "RpcSs")
    
    if ($criticalServices -contains $ServiceName) { return "CRITICAL" }
    if ($highServices -contains $ServiceName) { return "HIGH" }
    
    # Check display name patterns
    if ($DisplayName -like "*Defender*" -or $DisplayName -like "*Firewall*" -or 
        $DisplayName -like "*Security*" -or $DisplayName -like "*Antivirus*") {
        return "CRITICAL"
    }
    
    if ($DisplayName -like "*DNS*" -or $DisplayName -like "*DHCP*" -or 
        $DisplayName -like "*Domain*" -or $DisplayName -like "*Network*") {
        return "HIGH"
    }
    
    return "MEDIUM"
}

param(
    [string]$FileName = ".\service_scry_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').json",
    [switch]$VerboseOutput
)

try {
    Write-Host "Aethelgard Enhanced Service Scry: Checking services..." -ForegroundColor Yellow

    # ===== ENHANCED SERVICE ENUMERATION =====
    $allServices = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop

    # Analyze each service with enhanced information
    $enhancedServices = $allServices | ForEach-Object {
        # Determine start type (Auto vs Auto Delayed)
        $startType = if ($_.DelayedAutoStart) { "Automatic (Delayed)" } else { $_.StartMode }
        
        # Get risk level
        $riskLevel = Get-ServiceRiskLevel -ServiceName $_.Name -DisplayName $_.DisplayName
        
        # Check for broken dependencies
        $hasStoppedDeps = $false
        if ($_.ServicesDependedOn) {
            $stoppedDeps = $_.ServicesDependedOn | Where-Object {
                $depService = $allServices | Where-Object Name -eq $_
                $depService.State -eq 'Stopped'
            }
            $hasStoppedDeps = $stoppedDeps.Count -gt 0
        }
        
        [PSCustomObject]@{
            Name = $_.Name
            DisplayName = $_.DisplayName
            Status = $_.State
            StartType = $startType
            StartMode = $_.StartMode
            RiskLevel = $riskLevel
            Dependencies = if ($_.ServicesDependedOn) { $_.ServicesDependedOn -join ", " } else { "None" }
            HasStoppedDependencies = $hasStoppedDeps
            DelayedAutoStart = $_.DelayedAutoStart
        }
    }

    # Filter for problematic services
    $problems = $enhancedServices | Where-Object {
        $_.StartMode -eq 'Auto' -and $_.Status -eq 'Stopped'
    }

    # ===== ENHANCED HUMAN-READABLE OUTPUT =====
    Write-Host "`n=== SECURITY RISK ASSESSMENT ===" -ForegroundColor Cyan
    Write-Host "Scanned host: $env:COMPUTERNAME" -ForegroundColor Yellow
    Write-Host "Total services analyzed: $($allServices.Count)" -ForegroundColor Yellow
    Write-Host "Problematic services found: $($problems.Count)" -ForegroundColor Red
    
    # Risk summary
    $criticalCount = ($problems | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highCount = ($problems | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $brokenDepsCount = ($problems | Where-Object { $_.HasStoppedDependencies }).Count
    
    Write-Host "Critical risk services: $criticalCount" -ForegroundColor Red
    Write-Host "High risk services: $highCount" -ForegroundColor Yellow
    Write-Host "Services with broken dependencies: $brokenDepsCount" -ForegroundColor Magenta
    Write-Host ""

    if ($problems.Count -gt 0) {
        # Display services sorted by risk level (Critical first)
        $problems | Sort-Object @{Expression = {$_.RiskLevel -eq "CRITICAL"}; Descending = $true}, 
                               @{Expression = {$_.RiskLevel -eq "HIGH"}; Descending = $true}, 
                               Name | Format-Table -Property @(
            @{Name="Service"; Expression={$_.Name}}
            @{Name="Display Name"; Expression={$_.DisplayName}}
            @{Name="Start Type"; Expression={$_.StartType}}
            @{Name="Status"; Expression={$_.Status}}
            @{Name="Risk Level"; Expression={
                switch ($_.RiskLevel) {
                    "CRITICAL" { "🚨 CRITICAL" }
                    "HIGH" { "⚠️ HIGH" }
                    default { "🔸 MEDIUM" }
                }
            }}
            @{Name="Broken Deps"; Expression={if($_.HasStoppedDependencies){"🔗 YES"}else{"-"}}}
        ) -AutoSize
        
        # Additional warnings for critical findings
        if ($criticalCount -gt 0) {
            Write-Host "`n🚨 SECURITY ALERT: $criticalCount critical services are stopped!" -ForegroundColor Red
            Write-Host "   These services should be investigated immediately." -ForegroundColor Yellow
        }
        
        if ($brokenDepsCount -gt 0) {
            Write-Host "`n🔗 DEPENDENCY ISSUE: $brokenDepsCount services have stopped dependencies" -ForegroundColor Magenta
            Write-Host "   Check dependent services to resolve chain failures." -ForegroundColor Yellow
        }
    } else {
        Write-Host "✅ No problematic services detected. System conforms to expectations." -ForegroundColor Green
    }

    # ===== ENHANCED MACHINE-READABLE JSON OUTPUT =====
    $outputObject = [PSCustomObject]@{
        scan_timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        hostname = $env:COMPUTERNAME
        scan_summary = @{
            total_services = $allServices.Count
            problematic_services_count = $problems.Count
            critical_risk_count = $criticalCount
            high_risk_count = $highCount
            services_with_broken_dependencies = $brokenDepsCount
        }
        problematic_services = $problems | Select-Object Name, DisplayName, StartType, Status, RiskLevel, HasStoppedDependencies, Dependencies, DelayedAutoStart
    }

    $outputObject | ConvertTo-Json -Depth 4 | Out-File -FilePath $FileName -Encoding UTF8
    Write-Host "`nEnhanced results saved to: $FileName" -ForegroundColor Green

}
catch {
    Write-Host "ERROR: Service enumeration failed - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`nService scry complete. Ethical Codex maintained." -ForegroundColor Cyan