# Arcanum I — Week 1: Service Scry Utility

Defensive PowerShell script identifying Windows services set to Automatic but Stopped.

## Usage
\\\powershell
.\01_ArcanumI_week1_service_scry.ps1
\\\

## Features
- Human-readable console output
- Machine-readable JSON export
- Error handling
- Ethical Codex compliant


# Add Part II section to README.md
$partIIContent = @'

## Part II Enhancements (Week 1 Extension)

### Risk Assessment Framework
Services are categorized by security impact:
- **🚨 CRITICAL**: Security services (Defender, Firewall, Event Logging)
- **⚠️ HIGH**: Infrastructure services (DNS, DHCP, Authentication)
- **🔸 MEDIUM**: Application/utility services

### Dependency Chain Analysis
Identifies services with stopped dependencies, revealing cascade failure points that attackers can exploit.

### Delayed Start Detection
Distinguishes between:
- **Automatic**: Starts immediately at boot (high priority)
- **Automatic (Delayed)**: Starts 2 minutes after boot (lower priority)

### Security Assessment Output
Professional risk-prioritized reporting with:
- Color-coded risk levels
- Dependency chain warnings  
- Actionable remediation guidance
'@

# Append to README.md
$partIIContent | Out-File -FilePath "README.md" -Append -Encoding UTF8
