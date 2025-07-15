<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Andre Means
    LinkedIn        : linkedin.com/
    GitHub          : github.com/
    Date Created    : 2025-07-15
    Last Modified   : 2025-07-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 2025-07-15
    Tested By       : Andre Means
    Systems Tested  : 
    PowerShell Ver. : v1.0\PowerShell_ISE.exe

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# YOUR CODE GOES HERE



#--------------------------------------------------------------------
# Set MaxSize for Application Event Log (Policy key)
# Location: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application
# Value   : MaxSize (REG_DWORD) = 0x00008000 (32 768 KB)
#--------------------------------------------------------------------

$regPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
$valueName = 'MaxSize'
$valueData = 0x8000  # hexadecimal 0x8000 = 32768 decimal

# Create the key if it doesn't exist
if (-not (Test-Path -LiteralPath $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set (or update) the DWORD value
New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWord -Force | Out-Null

Write-Host "MaxSize successfully set to 0x$("{0:X8}" -f $valueData) under $regPath"
