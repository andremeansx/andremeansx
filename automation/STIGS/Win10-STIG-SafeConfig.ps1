<#
.SYNOPSIS

This script implements a safe, compliant subset of Windows 10 STIGs (V3R4) through registry and feature configurations, organized by STIG categories.
 
#>

.NOTES
    Author          : Andre Means
    LinkedIn        : linkedin.com/
    GitHub          : github.com/
    Date Created    : 2025-08-29
    Last Modified   : 2025-08-29
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A

.TESTED ON
    Date(s) Tested  : 
    Tested By       : Andre Means
    Systems Tested  : 
    PowerShell Ver. : 5.1

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\Win10-STIG-SafeConfig.ps1 

== STIGs Implemented (V3R4) ==

-- Security Options / Lockout --
 - WN10-SO-000070 – The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.

-- Core Configuration / Telemetry & Update Controls --
 - WN10-CC-000205 – Windows Telemetry must not be configured to Full.
 - WN10-CC-000206 – Windows Update must not obtain updates from other PCs on the internet.

-- Core Configuration / SmartScreen & Autoplay --
 - WN10-CC-000210 – The Windows Defender SmartScreen for Explorer must be enabled.
 - WN10-CC-000180 – Autoplay must be turned off for non-volume devices.
 - WN10-CC-000190 – Autoplay must be disabled for all drives.

-- Core Configuration / Networking & SMB --
 - WN10-CC-000025 – The system must be configured to prevent IP source routing (IPv4).
 - WN10-CC-000020 – IPv6 source routing must be configured to highest protection.
 - WN10-CC-000030 – The system must be configured to prevent ICMP redirects from overriding OSPF-generated routes.
 
-- Core Configuration / Event Log Sizes --
 - WN10-AU-000500 – The Application event log size must be configured to 32768 KB or greater.
 - WN10-AU-000505 – The Security event log size must be configured to 1024000 KB or greater.
 - WN10-AU-000510 – The System event log size must be configured to 32768 KB or greater.

-- Core Configuration / RDP Security --
 - WN10-CC-000270 – Passwords must not be saved in the Remote Desktop Client.
 - WN10-CC-000280 – Remote Desktop Services must always prompt a client for passwords upon connection.
 - WN10-CC-000285 – The Remote Desktop Session Host must require secure RPC communications.

-- Core Configuration / WinRM Security --
 - WN10-CC-000330 – The Windows Remote Management (WinRM) client must not use Basic authentication.
 - WN10-CC-000335 – The Windows Remote Management (WinRM) client must not allow unencrypted traffic.
 - WN10-CC-000360 – The Windows Remote Management (WinRM) client must not use Digest authentication.
 - WN10-CC-000345 – The Windows Remote Management (WinRM) service must not use Basic authentication.
 - WN10-CC-000350 – The Windows Remote Management (WinRM) service must not allow unencrypted traffic.
 - WN10-CC-000355 – The Windows Remote Management (WinRM) service must not store RunAs credentials.

-- General System Security / SMBv1 & Signing --
 - WN10-00-000160 – The SMB v1 protocol must be disabled on the system.
 - WN10-00-000165 – The SMB v1 protocol must be disabled on the SMB server.
 - WN10-00-000170 – The SMB v1 protocol must be disabled on the SMB client.
 - WN10-SO-000100 – The Windows SMB client must be configured to always perform SMB packet signing.
 - WN10-SO-000120 – The Windows SMB server must be configured to always perform SMB packet signing.

-- Security Options / Anonymous & Password Hash Control --
 - WN10-SO-000160 – The system must be configured to prevent anonymous users from having the same rights as the Everyone group.
 - WN10-SO-000195 – The system must be configured to prevent the storage of the LAN Manager hash of passwords.

-- PowerShell Logging & Transcription --
 - WN10-CC-000326 – PowerShell script block logging must be enabled on Windows 10.
 - WN10-CC-000327 – PowerShell Transcription must be enabled on Windows 10.

== End of STIGs List ==

# --- Helpers ---
function Ensure-RegistryValue {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] $Desired,
        [ValidateSet('String','ExpandString','Dword','Qword','Binary','MultiString')]
        [string]$Type = 'Dword'
    )
    $exists = Test-Path $Path
    if (-not $exists) { New-Item -Path $Path -Force | Out-Null }

    $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    $changed = $false

    # Normalize desired type/value
    switch ($Type) {
        'Dword'      { $DesiredTyped = [uint32]$Desired }
        'Qword'      { $DesiredTyped = [uint64]$Desired }
        'String'     { $DesiredTyped = [string]$Desired }
        'ExpandString' { $DesiredTyped = [string]$Desired }
        'Binary'     { $DesiredTyped = [byte[]]$Desired }
        'MultiString'{ $DesiredTyped = [string[]]$Desired }
    }

    if ($null -eq $current -or ($current -ne $DesiredTyped -and ($current -join '|') -ne ($DesiredTyped -join '|'))) {
        New-ItemProperty -Path $Path -Name $Name -Value $DesiredTyped -PropertyType $Type -Force | Out-Null
        $changed = $true
    }

    return [pscustomobject]@{
        Path    = $Path
        Name    = $Name
        Type    = $Type
        Current = if ($null -eq $current) { '<not set>' } else { $current }
        Desired = $DesiredTyped
        Changed = $changed
    }
}

function Ensure-FeatureDisabled {
    param([string[]]$FeatureNames)
    $results = @()
    foreach ($f in $FeatureNames) {
        try {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction Stop)
            if ($state.State -ne 'Disabled') {
                Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop | Out-Null
                $changed = $true
            } else { $changed = $false }
            $results += [pscustomobject]@{
                Feature = $f
                Current = $state.State
                Desired = 'Disabled'
                Changed = $changed
            }
        } catch {
            $results += [pscustomobject]@{
                Feature = $f
                Current = 'Unknown/Error'
                Desired = 'Disabled'
                Changed = $false
                Error   = $_.Exception.Message
            }
        }
    }
    return $results
}

$Results = New-Object System.Collections.ArrayList

# --- STIGs (V3R4) ---

# Machine inactivity limit (replaces old HKCU screensaver entries) — WN10-SO-000070
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Desired 900 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-SO-000070'}}, @{n='Desc';e={'Machine inactivity limit = 15 minutes (lock)'}}

# Telemetry not Full — WN10-CC-000205
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Desired 0 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000205'}}, @{n='Desc';e={'Telemetry must not be Full'}}

# Delivery Optimization: no Internet peering — WN10-CC-000206
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -Desired 0 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000206'}}, @{n='Desc';e={'Windows Update must not obtain updates from Internet PCs'}}

# SmartScreen for Explorer enabled — WN10-CC-000210
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000210'}}, @{n='Desc';e={'Windows Defender SmartScreen for Explorer enabled'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Desired 'Block' -Type String |
    Select-Object *, @{n='STIG';e={'WN10-CC-000210'}}, @{n='Desc';e={'SmartScreen level = Block'}}

# Autoplay/Autorun off — WN10-CC-000180/190
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Desired 255 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000190'}}, @{n='Desc';e={'Disable Autoplay for all drives'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000180'}}, @{n='Desc';e={'Autoplay off for non-volume devices'}}

# IP source routing + ICMP redirects — WN10-CC-000025/030 and IPv6 complement of 000020
$Results += Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Desired 2 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000025'}}, @{n='Desc';e={'Disable IP source routing (IPv4)'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Desired 2 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000020'}}, @{n='Desc';e={'Disable IP source routing (IPv6)'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Desired 0 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000030'}}, @{n='Desc';e={'Prevent ICMP redirects from overriding routes'}}

# Event Log sizes — WN10-AU-000500/505/510
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'MaxSize' -Desired 32768 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-AU-000500'}}, @{n='Desc';e={'Application log size >= 32768 KB'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize' -Desired 1024000 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-AU-000505'}}, @{n='Desc';e={'Security log size >= 1024000 KB'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'MaxSize' -Desired 32768 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-AU-000510'}}, @{n='Desc';e={'System log size >= 32768 KB'}}

# RDP hardening — WN10-CC-000270/280/285
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000270'}}, @{n='Desc';e={'Do not save passwords in RDP client'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fPromptForPassword' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000280'}}, @{n='Desc';e={'Always prompt for password upon connection'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEncryptRPCTraffic' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000285'}}, @{n='Desc';e={'Require secure RPC on RDSH'}}

# WinRM client/service auth — WN10-CC-000330/335/345/350/355/360
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -Desired 0 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000330'}}, @{n='Desc';e={'WinRM client: Basic auth disabled'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowUnencryptedTraffic' -Desired 0 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000335'}}, @{n='Desc';e={'WinRM client: unencrypted traffic not allowed'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowDigest' -Desired 0 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000360'}}, @{n='Desc';e={'WinRM client: Digest auth disabled'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic' -Desired 0 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000345'}}, @{n='Desc';e={'WinRM service: Basic auth disabled'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Desired 0 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000350'}}, @{n='Desc';e={'WinRM service: unencrypted traffic not allowed'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'DisableRunAs' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000355'}}, @{n='Desc';e={'WinRM service: do not store RunAs credentials'}}

# SMBv1 disabled (system/server/client) — WN10-00-000160/165/170
$Results += Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Desired 0 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-00-000165'}}, @{n='Desc';e={'SMBv1 server component disabled'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'SMB1' -Desired 0 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-00-000170'}}, @{n='Desc';e={'SMBv1 client component disabled'}}

# SMB signing always — WN10-SO-000100/120
$Results += Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-SO-000100'}}, @{n='Desc';e={'SMB client: packet signing required'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-SO-000120'}}, @{n='Desc';e={'SMB server: packet signing required'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'EnableSecuritySignature' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-SO-000120'}}, @{n='Desc';e={'SMB server: packet signing enabled'}}

# Anonymous restrictions — WN10-SO-000160 (EveryoneIncludesAnonymous = 0)
$Results += Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Desired 0 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-SO-000160'}}, @{n='Desc';e={'Prevent anonymous users having Everyone rights'}}

# LAN Manager hash not stored — WN10-SO-000195
$Results += Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-SO-000195'}}, @{n='Desc';e={'Do not store LM hash of passwords'}}

# PowerShell logging — WN10-CC-000326/327 and disable PSv2 — WN10-00-000155
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000326'}}, @{n='Desc';e={'PowerShell Script Block Logging enabled'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Desired 1 -Type Dword |
    Select-Object *, @{n='STIG';e={'WN10-CC-000327'}}, @{n='Desc';e={'PowerShell Transcription enabled'}}
$Results += Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Desired 'C:\ProgramData\PowerShell\Transcripts' -Type String |
    Select-Object *, @{n='STIG';e={'WN10-CC-000327'}}, @{n='Desc';e={'PowerShell Transcription output to central path'}}
$Results += Ensure-FeatureDisabled -FeatureNames @('MicrosoftWindowsPowerShellV2','MicrosoftWindowsPowerShellV2Root')

# --- Output summary ---
$Csv = Join-Path $env:PUBLIC ("STIG_V3R4_Results_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))
$Results | Export-Csv -Path $Csv -NoTypeInformation
Write-Host "STIG V3R4 enforcement complete. Results: $Csv"
