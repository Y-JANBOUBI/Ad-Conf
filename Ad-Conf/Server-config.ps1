<#
.SYNOPSIS
    Run file for ADConf-Module.psm1 to configure Active Directory, DHCP, and network settings.

.DESCRIPTION
    This script provides a menu-driven interface to execute functions from ADConf-Module.psm1
    for configuring network settings, system settings, Active Directory, and DHCP services 
    with a professional and colorful user interface.

.CONFIGURATION
    To pre-configure settings (avoid manual input during execution):
    
    1. Edit the "Config Parameter" section in this script (lines ~50-200)
    2. Set the desired variables with your configuration values
    3. Examples:
       - $script:DomainName = "company.local"
       - $script:IPv4 = "192.168.1.10"
       - $script:NewName = "DC01"

    4. Leave variables as `$null` if you want to be prompted during execution

.USAGE
    # Interactive mode (shows menu)
    .\Server-config.ps1

.EXAMPLE
    # Pre-configured mode (edit script variables first)
    # Set $script:DomainName, $script:IPv4, etc. then run:
    .\Server-config.ps1

.NOTES
    - Requires Administrator privileges
    - Requires ADConf-Module.psm1 in the same directory
    - Some operations may require system reboot
    - Test in non-production environment first

.AUTHOR
    Name : Yasser-Janboubi 
    GitHub : Y-Janboubi

#>

param(
    [string]$ScriptPath = $PSCommandPath
)

#region Config Parameter 

#==========================================================================
# CONFIGURATION PARAMETERS - SET VALUES BELOW AS NEEDED
#==========================================================================
#
# For each feature you want to pre-configure, replace $null with your value
# Leave as $null to be prompted for input during script execution
# 
# Examples: 
#   $script:DomainName = "company.local"    # ← Uses this value (no prompt)
#   $script:DomainName = $null              # ← Prompts user for input
#==========================================================================

# ================== SYSTEM / NETWORK CONFIG ==================

# 1.1) Enables or disables Ctrl+Alt+Del secure logon requirement
# Function: Disable-CtrlAltDel
$script:Disable_CAD = $null  # Example: $true (disable CAD) or $false (enable CAD)

# 1.2) Sets system timezone
# Function: Set-TimeZoneConfig
$script:TimeZone = "Morocco Standard Time"  # Example: "UTC" or "Morocco Standard Time"

# 1.3) Renames the local computer
# Function: Rename-ComputerSystem
$script:NewName = $null  # Example: "DC01"

# 1.4) Configures static IPv4 address, gateway, and DNS servers
# Function: Set-StaticIPv4
$script:IPv4 = $null  # Example: "192.168.2.10"
$script:Gateway4 = $null  # Example: "192.168.2.1"
$script:DNS4 = $null  # Example: "8.8.8.8"

# 1.5) Configures static IPv6 address, gateway, and DNS servers
# Function: Set-StaticIPv6
$script:IPv6 = $null  # Example: "2001:db8::10"
$script:Gateway6 = $null  # Example: "2001:db8::1"
$script:DNS6 = $null  # Example: "2001:4860:4860::8888"

# 1.9) Configures Server Manager startup behavior
# Function: Set-ServerManagerStartup
$script:Disable_Startup = $null  # Example: $true (disable Server Manager) or $false (enable Server Manager)

# ===================== ACTIVE DIRECTORY ======================

# 2.1) Installs AD and creates a new AD forest
# Function: Install-CustomADForest
$script:DomainName = $null  # Example: "test.local"
$script:NetbiosName = $null  # Example: "TEST"
$script:SafeModePassword = $null  # Example: "Password123!"

# 2.2) Creates random AD users in a specified OU
# Function: New-RandomADUser
$script:OuName = $null  # Example: "OU=Users,DC=test,DC=local"  # Standardized from $OUPath
$script:Random_User_Name = $null  # Example: "TestUser"
$script:Count = $null  # Example: 10
$script:Random_User_Password = $null  # Example: "Pass@123"
$script:Random_User_Enabled = $null  # Optional: $true (enable users) or $false (disable users)
$script:Random_User_Description = $null  # Optional: Example: "Random User N:"
$script:Random_User_ChangePasswordAtLogon = $null  # Optional: $true or $false

# 2.3) Creates OUs, groups, and users from a CSV file
# Function: Import-CsvADUser
$script:CsvPath = $null  # Example: "C:\AD\users.csv"
$script:Csv_User_Password = ConvertTo-SecureString "Pass@123" -AsPlainText -Force  # Example: ConvertTo-SecureString "Pass@123" -AsPlainText -Force
$script:Csv_User_Enabled = $null  # Optional: $true (enable users) or $false (disable users)
$script:Csv_User_ChangePasswordAtLogon = $null  # Optional: $true or $false

# =========================== DHCP ============================

# 3.1) Creates a new DHCP IPv4 scope
# Function: New-Dhcp4Scope
$script:ScopeName = $null  # Example: "OfficeScope"
$script:StartRange = $null  # Example: "192.168.2.50"
$script:EndRange = $null  # Example: "192.168.2.100"
$script:SubnetMask = $null  # Optional: Example: "255.255.255.0"
$script:LeaseDuration = $null # Optional: Example: (New-TimeSpan -Days 8)
$script:State = $null  # Optional: Example: "Active" or "Inactive"
$script:Description = $null  # Optional: Example: "Main Office Scope"

# 3.2) Installs and authorizes the DHCP server in Active Directory
# Function: Install-DhcpAndAuthorize
$script:DhcpServerName = $null  # Optional: Example: "dhcp01.test.local"
$script:DhcpServerIP = $null  # Optional: Example: "192.168.2.10"

# 3.3) Combines DHCP installation, authorization, and scope creation
# Function: Add-DhcpServer
# Reuses parameters from 3.1 and 3.2 above

# =========================== DNS =============================

# 4.1) Creates a primary forward DNS zone
# Function: Add-DnsPrimaryForwardZone
$script:ZoneName = $null  # Example: "corp.local"
$script:ComputerName = $null  # Example: "DC01"

# 4.2) Creates a primary reverse DNS zone
# Function: Add-DnsPrimaryReverseZone
$script:NetworkID = $null  # Example: "192.168.2"

# 4.3) Creates a file-based DNS zone
# Function: Add-DnsFileBasedZone
$script:ZoneFile = $null  # Example: "corp.local.dns"

# 4.4) Configures DNS zone notifications
# Function: Set-DnsZoneNotification
$script:NotifyServers = $null  # Example: "192.168.2.11"

# 4.5) Exports a DNS zone to a file
# Function: Export-DnsZone
$script:ExportFile = $null  # Example: "C:\DNS\corp.local.dns"

# 4.6) Creates a secondary DNS zone
# Function: Add-DnsSecondaryZone
$script:SecondaryZoneName = $null  # Example: "corp.local"
$script:SecondaryZoneFile = $null  # Example: "corp.local.dns"
$script:MasterServers = $null  # Example: "192.168.2.10"

# 4.7) Creates a stub DNS zone
# Function: Add-DnsStubZone
$script:StubZoneName = $null  # Example: "corp.local"
$script:StubMasterServers = $null  # Example: @("192.168.2.10")

# 4.8) Configures conditional forwarder
# Function: Add-DnsConditionalForwarder
$script:ForwarderDomain = $null  # Example: "partner.local"
$script:ForwarderServers = $null  # Example: @("192.168.3.10")
$script:ForwarderTimeout = $null  # Optional: Example: 5 (seconds)

# 4.9) Delegates a subdomain
# Function: Add-DnsZoneDelegation
$script:ParentZone = $null  # Example: "corp.local"
$script:ChildZone = $null  # Example: "dev.corp.local"
$script:ChildNS = $null  # Example: @("ns1.dev.corp.local")
$script:ChildIPs = $null  # Example: @("192.168.4.10")

# 4.10) Adds an A record
# Function: Add-DnsARecord
$script:RecordName = $null  # Example: "web01"
$script:RecordIPv4 = $null  # Example: "192.168.2.200"

# 4.11) Adds a CNAME record
# Function: Add-DnsCnameRecord
$script:AliasName = $null  # Example: "www"
$script:CNameTarget = $null  # Example: "web01.corp.local"

# 4.12) Adds an MX record
# Function: Add-DnsMxRecord
$script:MailServer = $null  # Example: "mail.corp.local"
$script:Preference = $null  # Optional: Example: 10

# 4.13) Enables DNS scavenging
# Function: Enable-DnsScavenging
$script:ScavengingInterval = $null  # Example: (New-TimeSpan -Days 7)


#endregion

#region Display Option Menu with Logo

function logo-option {
    Clear-Host
    Write-Host "╔═════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═══════════════════════════════ [AD-CONF] ═══════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "         █████╗ ██████╗        ██████╗ ██████╗ ███╗   ██╗███████╗          " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ██╔══██╗██╔══██╗      ██╔════╝██╔═══██╗████╗  ██║██╔════╝          " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ███████║██║  ██║█████╗██║     ██║   ██║██╔██╗ ██║█████╗            " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ██╔══██║██║  ██║╚════╝██║     ██║   ██║██║╚██╗██║██╔══╝            " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ██║  ██║██████╔╝      ╚██████╗╚██████╔╝██║ ╚████║██║               " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ╚═╝  ╚═╝╚═════╝        ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝               " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╔═════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═══════════════ Active Directory & Network Configuration ════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "[*] Select an option from the menu below:" -ForegroundColor Black -BackgroundColor Cyan
    Write-Host "  0) Configure AD from scratch" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "  1) Fresh Installation & Configuration Option" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "  2) AD Installation & Configuration Option" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "  3) DHCP Installation & Configuration Option" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "  4) DNS Installation & Configuration Option" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "  5) Exit" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host -NoNewline "[*] Enter your choice (0-5): " -ForegroundColor Black -BackgroundColor Cyan
    return Read-Host
}

function Show-SubMenu {
    param($MenuNumber)
    
    Clear-Host
    Write-Host "╔═════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═══════════════════════════════ [AD-CONF] ═══════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "         █████╗ ██████╗        ██████╗ ██████╗ ███╗   ██╗███████╗          " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ██╔══██╗██╔══██╗      ██╔════╝██╔═══██╗████╗  ██║██╔════╝          " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ███████║██║  ██║█████╗██║     ██║   ██║██╔██╗ ██║█████╗            " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ██╔══██║██║  ██║╚════╝██║     ██║   ██║██║╚██╗██║██╔══╝            " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ██║  ██║██████╔╝      ╚██████╗╚██████╔╝██║ ╚████║██║               " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ╚═╝  ╚═╝╚═════╝        ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝               " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╔═════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═══════════════ Active Directory & Network Configuration ════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    
    switch ($MenuNumber) {
        1 {
            Write-Host "[*] Fresh Configuration Option" -ForegroundColor Black -BackgroundColor Cyan
            Write-Host "  1) Disable or enable Ctrl+Alt+Del requirement" -ForegroundColor White
            Write-Host "  2) Set timezone" -ForegroundColor White
            Write-Host "  3) Rename computer" -ForegroundColor White
            Write-Host "  4) Set static IPv4" -ForegroundColor White
            Write-Host "  5) Set static IPv6" -ForegroundColor White
            Write-Host "  6) Disable IPv6" -ForegroundColor White
            Write-Host "  7) Install Windows updates (PSWindowsUpdate)" -ForegroundColor White
            Write-Host "  8) Enable RDP & firewall rules" -ForegroundColor White
            Write-Host "  9) Disable Server Manager from startup" -ForegroundColor White
            Write-Host "  10) Back to main menu" -ForegroundColor White
            Write-Host -NoNewline "[*] Enter your choice (1-10): " -ForegroundColor Black -BackgroundColor Cyan
            return Read-Host
        }
        2 {
            Write-Host "[*] AD Installation & Configuration Option" -ForegroundColor Black -BackgroundColor Cyan
            Write-Host "  1) Install ADDS & create new AD forest" -ForegroundColor White
            Write-Host "  2) Create random users" -ForegroundColor White
            Write-Host "  3) Create users from custom config file (CSV)" -ForegroundColor White
            Write-Host "  4) Back to main menu" -ForegroundColor White
            Write-Host -NoNewline "[*] Enter your choice (1-4): " -ForegroundColor Black -BackgroundColor Cyan
            return Read-Host
        }
        3 {
            Write-Host "[*] DHCP Installation & Configuration Option" -ForegroundColor Black -BackgroundColor Cyan
            Write-Host "  1) Install DHCP & Authorize" -ForegroundColor White
            Write-Host "  2) Create DHCP for IPv4" -ForegroundColor White
            #Write-Host "  3) DHCP Reservations" -ForegroundColor White
            Write-Host "  4) Back to main menu" -ForegroundColor White
            Write-Host -NoNewline "[*] Enter your choice (1-4): " -ForegroundColor Black -BackgroundColor Cyan
            return Read-Host
        }
        4 {
            Write-Host "[*] DNS Configuration Option" -ForegroundColor Black -BackgroundColor Cyan
            Write-Host "  1) Create primary forward DNS zone" -ForegroundColor White
            Write-Host "  2) Create primary reverse DNS zone" -ForegroundColor White
            Write-Host "  3) Create file-based DNS zone" -ForegroundColor White
            Write-Host "  4) Configure DNS zone notifications" -ForegroundColor White
            Write-Host "  5) Export DNS zone to file" -ForegroundColor White
            Write-Host "  6) Create secondary DNS zone" -ForegroundColor White
            Write-Host "  7) Create stub DNS zone" -ForegroundColor White
            Write-Host "  8) Configure conditional forwarder" -ForegroundColor White
            Write-Host "  9) Delegate a subdomain" -ForegroundColor White
            Write-Host "  10) Add A record" -ForegroundColor White
            Write-Host "  11) Add CNAME record" -ForegroundColor White
            Write-Host "  12) Add MX record" -ForegroundColor White
            Write-Host "  13) Enable DNS scavenging" -ForegroundColor White
            Write-Host "  14) Back to main menu" -ForegroundColor White
            Write-Host -NoNewline "[*] Enter your choice (1-14): " -ForegroundColor Black -BackgroundColor Cyan
            return Read-Host
        }
    }
}

function LogoAd-Conf {
    Clear-Host
    Write-Host "╔═════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═══════════════════════════════ [AD-CONF] ═══════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "         █████╗ ██████╗        ██████╗ ██████╗ ███╗   ██╗███████╗          " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ██╔══██╗██╔══██╗      ██╔════╝██╔═══██╗████╗  ██║██╔════╝          " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ███████║██║  ██║█████╗██║     ██║   ██║██╔██╗ ██║█████╗            " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ██╔══██║██║  ██║╚════╝██║     ██║   ██║██║╚██╗██║██╔══╝            " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ██║  ██║██████╔╝      ╚██████╗╚██████╔╝██║ ╚████║██║               " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "        ╚═╝  ╚═╝╚═════╝        ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝               " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╔═════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═══════════════ Active Directory & Network Configuration ════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚═════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host ""
}

function LogoCheck {
    Clear-Host
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkGreen -BackgroundColor Black
    Write-Host "╚═══════════════════════════════ [ CONF-CHECK ] ════════════════════════════════════╝" -ForegroundColor DarkGreen -BackgroundColor Black
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkGreen -BackgroundColor Black
    Write-Host "    ██████╗ ██████╗ ███╗   ██╗███████╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗   " -ForegroundColor DarkGreen -BackgroundColor Black
    Write-Host "   ██╔════╝██╔═══██╗████╗  ██║██╔════╝    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝   " -ForegroundColor DarkGreen -BackgroundColor Black
    Write-Host "   ██║     ██║   ██║██╔██╗ ██║█████╗█████╗██║     ███████║█████╗  ██║     █████╔╝    " -ForegroundColor DarkGreen -BackgroundColor Black
    Write-Host "   ██║     ██║   ██║██║╚██╗██║██╔══╝╚════╝██║     ██╔══██║██╔══╝  ██║     ██╔═██╗    " -ForegroundColor DarkGreen -BackgroundColor Black
    Write-Host "   ╚██████╗╚██████╔╝██║ ╚████║██║         ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗   " -ForegroundColor DarkGreen -BackgroundColor Black
    Write-Host "    ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝          ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝   " -ForegroundColor DarkGreen -BackgroundColor Black
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkGreen -BackgroundColor Black
    Write-Host "╚════════════════════ Active Directory & Network Configuration ═════════════════════╝" -ForegroundColor DarkGreen -BackgroundColor Black
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkGreen -BackgroundColor Black
}

#endregion

#region Check module file

function Check-Module {
    
    $expectedModule = "ADConf-Module.psm1"
    $scriptDir = Split-Path $ScriptPath -Parent
    $global:ModulePath = Join-Path $scriptDir $expectedModule

    # Get all modules in the folder
    $modules = Get-ChildItem -Path $scriptDir -Filter *.psm1 -File -ErrorAction SilentlyContinue 


    if ($modules.Name -notcontains $expectedModule) {
        Write-Host "[-] Found Module(s): $($modules.Name -join '; ')" -ForegroundColor Green -BackgroundColor Black
        Write-Host "[-] But Expected Module: $expectedModule" -ForegroundColor Red -BackgroundColor Black
        exit 1
    }
    elseif (-not (Test-Path $global:ModulePath)) {
        Write-Host "[-] Cannot find $expectedModule in $ScriptPath" -ForegroundColor Red -BackgroundColor Black
        exit 1
    }
    else {
        Write-Host "[+] Module found: $global:ModulePath" -ForegroundColor Green -BackgroundColor Black
    }

}

#endregion

#region Import the module

function Import-Modul {

    try {
        Import-Module $ModulePath -Force -ErrorAction Stop -Verbose:$false
        Write-Host "[+] Module ADConf-Module.psm1 imported successfully." -ForegroundColor Green -BackgroundColor Black
    } catch {
        Write-Host "[-] Failed to import ADConf-Module.psm1: $_" -ForegroundColor Red -BackgroundColor Black
        exit 1
    }

}

#endregion

#region check Module & Admin

function check-Module-Admin {

    # Display logo
    LogoCheck

    # Check module file
    Check-Module

    # Import module
    Import-Modul

    Write-Host "[*] System Check Started" -ForegroundColor Cyan -BackgroundColor Black  
    Write-Host "[*] Running at: $(Get-Date)" -ForegroundColor Yellow -BackgroundColor Black
    $admin    = Test-AdministratorPrivileges
    if (-not $admin){
            Write-Host "[!] This program must be run as Administrator." -ForegroundColor Red -BackgroundColor Black
            Write-Host "[-] Checks FAILED!" -ForegroundColor Red -BackgroundColor Black
            exit 1         
    }
}

#endregion

#region Reset- Unset Parameters

function Get-UnsetVariables {
    [CmdletBinding()]
    param()
    
    # Define all script variables that should be tracked
    $global:setVariables = @()
    $global:unsetVariables = @()  # Renamed for clarity

    $scriptVariables = @(
        # ================== SYSTEM / NETWORK CONFIG ==================
        'Disable_CAD', 'TimeZone', 'NewName', 'IPv4', 'Gateway4', 'DNS4',
        'IPv6', 'Gateway6', 'DNS6', 'Disable_Startup',
        
        # ===================== ACTIVE DIRECTORY ======================
        'DomainName', 'NetbiosName', 'SafeModePassword', 'OuName',
        'Random_User_Name', 'Count', 'Random_User_Password', 'Random_User_Enabled',
        'Random_User_Description', 'Random_User_ChangePasswordAtLogon',
        'CsvPath', 'Csv_User_Password', 'Csv_User_Enabled', 'Csv_User_ChangePasswordAtLogon',
        
        # =========================== DHCP ============================
        'ScopeName', 'StartRange', 'EndRange', 'SubnetMask', 'LeaseDuration',
        'State', 'Description', 'DhcpServerName', 'DhcpServerIP',
        
        # =========================== DNS =============================
        'ZoneName', 'ComputerName', 'NetworkID', 'ZoneFile', 'NotifyServers',
        'ExportFile', 'SecondaryZoneName', 'SecondaryZoneFile', 'MasterServers',
        'StubZoneName', 'StubMasterServers', 'ForwarderDomain', 'ForwarderServers',
        'ForwarderTimeout', 'ParentZone', 'ChildZone', 'ChildNS', 'ChildIPs',
        'RecordName', 'RecordIPv4', 'AliasName', 'CNameTarget', 'MailServer',
        'Preference', 'ScavengingInterval'
    )
     
    foreach ($varName in $scriptVariables) {
        $variable = Get-Variable -Name $varName -Scope Script -ErrorAction SilentlyContinue
        if ($variable -and $null -ne $variable.Value) {
            $global:setVariables += $varName
        } else {
            $global:unsetVariables += $varName 
        }
    }
}

function Reset-UnsetVariables {
    [CmdletBinding()]
    param()
        
    foreach ($varName in $global:unsetVariables) {
        Set-Variable -Name $varName -Scope Script -Value $null -ErrorAction SilentlyContinue   
    }
}

#endregion

#region ErrorsAndWarnings

function ErrorsAndWarnings {
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$false)]
        [array]$errors = @(),
        
        [Parameter(Mandatory=$false)]
        [array]$warnings = @()  
    )

    Write-Host ""
    if ($errors.Count -gt 0) {
        Write-Host "[ERRORS] ($($errors.Count))" -ForegroundColor Red -BackgroundColor Black
        foreach ($e in $errors) { Write-Host "  - $e" -ForegroundColor Red -BackgroundColor Black }
        Write-Host ""   
    }

    if ($warnings.Count -gt 0) {
        Write-Host "[WARNINGS] ($($warnings.Count))" -ForegroundColor Yellow -BackgroundColor Black
        foreach ($w in $warnings) { Write-Host "  - $w" -ForegroundColor Yellow -BackgroundColor Black }
        Write-Host ""
    }

    if ($errors.Count -ne 0) {
        Reset-UnsetVariables
        return 
    } 
}

#endregion

#region Main function

function Main {
    # check Module & Admin
    try {
        check-Module-Admin
        Get-UnsetVariables 
    }
    catch {
        Write-Host "[-] Critical initialization error: $_" -ForegroundColor Red -BackgroundColor Black
        Write-Host "[-] Exiting..." -ForegroundColor Red -BackgroundColor Black
        exit 1
    }

    # Main Menu Loop
    while ($true) {
        try {
            $option = logo-option

            $errors = @()
            $warnings = @()

            # Validate main menu option
            if ($option -notmatch '^[0-5]$') {
                Write-Host "[-] Invalid option selected. Please choose a number between 0 and 5." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Press Enter to continue..." -ForegroundColor Yellow -BackgroundColor Black
                Read-Host
                continue
            }

            if ($option -eq "5") {
                Write-Host "[+] Exiting..." -ForegroundColor Green -BackgroundColor Black
                exit 0
            }

            Write-Host "[+] Executing main menu option $option ..." -ForegroundColor Green -BackgroundColor Black

            switch ($option) {
                "0" {
                    # Configure AD from scratch - Run_Option_0_.ps1 handles all verification
                    Write-Host "[*] Configuring Active Directory from scratch..." -ForegroundColor Cyan -BackgroundColor Black
                    Write-Host "[*] Running... " -ForegroundColor Yellow -BackgroundColor Black

                    $scriptDir = Split-Path $ScriptPath -Parent
                    $Run_Option_0_Path = Get-ChildItem -Path $scriptDir -Filter "Run_Option*.ps1" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName

                    if ($Run_Option_0_Path) {
                        try {
                            Write-Host "[*] Found script: $(Split-Path $Run_Option_0_Path -Leaf)" -ForegroundColor Green -BackgroundColor Black
                            . $Run_Option_0_Path
                            Write-Host "[+] Successfully loaded Run_Option script" -ForegroundColor Green -BackgroundColor Black
                        }
                        catch {
                            Write-Host "[!] Error loading script: $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
                        }
                    } else {
                        Write-Host "[!] Run_Option script not found in $scriptDir" -ForegroundColor Red -BackgroundColor Black
                        Write-Host "[!] Looking for files matching: Run_Option*.ps1" -ForegroundColor Yellow -BackgroundColor Black
                        $availableScripts = Get-ChildItem -Path $scriptDir -Filter "*.ps1" | Select-Object -ExpandProperty Name
                        if ($availableScripts) {
                            Write-Host "[*] Available scripts: $($availableScripts -join ', ')" -ForegroundColor Cyan -BackgroundColor Black
                        }
                    }

                }

                { $_ -in "1", "2", "3", "4" } {
                    # Show sub-menu and process selection
                    while ($true) {
                        try {
                            $subOption = Show-SubMenu -MenuNumber $option
                            
                            # Validate sub-option based on menu number
                            $validSubOption = $false
                            switch ($option) {
                                "1" { if ($subOption -match '^(10|[1-9])$') { $validSubOption = $true } }
                                "2" { if ($subOption -match '^[1-4]$') { $validSubOption = $true } }
                                "3" { if ($subOption -match '^[1-4]$') { $validSubOption = $true } }
                                "4" { if ($subOption -match '^(1[0-4]|[1-9])$') { $validSubOption = $true } }
                            }

                            if (-not $validSubOption) {
                                Write-Host "[-] Invalid sub-option selected. Please choose a valid option for menu $option." -ForegroundColor Red -BackgroundColor Black
                                Write-Host "Press Enter to continue..." -ForegroundColor Yellow -BackgroundColor Black
                                Read-Host
                                continue
                            }

                            if (($subOption -eq "10" -and $option -eq "1") -or 
                                ($subOption -eq "4" -and $option -in "2", "3") -or 
                                ($subOption -eq "14" -and $option -eq "4")) { 
                                break 
                            }

                            Write-Host "[+] Executing sub-menu option $subOption for menu $option ..." -ForegroundColor Green -BackgroundColor Black

                            # Reset errors and warnings for each operation
                            $operationErrors = @()
                            $operationWarnings = @()

                            switch ($option) {
                                "1" {
                                    switch ($subOption) {
                                        "1" {
                                            try {
                                                if ($null -eq $script:Disable_CAD) {
                                                    $input = Read-Host "[+] Disable Ctrl+Alt+Del requirement? (true/false) "
                                                    if ($input -notin @('true', 'false')) {
                                                        Write-Host "Invalid input. Please enter 'true' or 'false'." -ForegroundColor Red
                                                        continue
                                                    }
                                                    $script:Disable_CAD = [bool]::Parse($input.ToLower())
                                                }
                                                Disable-CtrlAltDel -Disable $script:Disable_CAD -ErrorAction Stop -Verbose 
                                                Write-Host "[+] Ctrl+Alt+Del requirement set to $($script:Disable_CAD)" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to configure Ctrl+Alt+Del: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "2" {
                                            try {
                                                if (-not $script:TimeZone) { $script:TimeZone = Read-Host "[+] Enter timezone (e.g., UTC, Pacific Standard Time) " }
                                                Set-TimeZoneConfig -TimeZone $script:TimeZone -ErrorAction Stop -Verbose
                                                Write-Host "[+] Timezone set to $($script:TimeZone)" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to set timezone: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables
                                            }
                                        }
                                        "3" {
                                            try {
                                                if (-not $script:NewName) { $script:NewName = Read-Host "[+] Enter new computer name (e.g., DC01) " }
                                                Write-Host "[+] reboot required..." -ForegroundColor Green -BackgroundColor Black
                                                Start-Sleep -Seconds 2 
                                                Rename-ComputerSystem -Name $script:NewName -ErrorAction Stop -Verbose
                                                Write-Host "[+] Computer renamed to $($script:NewName)" -ForegroundColor Green -BackgroundColor Black 
                                            }
                                            catch {
                                                $operationErrors += "Failed to rename computer: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "4" {
                                            try {
                                                if (-not $script:IPv4 -or -not $script:Gateway4 -or -not $script:DNS4) {
                                                    if (-not $script:IPv4) { $script:IPv4 = Read-Host "[+] Enter IPv4 address (e.g., 192.168.2.10) " }
                                                    if (-not $script:Gateway4) { $script:Gateway4 = Read-Host "[+] Enter gateway (e.g., 192.168.2.1) " }
                                                    if (-not $script:DNS4) { $dnsInput = Read-Host "[+] Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4) " }
                                                    $script:DNS4 = @($dnsInput -split ',' | ForEach-Object { $_.Trim() }) 
                                                }
                                                Set-StaticIPv4 -IPv4 $script:IPv4 -Gateway $script:Gateway4 -DNS $script:DNS4 -ErrorAction Stop -Verbose
                                                Write-Host "[+] Static IPv4 configured" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to configure IPv4: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "5" {
                                            try {
                                                if (-not $script:IPv6 -or -not $script:Gateway6 -or -not $script:DNS6) {
                                                    if (-not $script:IPv6) { $script:IPv6 = Read-Host "[+] Enter IPv6 address (e.g., 2001:db8::10) " }
                                                    if (-not $script:Gateway6) { $script:Gateway6 = Read-Host "[+] Enter IPv6 gateway (e.g., 2001:db8::1) " }
                                                    if (-not $script:DNS6) { $dnsInput = Read-Host "[+] Enter IPv6 DNS servers (e.g., 2001:4860:4860::8888) " }
                                                    $script:DNS6 = @($dnsInput -split ',' | ForEach-Object { $_.Trim() })
                                                }
                                                Set-StaticIPv6 -IPv6 $script:IPv6 -Gateway $script:Gateway6 -DNS $script:DNS6 -ErrorAction Stop -Verbose
                                                Write-Host "[+] Static IPv6 configured" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to configure IPv6: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "6" {
                                            try {
                                                Disable-IPv6 -ErrorAction Stop -Verbose
                                                Write-Host "[+] IPv6 disabled" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to disable IPv6: $($_.Exception.Message)"
                                            }
                                        }
                                        "7" {
                                            try {
                                                Test-SystemReadiness -ErrorAction Stop
                                                Write-Host "[+] Starting Windows updates" -ForegroundColor Green -BackgroundColor Black
                                                Update-WindowsSystem -ErrorAction Stop -Verbose
                                              
                                            }
                                            catch {
                                                $operationErrors += "Failed to update system: $($_.Exception.Message)"
                                            }
                                        }
                                        "8" {
                                            try {
                                                Enable-RemoteDesktop -ErrorAction Stop -Verbose
                                                Write-Host "[+] RDP enabled" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to enable RDP: $($_.Exception.Message)"
                                            }
                                        }
                                        "9" {
                                            try {
                                                if ($null -eq $script:Disable_Startup) {
                                                    $input = Read-Host "[+] Disable Server Manager startup? (true/false) "
                                                    if ($input -notin @('true', 'false')) {
                                                        Write-Host "Invalid input. Please enter 'true' or 'false'." -ForegroundColor Red -BackgroundColor Black
                                                        continue
                                                    }
                                                    $script:Disable_Startup = [bool]::Parse($input.ToLower())
                                                }
                                                Set-ServerManagerStartup -Disable $script:Disable_Startup -ErrorAction Stop -Verbose
                                                Write-Host "[+] Server Manager startup set to $($script:Disable_Startup)" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to configure Server Manager: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables
                                            }
                                        }
                                    }
                                }
                                "2" {
                                    switch ($subOption) {
                                        "1" {
                                            try {
                                                if (-not $script:DomainName -or -not $script:NetbiosName -or -not $script:SafeModePassword) {
                                                    $script:DomainName = Read-Host "[+] Enter domain name (e.g., test.local) "
                                                    $script:NetbiosName = Read-Host "[+] Enter NetBIOS name (e.g., TEST) "
                                                    $script:SafeModePassword = Read-Host "[+] Enter Safe Mode password " -AsSecureString 
                                                }
                                                Install-CustomADForest -DomainName $script:DomainName -NetbiosName $script:NetbiosName -SafeModePassword $script:SafeModePassword -ErrorAction Stop -Verbose
                                                Write-Host "[+] Active Directory forest created with domain $($script:DomainName)" -ForegroundColor Green -BackgroundColor Black
                                                Write-Host "Rebooting to apply changes..." -ForegroundColor Green -BackgroundColor Black
                                                Start-Sleep -Seconds 5
                                                Restart-Computer -Force 
                                            }
                                            catch {
                                                $operationErrors += "Failed to install AD forest: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "2" {
                                            try {
                                                if (-not $script:Random_User_Name -or -not $script:Count -or -not $script:Random_User_Password) {
                                                    if (-not $script:Random_User_Name) { $script:Random_User_Name = Read-Host "[+] Enter base user name (e.g., TestUser) " }
                                                    if (-not $script:Count) { $script:Count = Read-Host "[+] Enter number of users to create (e.g., 10) " }
                                                    if (-not $script:Random_User_Password) { $script:Random_User_Password = Read-Host "[+] Enter user password " -AsSecureString }
                                                }
                                                
                                                if (-not $script:OuName) { $script:OuName = Read-Host "[+] Enter OU name (optional, press Enter for 'Random_Users') " } 
                                                if (-not $script:Random_User_Enabled ) { $script:Random_User_Enabled = Read-Host "[+] Enable users? (true/false, optional, press Enter to skip) " } 
                                                if (-not $script:Random_User_Description ) { $script:Random_User_Description = Read-Host "[+] Enter user description (optional, press Enter to skip) " } 
                                                if (-not $script:Random_User_ChangePasswordAtLogon ) { $script:Random_User_ChangePasswordAtLogon = Read-Host "[+] Force password change at logon? (true/false, optional, press Enter to skip) " } 
                                                    
                                                $params = @{
                                                    Name = $script:Random_User_Name
                                                    Count = $script:Count
                                                    Password = $script:Random_User_Password
                                                }

                                                if (-not [string]::IsNullOrWhiteSpace($script:OuName)) {
                                                    $params.Add("OuName", $script:OuName)
                                                }

                                                $boolValue = $null
                                                if (-not [string]::IsNullOrWhiteSpace($script:Random_User_Enabled) -and [bool]::TryParse($script:Random_User_Enabled, [ref]$boolValue)) {
                                                    $params.Add("Enabled", $boolValue)
                                                }

                                                if (-not [string]::IsNullOrWhiteSpace($script:Random_User_Description)) {
                                                    $params.Add("Description", $script:Random_User_Description)
                                                }

                                                $boolValue = $null
                                                if (-not [string]::IsNullOrWhiteSpace($script:Random_User_ChangePasswordAtLogon) -and [bool]::TryParse($script:Random_User_ChangePasswordAtLogon, [ref]$boolValue)) {
                                                    $params.Add("ChangePasswordAtLogon", $boolValue)
                                                }

                                                New-RandomADUser @params -ErrorAction Stop -Verbose
                                                Write-Host "[+] $($script:Count) random AD users created in OU: $($script:OuName)" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to create random AD users: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "3" {
                                            try {
                                                if (-not $script:CsvPath -or -not $script:Csv_User_Password ) {
                                                    if (-not $script:CsvPath) { $script:CsvPath = Read-Host "[+] Enter CSV file path (e.g., C:\AD\users.csv) " }
                                                    if (-not $script:Csv_User_Password) { $script:Csv_User_Password = Read-Host "[+] Enter user password " -AsSecureString }
                                                }
                                                
                                                if (-not $script:Csv_User_Enabled) { $script:Csv_User_Enabled = Read-Host "[+] Enable users? (true/false, optional, press Enter to skip) " }
                                                if (-not $script:Csv_User_ChangePasswordAtLogon) { $script:Csv_User_ChangePasswordAtLogon = Read-Host "[+] Change password at logon? (true/false, optional, press Enter to skip) " }

                                                if (-not (Test-Path $script:CsvPath)) {
                                                    $operationErrors += "CSV file does not exist: $script:CsvPath"
                                                }

                                                if ($script:Csv_User_Enabled -and $script:Csv_User_Enabled -notmatch '^(true|false)$') {
                                                    $operationWarnings += "Invalid 'Enable users' value: '$script:Csv_User_Enabled'. Expected 'true' or 'false'. Defaulting to true."
                                                    $script:Csv_User_Enabled = $null
                                                }
                
                                                if ($script:Csv_User_ChangePasswordAtLogon -and $script:Csv_User_ChangePasswordAtLogon -notmatch '^(true|false)$') {
                                                    $operationWarnings += "Invalid 'Change password at logon' value: '$script:Csv_User_ChangePasswordAtLogon'. Expected 'true' or 'false'. Defaulting to true."
                                                    $script:Csv_User_ChangePasswordAtLogon = $null
                                                }

                                                ErrorsAndWarnings -errors $operationErrors -warnings $operationWarnings
                                                $params = @{
                                                    CsvPath = $script:CsvPath
                                                    Password = $script:Csv_User_Password
                                                }
                                                if ($script:Csv_User_Enabled -and $script:Csv_User_Enabled -in @('true', 'false')) { 
                                                    $params.Add("Enabled", [bool]::Parse($script:Csv_User_Enabled.ToLower())) 
                                                }
                                                if ($script:Csv_User_ChangePasswordAtLogon -and $script:Csv_User_ChangePasswordAtLogon -in @('true', 'false')) { 
                                                    $params.Add("ChangePasswordAtLogon", [bool]::Parse($script:Csv_User_ChangePasswordAtLogon.ToLower())) 
                                                }

                                                if ( Test-CsvContent -CsvPath $script:CsvPath ) {                                    
                                                    Import-CsvADUser @params -ErrorAction Stop -Verbose 
                                                    Write-Host "[+] AD users created from CSV at $($script:CsvPath)" -ForegroundColor Green -BackgroundColor Black 
                                                }
                                            }
                                            catch {
                                                $operationErrors += "Failed to import CSV users: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables
                                            }
                                        }
                                    }
                                }
                                "3" {
                                    switch ($subOption) {
                                        "1" {
                                            try {
                                                if (-not $script:DhcpServerName -or -not $script:DhcpServerIP) {
                                                    $script:DhcpServerName = Read-Host "[+] Enter DHCP server name (e.g., dhcp01.test.local, optional, press Enter to skip) "
                                                    $script:DhcpServerIP = Read-Host "[+] Enter DHCP server IP (e.g., 192.168.2.10, optional, press Enter to skip) "
                                                }
                                                $params = @{}
                                                if ($script:DhcpServerName) { $params.Add("DhcpServerName", $script:DhcpServerName) }
                                                if ($script:DhcpServerIP) { $params.Add("DhcpServerIP", $script:DhcpServerIP) }
                                                Install-DhcpAndAuthorize @params -ErrorAction Stop -Verbose
                                                Write-Host "[+] DHCP server installed and authorized" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to install DHCP: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables
                                            }
                                        }
                                        "2" {
                                            try {
                                                if (-not $script:ScopeName -or -not $script:StartRange -or -not $script:EndRange) {
                                                    $script:ScopeName = Read-Host "[+] Enter DHCP scope name (e.g., OfficeScope) "
                                                    $script:StartRange = Read-Host "[+] Enter start range (e.g., 192.168.2.50) "
                                                    $script:EndRange = Read-Host "[+] Enter end range (e.g., 192.168.2.100) "
                                                    $script:SubnetMask = Read-Host "[+] Enter subnet mask (e.g., 255.255.255.0, optional, press Enter to skip) "
                                                    $script:LeaseDuration = Read-Host "[+] Enter lease duration in days (e.g., 8, optional, press Enter to skip) "
                                                    $script:State = Read-Host "[+] Enter scope state (Active/Inactive, optional, press Enter to skip) "
                                                    $script:Description = Read-Host "[+] Enter scope description (optional, press Enter to skip) "
                                                }
                                                $params = @{
                                                    ScopeName = $script:ScopeName
                                                    StartRange = $script:StartRange
                                                    EndRange = $script:EndRange
                                                }
                                                if ($script:SubnetMask) { $params.Add("SubnetMask", $script:SubnetMask) }
                                                if ($script:LeaseDuration) { $params.Add("LeaseDuration", (New-TimeSpan -Days ([int]$script:LeaseDuration))) }
                                                if ($script:State) { $params.Add("State", $script:State) }
                                                if ($script:Description) { $params.Add("Description", $script:Description) }
                                                New-Dhcp4Scope @params -ErrorAction Stop -Verbose
                                                Write-Host "[+] DHCP IPv4 scope $($script:ScopeName) created" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to create DHCP scope: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "3" {
                                            try {
                                                Write-Host "[-] DHCP Reservations not implemented in this script. Please configure manually." -ForegroundColor Yellow -BackgroundColor Black

                                            }
                                            catch {
                                                $operationErrors += "Error displaying DHCP reservations info: $($_.Exception.Message)"
                                            }
                                        }
                                    }
                                }
                                "4" {
                                    switch ($subOption) {
                                        "1" {
                                            try {
                                                if (-not $script:ZoneName -or -not $script:ComputerName) {
                                                    $script:ZoneName = Read-Host "[+] Enter DNS zone name (e.g., corp.local) "
                                                    $script:ComputerName = Read-Host "[+] Enter computer name (e.g., DC01) "
                                                }
                                                Add-DnsPrimaryForwardZone -ZoneName $script:ZoneName -ComputerName $script:ComputerName -ErrorAction Stop -Verbose
                                                Write-Host "[+] Primary forward DNS zone $($script:ZoneName) created" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to create DNS forward zone: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "2" {
                                            try {
                                                if (-not $script:NetworkID) {
                                                    $script:NetworkID = Read-Host "[+] Enter network ID for reverse zone (e.g., 192.168.2.0/24) "
                                                }
                                                Add-DnsPrimaryReverseZone -NetworkID $script:NetworkID -ErrorAction Stop -Verbose
                                                Write-Host "[+] Primary reverse DNS zone for $($script:NetworkID) created" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to create DNS reverse zone: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables
                                            }
                                        }
                                        "3" {
                                            try {
                                                if (-not $script:ZoneName -or -not $script:ZoneFile) {
                                                    $script:ZoneName = Read-Host "[+] Enter DNS zone name (e.g., corp.local) "
                                                    $script:ZoneFile = Read-Host "[+] Enter zone file name (e.g., corp.local.dns) "
                                                }
                                                Add-DnsFileBasedZone -ZoneName $script:ZoneName -ZoneFile $script:ZoneFile -ErrorAction Stop -Verbose
                                                Write-Host "[+] File-based DNS zone $($script:ZoneName) created" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to create file-based DNS zone: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables
                                            }
                                        }
                                        "4" {
                                            try {
                                                if (-not $script:ZoneName -or -not $script:NotifyServers) {
                                                    $script:ZoneName = Read-Host "[+] Enter DNS zone name (e.g., corp.local) "
                                                    $script:NotifyServers = Read-Host "[+] Enter notify servers (e.g., 192.168.2.11) "
                                                }
                                                Set-DnsZoneNotification -ZoneName $script:ZoneName -NotifyServers $script:NotifyServers -ErrorAction Stop -Verbose
                                                Write-Host "[+] DNS zone notifications configured for $($script:ZoneName)" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to configure DNS notifications: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables
                                            }
                                        }
                                        "5" {
                                            try {
                                                if (-not $script:ZoneName -or -not $script:ExportFile) {
                                                    $script:ZoneName = Read-Host "[+] Enter DNS zone name (e.g., corp.local) "
                                                    $script:ExportFile = Read-Host "[+] Enter export file path (e.g., C:\DNS\corp.local.dns) "
                                                }
                                                Export-DnsZone -ZoneName $script:ZoneName -ExportFile $script:ExportFile -ErrorAction Stop -Verbose
                                                Write-Host "[+] DNS zone $($script:ZoneName) exported to $($script:ExportFile)" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to export DNS zone: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "6" {
                                            try {
                                                if (-not $script:SecondaryZoneName -or -not $script:SecondaryZoneFile -or -not $script:MasterServers) {
                                                    $script:SecondaryZoneName = Read-Host "[+] Enter secondary zone name (e.g., corp.local) "
                                                    $script:SecondaryZoneFile = Read-Host "[+] Enter secondary zone file name (e.g., corp.local.dns) "
                                                    $masterInput = Read-Host "[+] Enter master servers (comma-separated, e.g., 192.168.2.10) "
                                                    $script:MasterServers = @($masterInput -split ',' | ForEach-Object { $_.Trim() })
                                                }
                                                Add-DnsSecondaryZone -ZoneName $script:SecondaryZoneName -ZoneFile $script:SecondaryZoneFile -MasterServers $script:MasterServers -ErrorAction Stop -Verbose
                                                Write-Host "[+] Secondary DNS zone $($script:SecondaryZoneName) created" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to create secondary DNS zone: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "7" {
                                            try {
                                                if (-not $script:StubZoneName -or -not $script:StubMasterServers) {
                                                    $script:StubZoneName = Read-Host "[+] Enter stub zone name (e.g., corp.local) "
                                                    $stubInput = Read-Host "[+] Enter master servers (comma-separated, e.g., 192.168.2.10) "
                                                    $script:StubMasterServers = @($stubInput -split ',' | ForEach-Object { $_.Trim() })
                                                }
                                                Add-DnsStubZone -ZoneName $script:StubZoneName -MasterServers $script:StubMasterServers -ErrorAction Stop -Verbose
                                                Write-Host "[+] Stub DNS zone $($script:StubZoneName) created" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to create stub DNS zone: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables
                                            }
                                        }
                                        "8" {
                                            try {
                                                if (-not $script:ForwarderDomain -or -not $script:ForwarderServers) {
                                                    $script:ForwarderDomain = Read-Host "[+] Enter forwarder domain (e.g., partner.local) "
                                                    $forwarderInput = Read-Host "[+] Enter forwarder servers (comma-separated, e.g., 192.168.3.10) "
                                                    $script:ForwarderServers = @($forwarderInput -split ',' | ForEach-Object { $_.Trim() })
                                                    $script:ForwarderTimeout = Read-Host "[+] Enter forwarder timeout in seconds (e.g., 5, optional, press Enter to skip) "
                                                }
                                                $params = @{
                                                    ForwarderDomain = $script:ForwarderDomain
                                                    ForwarderServers = $script:ForwarderServers
                                                }
                                                if ($script:ForwarderTimeout) { $params.Add("ForwarderTimeout", ([int]$script:ForwarderTimeout)) }
                                                Add-DnsConditionalForwarder @params -ErrorAction Stop -Verbose
                                                Write-Host "[+] Conditional forwarder for $($script:ForwarderDomain) configured" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to configure conditional forwarder: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "9" {
                                            try {
                                                if (-not $script:ParentZone -or -not $script:ChildZone -or -not $script:ChildNS -or -not $script:ChildIPs) {
                                                    $script:ParentZone = Read-Host "[+] Enter parent zone (e.g., corp.local) "
                                                    $script:ChildZone = Read-Host "[+] Enter child zone (e.g., dev.corp.local) "
                                                    $childNsInput = Read-Host "[+] Enter child name servers (comma-separated, e.g., ns1.dev.corp.local) "
                                                    $script:ChildNS = @($childNsInput -split ',' | ForEach-Object { $_.Trim() })
                                                    $childIpInput = Read-Host "[+] Enter child IPs (comma-separated, e.g., 192.168.4.10) "
                                                    $script:ChildIPs = @($childIpInput -split ',' | ForEach-Object { $_.Trim() })
                                                }
                                                Add-DnsZoneDelegation -ParentZone $script:ParentZone -ChildZone $script:ChildZone -ChildNS $script:ChildNS -ChildIPs $script:ChildIPs -ErrorAction Stop -Verbose
                                                Write-Host "[+] DNS zone delegation for $($script:ChildZone) configured" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to configure DNS delegation: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "10" {
                                            try {
                                                if (-not $script:ZoneName -or -not $script:RecordName -or -not $script:RecordIPv4) {
                                                    $script:ZoneName = Read-Host "[+] Enter DNS zone name (e.g., corp.local) "
                                                    $script:RecordName = Read-Host "[+] Enter record name (e.g., web01) "
                                                    $script:RecordIPv4 = Read-Host "[+] Enter IPv4 address (e.g., 192.168.2.200) "
                                                }
                                                Add-DnsARecord -ZoneName $script:ZoneName -RecordName $script:RecordName -IPv4Address $script:RecordIPv4 -ErrorAction Stop -Verbose
                                                Write-Host "[+] A record $($script:RecordName) created in $($script:ZoneName)" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to create A record: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "11" {
                                            try {
                                                if (-not $script:ZoneName -or -not $script:AliasName -or -not $script:CNameTarget) {
                                                    $script:ZoneName = Read-Host "[+] Enter DNS zone name (e.g., corp.local) "
                                                    $script:AliasName = Read-Host "[+] Enter alias name (e.g., www) "
                                                    $script:CNameTarget = Read-Host "[+] Enter CNAME target (e.g., web01.corp.local) "
                                                }
                                                Add-DnsCnameRecord -ZoneName $script:ZoneName -AliasName $script:AliasName -CNameTarget $script:CNameTarget -ErrorAction Stop -Verbose
                                                Write-Host "[+] CNAME record $($script:AliasName) created in $($script:ZoneName)" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to create CNAME record: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "12" {
                                            try {
                                                if (-not $script:ZoneName -or -not $script:MailServer) {
                                                    $script:ZoneName = Read-Host "[+] Enter DNS zone name (e.g., corp.local) "
                                                    $script:MailServer = Read-Host "[+] Enter mail server (e.g., mail.corp.local) "
                                                    $script:Preference = Read-Host "[+] Enter preference (e.g., 10, optional, press Enter to skip) "
                                                }
                                                $params = @{
                                                    ZoneName = $script:ZoneName
                                                    MailServer = $script:MailServer
                                                }
                                                if ($script:Preference) { $params.Add("Preference", ([int]$script:Preference)) }
                                                Add-DnsMxRecord @params -ErrorAction Stop -Verbose
                                                Write-Host "[+] MX record for $($script:MailServer) created in $($script:ZoneName)" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to create MX record: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                        "13" {
                                            try {
                                                if (-not $script:ZoneName -or -not $script:ScavengingInterval) {
                                                    $script:ZoneName = Read-Host "[+] Enter DNS zone name (e.g., corp.local) "
                                                    $script:ScavengingInterval = Read-Host "[+] Enter scavenging interval in days (e.g., 7) "
                                                }
                                                Enable-DnsScavenging -ZoneName $script:ZoneName -ScavengingInterval (New-TimeSpan -Days ([int]$script:ScavengingInterval)) -ErrorAction Stop -Verbose
                                                Write-Host "[+] DNS scavenging enabled for $($script:ZoneName)" -ForegroundColor Green -BackgroundColor Black
                                            }
                                            catch {
                                                $operationErrors += "Failed to enable DNS scavenging: $($_.Exception.Message)"
                                            }
                                            finally {
                                                Reset-UnsetVariables 
                                            }
                                        }
                                    }
                                }
                            }

                            # Display operation results
                            if ($operationErrors.Count -gt 0 -or $operationWarnings.Count -gt 0) {
                                ErrorsAndWarnings -errors $operationErrors -warnings $operationWarnings
                            }

                        }
                        catch {
                            Write-Host "[-] Unexpected error in sub-menu processing: $_" -ForegroundColor Red -BackgroundColor Black
                            $errors += "Sub-menu processing error: $($_.Exception.Message)"
                        }

                        Write-Host "Press Enter to continue..." -ForegroundColor Yellow -BackgroundColor Black
                        Read-Host
                    }
                }
            }
        }
        catch {
            Write-Host "[-] Unexpected error in main menu: $_" -ForegroundColor Red -BackgroundColor Black
            $errors += "Main menu error: $($_.Exception.Message)"
            ErrorsAndWarnings -errors $errors -warnings $warnings
        }

        Write-Host "Press Enter to continue..." -ForegroundColor Yellow -BackgroundColor Black
        Read-Host
    }
}

#endregion

# Start the main execution
Main










