<#
.SYNOPSIS
    Automated configuration script for Windows Server with Active Directory, DHCP, DNS, and network settings.

.DESCRIPTION
    This script provides an automated sequential task execution system to configure Windows Server
    with network settings, system optimizations, Active Directory Domain Services, DHCP, DNS,
    and user creation from CSV. Features automatic reboot handling and resume capability.

.CONFIGURATION
 
    1. Edit the "Config Parameter" section in this script (lines ~50-200)
    2. Set the desired variables with your configuration values
    3. Examples:
       - $DomainName = "company.local"
       - $IPv4 = "192.168.1.10"
       - $NewName = "DC01"

    4. Leave optionale variables as `$null` if you want to use defaults

.AUTO-EXECUTION FEATURES
    - Sequential task execution with progress tracking
    - Automatic reboot handling between tasks
    - Resume capability after reboots
    - Comprehensive logging and reporting
    - Configuration validation before execution

.TASK SEQUENCE
    1.  Disable Ctrl+Alt+Del requirement
    2.  Set system timezone
    3.  Configure static IPv4 address
    4.  Disable IPv6
    5.  Configure Server Manager startup behavior
    6.  Enable Remote Desktop
    7.  Rename computer (requires reboot)
    8.  Update Windows system (requires reboot)
    9.  Install AD DS and create forest (requires reboot)
    10. Install and configure DHCP server (requires reboot)
    11. Create DNS reverse lookup zone
    12. Import AD users from CSV file

.USAGE
    .\Run_Option_0_.ps1 

.EXAMPLE
    # Pre-configured mode (edit script variables first)
    # Set $DomainName, $IPv4, $NewName, etc. then run:
    .\Server-config.ps1 chiose the Option "0" 
    
    # or Run directly 
    .\Run_Option_0_.ps1  

.NOTES
    - Requires Administrator privileges
    - Requires ADConf-Module.psm1 in the same directory
    - Some operations require system reboot (handled automatically)
    - Test in non-production environment first
    - Comprehensive logs saved to Repo directory
    - Automatic report generation upon completion

.AUTHOR
    Name: Yasser-Janboubi 
    GitHub: Y-Janboubi

#>

param(
    [int]$TaskNumber = 0,
    [string]$ScriptPath = $PSCommandPath
)


#region Display Logo

function Show-Conflogo {
    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚════════════════════════════════ [ AUTO-CONF ] ═══════════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "     █████╗ ██╗   ██╗████████╗ ██████╗        ██████╗ ██████╗ ███╗   ██╗███████╗    " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗      ██╔════╝██╔═══██╗████╗  ██║██╔════╝    " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "    ███████║██║   ██║   ██║   ██║   ██║█████╗██║     ██║   ██║██╔██╗ ██║█████╗      " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "    ██╔══██║██║   ██║   ██║   ██║   ██║╚════╝██║     ██║   ██║██║╚██╗██║██╔══╝      " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝      ╚██████╗╚██████╔╝██║ ╚████║██║         " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝        ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝         " -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚════════════════════ Active Directory & Network Configuration ════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan -BackgroundColor Black
}

#endregion

#region Config Parameter 

#==========================================================================
# CONFIGURATION PARAMETERS - SET VALUES BELOW AS NEEDED
#==========================================================================
#
# Set the values for your specific environment below
# Most parameters are required - only optional ones can be left as $null
# 
# Examples: 
#   $DomainName = "company.local"    # ← Required parameter
#   $Description = $null             # ← Optional parameter (uses default)
#
# WARNING: Leaving required parameters as $null will cause script to fail
# during configuration validation check.
#==========================================================================



# ================== SYSTEM / NETWORK CONFIG ==================

# 1) Enables or disables Ctrl+Alt+Del secure logon requirement
$Disable_CAD = $true  # Example: $true (disable CAD) or $false (enable CAD)

# 2) Sets system timezone
$TimeZone = "Morocco Standard Time"  # Example: "UTC" or "Morocco Standard Time"

# 3) Renames the local computer
$NewName = "test-it"  # Example: "DC01"

# 4) Configures static IPv4 address, gateway, and DNS servers
$IPv4 = "192.168.2.10"  # Example: "192.168.2.10"
$Gateway4 = "192.168.2.2"  # Example: "192.168.2.1"
$DNS4 = "192.168.2.2"  # Example: "8.8.8.8"

# 5) Configures Server Manager startup behavior
$Disable_Startup = $true  # Example: $true (disable Server Manager) or $false (enable Server Manager)

# ===================== ACTIVE DIRECTORY ======================

# 1) Installs AD DS and creates a new AD forest
$DomainName = "test.com"  # Example: "test.local"
$NetbiosName = "TEST"  # Example: "TEST"
$SafeModePassword = "Password123!"  # Example: "Password123!"


# 2) Creates OUs, groups, and users from a CSV file
$CsvPath = "C:\Users\Administrator\Desktop\Ad-Conf\AD-Object.csv"  # Example: "C:\AD\users.csv"
$Csv_User_Password = "P@ssw0rd"  # Example:"Pass@123"
$Csv_User_Enabled = $null  # Optional: $true (enable users) or $false (disable users)
$Csv_User_ChangePasswordAtLogon = $null  # Optional: $true or $false

# =========================== DHCP ============================

# 3) Installs, authorizes and Creates a new DHCP IPv4 scope 

$DhcpServerName = $null  # Optional: Example: "dhcp01.test.local"
$DhcpServerIP = $null  # Optional: Example: "192.168.2.10"
$ScopeName = "main_dhcp"  # Example: "OfficeScope"
$StartRange = "192.168.2.50"  # Example: "192.168.2.50"
$EndRange = "192.168.2.100"  # Example: "192.168.2.100"
$SubnetMask = $null  # Optional: Example: "255.255.255.0"
$LeaseDuration = $null # Optional: Example: (New-TimeSpan -Days 8)
$State = $null  # Optional: Example: "Active" or "Inactive"
$Description = $null  # Optional: Example: "Main Office Scope"


# =========================== DNS =============================

# 1) Creates a primary reverse DNS zone
$NetworkID = "192.168.2.0/24"  # Example: "192.168.2.0/24"

#endregion

#region Check Configuration Parameters
function Test-IPv4 {
    param([string]$Address)

    try {
        $ip = [System.Net.IPAddress]::Parse($Address)

        # Must be IPv4
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            return $false
        }

        $octets = $ip.GetAddressBytes()

        # Exclude reserved / unusable ranges
        switch -regex ($Address) {
            '^0\.'              { return $false } # "This network"
            '^169\.254\.'       { return $false } # APIPA
            '^224\.|^240\.|^255\.' { return $false } # Multicast & reserved
        }

        # Reject network (.0) and broadcast (.255) addresses
        if ($octets[3] -eq 0 -or $octets[3] -eq 255) {
            return $false
        }

        return $true
    } catch {
        return $false
    }
}
function Check-Config {
    Write-Host "[*] Checking configuration parameters..." -ForegroundColor Green -BackgroundColor Black

    $errors = @()
    $warnings = @()

    # ================== SYSTEM / NETWORK CONFIG ================== #

#region 1) Check Ctrl+Alt+Del secure logon requirement

    if ($null -eq $Disable_CAD) {
        $errors += "Disable_CAD is not set. Please specify `$true` to disable or `$false` to enable Ctrl+Alt+Del."
    } elseif ($Disable_CAD -isnot [bool]) {
        $errors += "Disable_CAD must be a boolean value (`$true` or `$false`)."
    }

#endregion

#region 2) Check system timezone

    if ($null -eq $TimeZone) {
        $errors += "TimeZone is not set. Please specify a valid timezone (e.g., 'UTC' or 'Morocco Standard Time')."
    } else {
        try {
            Get-TimeZone -Id $TimeZone -ErrorAction Stop | Out-Null
        } catch {
            $errors += "Invalid TimeZone: '$TimeZone'. Please specify a valid timezone ID."
        }
    }

#endregion
   
#region 3) Check computer name

    if ($null -eq $NewName) {
        $errors += "NewName is not set. Please specify a valid computer name (e.g., 'DC01')."
    } elseif ($NewName -notmatch '^(?!-)(?!.*-$)(?![0-9]+$)[a-zA-Z0-9-]{1,15}$') {
        $errors += "NewName '$NewName' is invalid. Must be 1–15 chars, alphanumeric or hyphen, cannot start/end with hyphen, cannot be all numbers."
    }

#endregion

#region 4) Check IPv4 configuration
    if ($null -eq $IPv4) {
        $errors += "IPv4 is not set. Please specify a valid IPv4 address (e.g., '192.168.2.10')."
    } elseif (-not (Test-IPv4 $IPv4)) {
        $errors += "IPv4 '$IPv4' is invalid or unusable."
    }
    
    if ($null -eq $Gateway4) {
        $errors += "Gateway4 is not set. Please specify a valid IPv4 gateway (e.g., '192.168.2.1')."
    } elseif (-not (Test-IPv4 $Gateway4)) {
        $errors += "Gateway4 '$Gateway4' is invalid."
    } 

    if ($null -eq $DNS4) {
        $errors += "DNS4 is not set. Please specify a valid DNS server address (e.g., '8.8.8.8')."
    }elseif (-not (Test-IPv4 $DNS4)) {
        $errors += "DNS4 '$DNS4' is invalid."
    } 
#endregion

#region 5) Check Server Manager startup behavior

    if ($null -eq $Disable_Startup) {
        $errors += "Disable_Startup is not set. Please specify `$true` to disable or `$false` to enable Server Manager."
    } elseif ($Disable_Startup -isnot [bool]) {
        $errors += "Disable_Startup must be a boolean value (`$true` or `$false`)."
    }

#endregion

    # ===================== ACTIVE DIRECTORY ======================

#region 1) Check AD DS forest creation parameters

    # DomainName
    if ($null -eq $DomainName) {
    $errors += "DomainName is not set. Please specify a valid domain name (e.g., 'test.local')."
    } elseif ($DomainName -notmatch '^(?!-)(?!.*-\.)[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$') {
        $errors += "DomainName '$DomainName' is invalid. Must be a valid FQDN with proper labels."
    }



    # NetbiosName
    if ($null -eq $NetbiosName) {
        $errors += "NetbiosName is not set. Please specify a valid NetBIOS name (e.g., 'TEST')."
    } elseif ($NetbiosName -notmatch '^(?!-)(?!.*-$)(?![0-9]+$)[a-zA-Z0-9-]{1,15}$') {
        $errors += "NetbiosName '$NetbiosName' is invalid. Must be 1–15 chars, alphanumeric or hyphen, cannot start/end with hyphen, cannot be all numbers."
    }

    # SafeModePassword
    if ($null -eq $SafeModePassword) {
        $errors += "SafeModePassword is not set. Please specify a valid safe mode password."
    } elseif ($SafeModePassword.Length -lt 8) {
        $errors += "SafeModePassword is too short. Must be at least 8 characters."
    } elseif ($SafeModePassword -notmatch '[A-Z]') {
        $errors += "SafeModePassword must include at least one uppercase letter."
    } elseif ($SafeModePassword -notmatch '[a-z]') {
        $errors += "SafeModePassword must include at least one lowercase letter."
    } elseif ($SafeModePassword -notmatch '\d') {
        $errors += "SafeModePassword must include at least one number."
    } elseif ($SafeModePassword -notmatch '[^a-zA-Z0-9]') {
        $errors += "SafeModePassword must include at least one special character."
    }

#endregion

#region 2) Check AD user creation from CSV
    
    # Csv Path 
    if ($null -eq $CsvPath) {
        $errors += "CsvPath is not set. Please specify a valid path to the CSV file (e.g., 'C:\AD\users.csv')."
    } elseif (-not (Test-Path $CsvPath -PathType Leaf -ErrorAction SilentlyContinue)) {
        $errors += "CsvPath '$CsvPath' does not exist or is not a valid file."
    } elseif (-not (Test-CsvContent -CsvPath $CsvPath)) {
        $errors += "CsvPath '$CsvPath' exists but does not contain valid CSV data."
    }

     # Csv User Password
    if ($null -eq $Csv_User_Password) {
        $errors += "Csv_User_Password is not set. Please specify a default password for CSV users."
    } 
    elseif ($Csv_User_Password.Length -lt 8) {
        $errors += "Csv_User_Password is too short. Must be at least 8 characters."
    } 
    elseif ($Csv_User_Password -notmatch '[A-Z]') {
        $errors += "Csv_User_Password must include at least one uppercase letter."
    } 
    elseif ($Csv_User_Password -notmatch '[a-z]') {
        $errors += "Csv_User_Password must include at least one lowercase letter."
    } 
    elseif ($Csv_User_Password -notmatch '\d') {
        $errors += "Csv_User_Password must include at least one number."
    } 

    # Csv User Enabled
    if ($null -eq $Csv_User_Enabled ) {
        $warnings += "Csv_User_Enabled is not set. Using default: $true "
    }elseif ( $Csv_User_Enabled -isnot [bool]) {
        $errors += "Csv_User_Enabled must be a boolean value (`$true` or `$false`)."
   }

    # Csv User ChangePassword At Logon
    if ($null -eq $Csv_User_ChangePasswordAtLogon ) {
        $warnings += "Csv_User_ChangePasswordAtLogon is not set. Using default: $true "
    }elseif ( $Csv_User_ChangePasswordAtLogon -isnot [bool]) {
        $errors += "Csv_User_ChangePasswordAtLogon must be a boolean value (`$true` or `$false`)."
    }




#endregion

    # =========================== DHCP ============================

#region 1) Check DHCP configuration

    # Dhcp Server Name
    if ($null -eq $DhcpServerName) {
        $warnings += "DhcpServerName is not set. Using local server name." 
    } elseif ($DhcpServerName -notmatch "^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$") {
        $errors += "DhcpServerName '$DhcpServerName' is invalid. Please specify a valid FQDN."
    }
    # Dhcp Server IP
    if ($null -eq $DhcpServerIP) {
        $warnings += "DhcpServerIP is not set. Using local IP address." 
    } elseif ($DhcpServerIP -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
        $errors += "DhcpServerIP '$DhcpServerIP' is invalid. Please specify a valid IPv4 address."
    }

    # Scope Name
    if ($null -eq $ScopeName) {
        $errors += "ScopeName is not set. Please specify a valid DHCP scope name (e.g., 'OfficeScope')."
    }
    
    # Start Range
    if ($null -eq $StartRange) {
        $errors += "StartRange for DHCP Scope is not set. Please specify a valid start range (e.g., '192.168.2.50')."
    } elseif ($StartRange -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
        $errors += "StartRange '$StartRange' is invalid. Please specify a valid IPv4 address."
    }
    
    # End Range
    if ($null -eq $EndRange) {
        $errors += "EndRange for DHCP Scope is not set. Please specify a valid end range (e.g., '192.168.2.100')."
    } elseif ($EndRange -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
        $errors += "EndRange '$EndRange' is invalid. Please specify a valid IPv4 address."
    }

    # Subnet Mask
    if ($null -eq $SubnetMask) {
        $warnings += "DHCP Scope SubnetMask is not set. Using default '255.255.255.0'."
    } elseif (-not (Test-IPv4 $SubnetMask)) {
        $errors += "SubnetMask '$SubnetMask' is invalid. Please specify a valid subnet mask."
    }

    # Lease Duration
    if ($null -eq $LeaseDuration ) {
        $warnings += "DHCP Scope LeaseDuration is not set. Using default: 8 days."
    }elseif ($LeaseDuration -isnot [TimeSpan]) {
        $errors += "LeaseDuration must be a valid TimeSpan object (e.g., New-TimeSpan -Days 8)."
    }

    # State
    if ($null -eq $State ) {
        $warnings += "DHCP Scope State is not set. Using default: 'Active' "
    }elseif ( $State -notin @("Active", "Inactive")) {
        $errors += "State '$State' is invalid. Please specify 'Active' or 'Inactive'."
    }

    # Description
    if ($null -eq $Description) {
        $warnings += "DHCP Scope Description is not set. No description will be applied."
    }

#endregion

    # =========================== DNS ============================= #

#region 1) Check primary reverse DNS zone
    if ($null -eq $NetworkID) {
        $errors += "NetworkID is not set. Please specify a valid network ID (e.g., '192.168.2.0/24')."
    } elseif ($NetworkID -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$") {
        $errors += "NetworkID '$NetworkID' is invalid. Please specify a valid network ID (e.g., '192.168.2.0/24')."
    }
#endregion

    # ======================= RESULTS ============================ #

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

    Write-Host "[Summary] :" -ForegroundColor Red -BackgroundColor Black
    Write-Host ("    [-] {0} error(s)" -f $errors.Count) -ForegroundColor Red -BackgroundColor Black
    Write-Host ("    [!] {0} warning(s)" -f $warnings.Count) -ForegroundColor Yellow -BackgroundColor Black

    if ($errors.Count -eq 0) {
        Write-Host "    [+] Configuration check passed" -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Host "    [!] Configuration check failed" -ForegroundColor Red -BackgroundColor Black
        exit 1
    }
    
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

#region Task Functions

function Task-1-Disable-CAD {
    Write-Log "Running Task 1: Disable Ctrl+Alt+Del requirement" -Level "INFO"
    try {
        Disable-CtrlAltDel -Disable $Disable_CAD -Verbose 
        Write-Log "Task 1 completed successfully" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Task 1 failed: $_" -Level "ERROR"
        return $false
    }
}
function Task-2-Set-Timezone {
    Write-Log "Running Task 2: Set system timezone" -Level "INFO"
    try {
        Set-TimeZoneConfig -TimeZone $TimeZone -Verbose 
        Write-Log "Task 2 completed successfully" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Task 2 failed: $_" -Level "ERROR"
        return $false
    }
}
function Task-3-Set-StaticIPv4 {
    Write-Log "Running Task 3: Set Static IPv4 " -Level "INFO"
    try {
        Set-StaticIPv4 -IPv4 $IPv4 -Gateway $Gateway4 -DNS $DNS4 -Verbose 
        Write-Log "Task 3 completed successfully" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Task 3 failed: $_" -Level "ERROR"
        return $false
    }
}
function Task-4-Disable-IPv6 {
    Write-Log "Running Task 4: Disable IPv6 " -Level "INFO"
    try {
        Disable-IPv6 -Verbose 
        Write-Log "Task 4 completed successfully" -Level "SUCCESS"
        return $true

    } catch {
        Write-Log "Task 4 failed: $_" -Level "ERROR"
        return $false
    }
}
function Task-5-DisableServerManager {
    Write-Log "Running Task 5: Configure Server Manager startup" -Level "INFO"
    try {
        Set-ServerManagerStartup -Disable $Disable_Startup -Verbose 
        Write-Log "Task 5 completed successfully" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Task 5 failed: $_" -Level "ERROR"
        return $false
    }
}
function Task-6-Enable-RemoteDesktop {
    Write-Log "Running Task 6: Enable Remote Desktop " -Level "INFO"
    try {
        Enable-RemoteDesktop -Verbose 
        Write-Log "Task 6 completed successfully" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Task 6 failed: $_" -Level "ERROR"
        return $false
    }
}
function Task-7-RenameComputer {
    Write-Log "Running Task 7: Rename computer" -Level "INFO"
    try {
        $NextTask = $global:CurrentTaskNumber + 1
        Set-Content -Path $global:FlagPath -Value $NextTask
        Write-Log "Task 7 completed, reboot required" -Level "SUCCESS"
        Write-Log "Rebooting to continue with Task $NextTask..." -Level "INFO"
        Rename-ComputerSystem -Name $NewName -Verbose

        return $true

    } catch {
        Write-Log "Task 7 failed: $_" -Level "ERROR"
        return $false
    }
}
function Task-8-Update-WindowsSystem {
    Write-Log "Running Task 8: Update Windows System " -Level "INFO"
    try {
        
        $NextTask = $global:CurrentTaskNumber + 1
        Set-Content -Path $global:FlagPath -Value $NextTask -ErrorAction Stop
        Update-WindowsSystem -Verbose 

        Write-Log "Task 8 completed, reboot required" -Level "SUCCESS"
        Write-Log "Rebooting to continue with Task $NextTask..." -Level "INFO"

        Start-Sleep -Seconds 2
        Restart-Computer -Force
        return $true

    } catch {
        Write-Log "Task 8 failed: $_" -Level "ERROR"
        return $false
    }
}
function Task-9-Install-CustomADDSForest {
    Write-Log "Running Task 9: Install AD DS and create forest" -Level "INFO"
    try {
        $NextTask = $global:CurrentTaskNumber + 1
        Set-Content -Path $global:FlagPath -Value $NextTask -ErrorAction Stop

        $pass = ConvertTo-SecureString $SafeModePassword -AsPlainText -Force
        Install-CustomADForest -DomainName $DomainName -NetbiosName $NetbiosName -SafeModePassword  $pass -Verbose
        
        Write-Log "Task 9 completed, reboot required" -Level "SUCCESS"
        Write-Log "Rebooting to continue with Task $NextTask..." -Level "INFO"
        
        Start-Sleep -Seconds 2
        Restart-Computer -Force 
        return $true
        
    } catch {
        Write-Log "Task 9 failed: $_" -Level "ERROR"
        return $false
    }
}
function Task-10-InstallDHCP {
    Write-Log "Running Task 10: Install and configure DHCP" -Level "INFO"
    try {
        
        $NextTask = $global:CurrentTaskNumber + 1
        Set-Content -Path $global:FlagPath -Value $NextTask -ErrorAction Stop
        
        Add-DhcpServer -ScopeName $ScopeName -StartRange $StartRange -EndRange $EndRange -Verbose
        
        Write-Log "Task 10 completed, reboot required" -Level "SUCCESS"
        Start-Sleep -Seconds 2
        Restart-Computer -Force 
        return $true
    } catch {
        Write-Log "Task 10 failed: $_" -Level "ERROR"
        return $false
    }
}
function Task-11-Add-DnsPrimaryReverseZone {
    Write-Log "Running Task 11: Add Dns Primary Reverse Zone" -Level "INFO"
    try {
        Add-DnsPrimaryReverseZone -NetworkID $NetworkID 
        Write-Log "Task 11 completed successfully" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Task 11 failed: $_" -Level "ERROR"
        return $false
    }
}
function Task-12-Import-ADUsersFromCSV {
    Write-Log "Running Task 12: creating AD users, groups, and OUs from CSV" -Level "INFO"
    try {
        $pass = ConvertTo-SecureString $Csv_User_Password -AsPlainText -Force
        $params = @{
            CsvPath = $CsvPath
            Password = $pass
            ErrorAction = "Stop"
        }

        if ($Csv_User_Enabled -ne $null -and $Csv_User_Enabled -is [bool]) {
            $params.Add("Enabled", $Csv_User_Enabled)
        }

        if ($Csv_User_ChangePasswordAtLogon -ne $null -and $Csv_User_ChangePasswordAtLogon -is [bool]) {
            $params.Add("ChangePasswordAtLogon", $Csv_User_ChangePasswordAtLogon)
        }

        if (Test-CsvContent -CsvPath $CsvPath) {                                    
            Import-CsvADUser @params -Verbose 
        }
        Write-Log "Task 12 completed successfully" -Level "SUCCESS" 
        return $true
    } catch {
        Write-Log "Task 12 failed: $_" -Level "ERROR"
        return $false
    }
}

# Define the task sequence
$AllTasks = @(
    { Task-1-Disable-CAD },
    { Task-2-Set-Timezone },
    { Task-3-Set-StaticIPv4 },
    { Task-4-Disable-IPv6 },
    { Task-5-DisableServerManager },
    { Task-6-Enable-RemoteDesktop },
    { Task-7-RenameComputer },
    { Task-8-Update-WindowsSystem },
    { Task-9-Install-CustomADDSForest},
    { Task-10-InstallDHCP },
    { Task-11-Add-DnsPrimaryReverseZone },
    { Task-12-Import-ADUsersFromCSV }
)

#endregion

#region ---Auto Run Main Function---

function Run-AutoConfig {
    param (
        [int]$TaskNumber = 0,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ScriptPath
    )

    #region ---Initialize global variables---
    $global:Username   = "Administrator"
    $global:Repo_Path = Join-Path $Path "Repo"
    $global:CredFile   = Join-Path $global:Repo_Path "cred.xml"
    $global:FlagPath   = Join-Path $global:Repo_Path "reboot_flag.txt"
    $global:LogFile    = Join-Path $global:Repo_Path "ServerConfig.log"
    $global:ScriptPath = $ScriptPath
    $global:CurrentTaskNumber = $TaskNumber
    $global:FailedTasks = @()
    #endregion

    #region ---Ensure Repo directory exists---
    if (-not (Test-Path $global:Repo_Path)) {
        New-Item -Path $global:Repo_Path -ItemType Directory -Force | Out-Null
        Write-Log "Created repository directory: $global:Repo_Path" -Level "INFO"
    }
    #endregion

    #region ---Get credentials---
    $global:PasswordPlain = Get-AutoLogonCredential -CredFile $global:CredFile -Username $global:Username
    #endregion

    # Resume from last task if flag exists
    if (Test-Path $global:FlagPath) {
        try {
            $TaskNumber = [int](Get-Content $global:FlagPath -ErrorAction Stop)
            $global:CurrentTaskNumber = $TaskNumber
            Write-Log "Resuming from Task $($TaskNumber + 1)..." -Level "INFO"
        } catch {
            Write-Log "Failed to read reboot_flag.txt: $_" -Level "ERROR"
            $TaskNumber = 0
            $global:CurrentTaskNumber = 0
        }
    } 
    else {
        Write-Log "Starting fresh configuration..." -Level "INFO"
    }

    # Show task status
    #Show-TaskStatus -Current $TaskNumber -Total $AllTasks.Count
    Show-TaskStatus -Current $TaskNumber -Total $AllTasks.Count -FailedIndexes $global:FailedTasks

    # Execute tasks sequentially
    for ($i = $TaskNumber; $i -lt $AllTasks.Count; $i++) {
        $global:CurrentTaskNumber = $i
        $taskName = "Task-$($i+1)"
        
        Write-Log "Executing $taskName..." -Level "INFO"
        Write-Host "`n[$($i+1)/$($AllTasks.Count)] Executing $taskName..." -ForegroundColor Cyan -BackgroundColor Black
        
        try {
            # Execute the task
            $result = & $AllTasks[$i]
            
            if ($result -eq $true) {
                Write-Log "$taskName completed successfully" -Level "SUCCESS"
                Write-Host "[+] $taskName completed successfully" -ForegroundColor Green -BackgroundColor Black
                
                # Update flag for next task
                Set-Content -Path $global:FlagPath -Value ($i + 1) -ErrorAction Stop
                
               # Enable auto-login 
               Enable-AutoLogonWithScript -ScriptPath $ScriptPath -TaskNumber ($i + 1) -Username $global:Username -PasswordPlain $global:PasswordPlain
            } 
            else {
                Write-Log "$taskName failed" -Level "ERROR"
                Write-Host "[-] $taskName failed" -ForegroundColor Red -BackgroundColor Black
                $global:FailedTasks += $i
            }
        }
        catch {
            Write-Log "$taskName failed with error: $_" -Level "ERROR"
            Write-Host "[-] $taskName failed with error: $_" -ForegroundColor Red -BackgroundColor Black
            $global:FailedTasks += $i
        }
        
        # Small delay between tasks
        Start-Sleep -Seconds 2
    }

    # Final completion check
    $completedTasks = ($AllTasks.Count - $global:FailedTasks.Count)
    $totalTasks = $AllTasks.Count
    
    if ($global:FailedTasks.Count -eq 0) {
        Write-Log "All tasks completed successfully!" -Level "SUCCESS"
        Write-Host "`n[+] All $totalTasks tasks completed successfully!" -ForegroundColor Green -BackgroundColor Black
        # Generate success report
        try {
            New-ConfigurationReport -Path $global:Repo_Path -TasksExecuted $totalTasks -Username $global:Username -LogFile $global:LogFile -SuccessfulTasks $completedTasks -FailedTaskNumbers @()
            Write-Log "Configuration report generated successfully" -Level "INFO"
        } catch {
            Write-Log "Report generation failed: $_" -Level "WARNING"
        }
    } 
    elseif ($completedTasks -gt 0) {
        Write-Host "`n[!] Configuration partially completed" -ForegroundColor Yellow -BackgroundColor Black
        Write-Host "    [+] Successfully completed: $completedTasks / $totalTasks tasks" -ForegroundColor Green -BackgroundColor Black
        Write-Host "    [-] Failed tasks: $($global:FailedTasks.Count) / $totalTasks tasks" -ForegroundColor Red -BackgroundColor Black
        
        # Show failed task numbers
        if ($global:FailedTasks.Count -gt 0) {
            $failedTaskNumbers = $global:FailedTasks | ForEach-Object { ($_ + 1) }
            Write-Host "    [-] Failed task numbers: $($failedTaskNumbers -join ', ')" -ForegroundColor Red -BackgroundColor Black
            Write-Log "Configuration completed with failures: Tasks $($failedTaskNumbers -join ', ') failed" -Level "WARNING"
        }
        
        Write-Host "    [>] Check log at $global:LogFile for detailed error information" -ForegroundColor Yellow -BackgroundColor Black
        Write-Host "    [>] Rerun the script to retry failed tasks or review configuration" -ForegroundColor Yellow -BackgroundColor Black
        
        # Generate configuration report with all details
        try {
            $failedTaskNumbersForReport = $global:FailedTasks | ForEach-Object { ($_ + 1) }
            New-ConfigurationReport -Path $global:Repo_Path -TasksExecuted $totalTasks -Username $global:Username -LogFile $global:LogFile -SuccessfulTasks $completedTasks -FailedTaskNumbers $failedTaskNumbersForReport
            Write-Log "Configuration report generated successfully" -Level "INFO"
        } catch {
            Write-Log "Report generation failed: $_" -Level "WARNING"
        }
    } else {
        Write-Log "All tasks failed! No progress made." -Level "ERROR"
        Write-Host "`n[-] All tasks failed!" -ForegroundColor Red -BackgroundColor Black
        Write-Host "    [>] Check log at $global:LogFile for detailed error information" -ForegroundColor Red -BackgroundColor Black
        Write-Host "    [>] Review configuration parameters and retry" -ForegroundColor Red -BackgroundColor Black
        
        # Generate report even for total failure
        try {
            $failedTaskNumbersForReport = $global:FailedTasks | ForEach-Object { ($_ + 1) }
            New-ConfigurationReport -Path $global:Repo_Path -TasksExecuted $totalTasks -Username $global:Username -LogFile $global:LogFile -SuccessfulTasks 0 -FailedTaskNumbers $failedTaskNumbersForReport
            Write-Log "Configuration report generated successfully" -Level "INFO"
            
        } catch {
            Write-Log "Report generation failed: $_" -Level "WARNING"
        }
    }
    
    Invoke-CleanupTask
    Write-Host "`n[*] Auto-Configuration process finished." -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "[*] Log file location: $global:LogFile" -ForegroundColor Cyan -BackgroundColor Black
    
    # Show final summary
    Write-Host "[*] FINAL SUMMARY:" -ForegroundColor Green -BackgroundColor Black
    Write-Host "    - Total Tasks: $totalTasks" -ForegroundColor White -BackgroundColor Black
    Write-Host "    - Completed: $completedTasks" -ForegroundColor Green -BackgroundColor Black
    Write-Host "    - Failed: $($global:FailedTasks.Count)" -ForegroundColor Red -BackgroundColor Black
    
    # Fixed success rate calculation - handle division by zero
    $successRate = if ($totalTasks -gt 0) { [math]::Round(($completedTasks / $totalTasks * 100), 1) } else { 0 }
    Write-Host "    - Success Rate: ${successRate}%" -ForegroundColor $(if ($completedTasks -eq $totalTasks) { "Green" } else { "Yellow" }) -BackgroundColor Black
    
    Write-Host "[*] Done" -ForegroundColor Green -BackgroundColor Black
    Write-Host ""
}

#endregion

#region ---check---

function check {
    
    # Auto-Conf logo
    Show-Conflogo

    # Check module file
    Check-Module

    # Import module
    Import-Modul

    # Check configuration
    Check-Config

    # Check privilege and internet
    Test-SystemReadiness

}

#endregion

# -----------------------------
# Execute Script
# -----------------------------

check 
Run-AutoConfig -TaskNumber $TaskNumber -Path $PSScriptRoot -ScriptPath $ScriptPath







