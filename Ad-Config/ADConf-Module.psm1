<#
============================================================================
WINDOWS SERVER ACTIVE DIRECTORY & NETWORK MANAGEMENT MODULE
============================================================================

Author:    Yasser-Janboubi
GitHub:    Y-Janboubi  
Version:   1.0

DESCRIPTION:
PowerShell module for Windows Server infrastructure automation. Provides comprehensive
functions for Active Directory deployment, DNS/DHCP configuration, network setup, and
user management.Designed for system administrators to streamline server configuration 
and user management and building lab/test deployments.

KEY FEATURES:
• Active Directory forest/domain deployment
• DNS zone and record management
• DHCP server configuration
• Network interface configuration
• Bulk user creation and management

REQUIREMENTS:
• Administrator privileges
• Active Directory PowerShell modules
• Network connectivity

QUICK START:
Import-Module .\ADConf-Module.psm1
$pass = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
Install-CustomADForest -DomainName "corp.local" -NetbiosName "CORP" -SafeModePassword $pass

For detailed help: Get-Help <FunctionName> -Full

============================================================================
FUNCTIONS SUMMARY
============================================================================

==========================================================================
#region NETWORK CONFIGURATION FUNCTIONS
==========================================================================

# 1. Set-StaticIPv4
#    Configures static IPv4 address, gateway, and DNS servers
#    Usage: Set-StaticIPv4 -IPv4 "192.168.2.30" -Gateway "192.168.2.1" -DNS "8.8.8.8","8.8.4.4"

# 2. Set-StaticIPv6
#    Configures static IPv6 address, gateway, and DNS servers
#    Usage: Set-StaticIPv6 -IPv6 "2001:db8::10" -Gateway "2001:db8::1" -DNS "2001:4860:4860::8888"

# 3. Disable-IPv6
#    Disables IPv6 on the first active network interface
#    Usage: Disable-IPv6

==========================================================================

==========================================================================
#region SYSTEM CONFIGURATION FUNCTIONS
==========================================================================

# 4. Disable-CtrlAltDel
#    Enables or disables Ctrl+Alt+Del secure logon requirement
#    Usage: Disable-CtrlAltDel -Disable ($true or $false)

# 5. Set-TimeZoneConfig
#    Sets system timezone
#    Usage: Set-TimeZoneConfig -TimeZone "UTC" 

# 6. Rename-ComputerSystem
#    Renames the local computer
#    Usage: Rename-ComputerSystem -Name "NewPCName"

# 7. Set-ServerManagerStartup
#    Configures Server Manager startup behavior
#    Usage: Set-ServerManagerStartup -Disable ($true or $false)

# 8. Enable-RemoteDesktop
#    Enables Remote Desktop Protocol (RDP) and firewall rules
#    Usage: Enable-RemoteDesktop

# 9. Update-WindowsSystem
#    Installs and updates Windows via PSWindowsUpdate module
#    Usage: Update-WindowsSystem

==========================================================================

==========================================================================
#region ACTIVE DIRECTORY FUNCTIONS
==========================================================================

# 10. Install-CustomADForest
#     Installs AD and creates a new AD forest
#     Usage: 
#        $pass = ConvertTo-SecureString "Password123!" -AsPlainText -Force
#        Install-CustomADForest -DomainName "test.local" -NetbiosName "TEST" -SafeModePassword $pass

==========================================================================

==========================================================================
#region DNS ZONE MANAGEMENT FUNCTIONS
==========================================================================

# 1. Add-DnsPrimaryForwardZone
#     Creates a primary forward DNS zone
#     Usage: Add-DnsPrimaryForwardZone -Name "example.local" -ComputerName "DC01"

# 2. Add-DnsPrimaryReverseZone
#     Creates a primary reverse DNS zone
#     Usage: Add-DnsPrimaryReverseZone -NetworkID "192.168.2"

# 3. Add-DnsFileBasedZone
#     Creates a file-based DNS zone
#     Usage: Add-DnsFileBasedZone -Name "example.local" -ZoneFile "example.local.dns"

# 4. Set-DnsZoneNotification
#     Sets DNS zone notifications
#     Usage: Set-DnsZoneNotification -Name "example.local" -NotifyServers "192.168.2.10","192.168.2.11"

# 5. Export-DnsZone
#     Exports a DNS zone to a file
#     Usage: Export-DnsZone -ZoneName "example.local" -FileName "C:\DNS\example.local.dns"

# 6. Add-DnsSecondaryZone
#     Creates a secondary read-only zone
#     Usage: Add-DnsSecondaryZone -Name "example.local" -ZoneFile "example.local.dns" -MasterServers "192.168.2.10"

# 7. Add-DnsStubZone
#     Creates a stub DNS zone (NS records only)
#     Usage: Add-DnsStubZone -Name "example.local" -MasterServers "192.168.2.10"

# 8. Add-DnsConditionalForwarder
#     Creates a conditional DNS forwarder
#     Usage: Add-DnsConditionalForwarder -Name "partner.local" -MasterServers "192.168.2.20"

# 9. Add-DnsZoneDelegation
#     Delegates a child DNS zone
#     Usage: Add-DnsZoneDelegation -ParentZone "example.local" -ChildZone "sub.example.local" -IPAddresses "192.168.2.10" -NameServers "ns1.example.local"

==========================================================================

==========================================================================
#region DNS RECORD MANAGEMENT FUNCTIONS
==========================================================================

# 1. Add-DnsARecord
#     Adds an A record (hostname → IPv4) with PTR
#     Usage: Add-DnsARecord -ZoneName "example.local" -Name "host1" -IPv4Address "192.168.2.50"

# 2. Add-DnsCnameRecord
#     Adds a CNAME alias
#     Usage: Add-DnsCnameRecord -ZoneName "example.local" -AliasName "www" -HostName "host1.example.local"

# 3. Add-DnsMxRecord
#     Adds a mail exchange (MX) record
#     Usage: Add-DnsMxRecord -ZoneName "example.local" -MailServer "mail.example.local" -Preference 10

# 4. Enable-DnsScavenging
#     Enables DNS scavenging (auto-remove stale records)
#     Usage: Enable-DnsScavenging -ScavengingInterval ([TimeSpan]"4.00:00:00")

==========================================================================

==========================================================================
#region ACTIVE DIRECTORY OBJECT MANAGEMENT
==========================================================================

# 1. New-RandomADUser
#     Creates random AD users in a specified OU
#     Usage:
#          $Password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
#          New-RandomADUser -Name "DemoUser" -Count 5 -Password $Password -Verbose

# 2. Import-CsvADUser
#     Creates OUs, groups, and users from a CSV file
#     Usage:
#          $pass = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force 
#          Import-CsvADUser -CsvPath "C:\users.csv" -Password $pass

# 3. Test-CsvContent
#     Validates CSV structure for Import-CsvADUser
#     Usage: Test-CsvContent -CsvPath "C:\users.csv"

==========================================================================

==========================================================================
#region SYSTEM CHECK FUNCTIONS
==========================================================================
# 27. Test-NetworkConnection
#     Tests internet connectivity (ping 8.8.8.8)
#     Returns: $true if available, $false otherwise

# 28. Test-AdministratorPrivileges
#     Checks if the current user has administrative privileges
#     Returns: $true if admin, $false otherwise

# 29. Test-SystemReadiness
#     Runs internet and admin checks, prints results, exits on failure
#     Usage: Test-SystemReadiness

==========================================================================

==========================================================================
#region AUTO-LOGIN FUNCTIONS
==========================================================================

# 30. Set-AutoLogon
#     Enable Windows auto-login for a specific user
#     Usage: Set-AutoLogon -Username "AdminUser" -PasswordPlain "Password123"

# 31. Remove-AutoLogon
#     Disable Windows auto-login
#     Usage: Remove-AutoLogon

# 32. Test-AutoLogon
#     Check if auto-login is enabled for a user
#     Usage: Test-AutoLogon -Username "AdminUser"

# 33. Get-AutoLogonCredential
#     Securely store or retrieve a user's password
#     Usage: Get-AutoLogonCredential -CredFile "C:\creds.xml" -Username "AdminUser"

==========================================================================

==========================================================================
#region STARTUP SCRIPT FUNCTIONS
==========================================================================

# 34. Add-StartupScript
#     Add a PowerShell script to Windows startup
#     Usage: Add-StartupScript -ScriptPath "C:\script.ps1" -TaskNumber 1

# 35. Remove-StartupScript
#     Remove a startup script shortcut
#     Usage: Remove-StartupScript

# 36. Test-StartupScript
#     Check if startup script exists
#     Usage: Test-StartupScript

==========================================================================

==========================================================================
#region TASK MANAGEMENT FUNCTIONS
==========================================================================

# 37. Show-TaskStatus
#     Display the progress of tasks
#     Usage: Show-TaskStatus -Current 1 -Total 5

# 38. New-ConfigurationReport
#     Generate a configuration summary report
#     Usage: New-ConfigurationReport -Path "C:\reports" -TasksExecuted 5 -Username "Admin" -LogFile "C:\log.txt"

# 39. Write-Log
#     Log messages to console and file
#     Usage: Write-Log -Message "Task completed" -Level "SUCCESS"

# 40. Invoke-CleanupTask
#     Perform final cleanup tasks after configuration
#     Usage: Invoke-CleanupTask

# 41. Enable-AutoLogonWithScript
#     Enable auto-login and ensure startup script exists
#     Usage: Enable-AutoLogonWithScript -TaskNumber 1 -ScriptPath "C:\script.ps1" -Username "Admin" -PasswordPlain "Password123"

==========================================================================

==========================================================================
#region DHCP SERVER FUNCTIONS
==========================================================================
# 42. New-Dhcp4Scope
#     Creates a new DHCP IPv4 scope with optional lease duration, state, and description
#     Usage: New-Dhcp4Scope -ScopeName "Scope1" -StartRange "192.168.2.50" -EndRange "192.168.2.100" -SubnetMask "255.255.255.0" -LeaseDuration ([TimeSpan]"8.00:00:00") -State "Active"

# 43. Install-DhcpAndAuthorize
#     Installs the DHCP server role (if missing) and authorizes the DHCP server in Active Directory
#     Usage: Install-DhcpAndAuthorize -DnsName "dhcp01.test.local" -IpAddress "192.168.2.10"

# 44. Add-DhcpServer
#     Combines DHCP installation, authorization, and scope creation in one function
#     Usage: Add-DhcpServer -ScopeName "Scope1" -StartRange "192.168.2.50" -EndRange "192.168.2.100" -SubnetMask "255.255.255.0" -State "Active"

==========================================================================
#>

#region ---Networking Configuration--- 

#region ---Set-StaticIPv4---

# ======================================================================
# Set-StaticIPv4
# Configures a static IPv4 address, default gateway, and DNS servers
# Usage:
#      Set-StaticIPv4 -IPv4 "192.168.2.30" -Gateway "192.168.2.1" -DNS "8.8.8.8","8.8.4.4"
# ======================================================================

function Set-StaticIPv4 {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][string]$IPv4,  
           [Parameter(Mandatory=$true)][string]$Gateway,  
           [Parameter(Mandatory=$true)][string[]]$DNS 
          )

    Write-Verbose "Configuring static IP $IPv4..."
    try {
        # Get the first active physical adapter
        $nic = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.HardwareInterface -eq $true } | Select-Object -First 1
        if ($null -eq $nic) { 
            Write-Warning "No active network interface found"
            return
        }

        # Remove all existing IPv4 addresses and gateway
        Get-NetIPAddress -InterfaceIndex $nic.InterfaceIndex -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $nic.InterfaceIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false

        # Set the new static IP and DNS servers
        New-NetIPAddress -InterfaceIndex $nic.InterfaceIndex -IPAddress $IPv4 -PrefixLength 24 -DefaultGateway $Gateway -ErrorAction Stop
        Set-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses $DNS

        Write-Verbose "[+] Static IP and DNS configured on interface $($nic.Name)."
    } catch {
        Write-Warning "[-] Failed: $_"
    }
}

#endregion

#region ---Set-StaticIPv6---

# ======================================================================
# Set-StaticIPv6
# Configures a static IPv6 address, default gateway, and DNS servers
# Usage:
#      Set-StaticIPv6 -IPv6 "2001:db8::10" -Gateway "2001:db8::1" -DNS "2001:4860:4860::8888"
# ======================================================================

function Set-StaticIPv6 {
    [CmdletBinding()]
    param ( [Parameter(Mandatory=$true)][string]$IPv6,
            [Parameter(Mandatory=$true)][string]$Gateway,
            [Parameter(Mandatory=$true)][string[]]$DNS  
            )

    Write-Verbose "Configuring static IPv6 $IPv6..."
    try {
        $nic = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.HardwareInterface -eq $true } | Select-Object -First 1
        if ($null -eq $nic) {
            Write-Warning "No active network interface found"
            return
        }

        # Check if IPv6 is enabled on the adapter
        $ipv6Binding = Get-NetAdapterBinding -Name $nic.Name -ComponentID ms_tcpip6
        if ($ipv6Binding.Enabled -eq $false) {
            Write-Verbose "IPv6 is disabled on $($nic.Name). Enabling..."
            Enable-NetAdapterBinding -Name $nic.Name -ComponentID ms_tcpip6 -ErrorAction Stop
            Start-Sleep -Seconds 2  # Give it a moment to apply
        }


        # Remove existing IPv6 addresses and routes
        Get-NetIPAddress -InterfaceIndex $nic.InterfaceIndex -AddressFamily IPv6 | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $nic.InterfaceIndex -DestinationPrefix "::/0" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false

        # Apply new IPv6 configuration
        New-NetIPAddress -InterfaceIndex $nic.InterfaceIndex -IPAddress $IPv6 -PrefixLength 64 -DefaultGateway $Gateway -ErrorAction Stop
        Set-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses $DNS

        Write-Verbose "[+] Static IPv6 and DNS configured on interface $($nic.Name)."
    } catch {
        Write-Warning "[-] Failed: $_"
    }
}

#endregion

#region ---Disable-IPv6---

# ======================================================================
# Disable-IPv6
# Disables IPv6 on the first active physical network interface
# Usage:
#      Disable-IPv6
# ======================================================================

function Disable-IPv6 {
    
    [CmdletBinding()]
    param ()

    Write-Verbose "Disabling IPv6..."
    try {
        $nic = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.HardwareInterface -eq $true } | Select-Object -First 1
        if ($null -eq $nic) { Write-Warning "No active network interface found"; return }

        Disable-NetAdapterBinding -Name $nic.Name -ComponentID "ms_tcpip6"
        Write-Verbose "IPv6 disabled on interface $($nic.Name)."
    } catch { Write-Warning "Failed: $_" }
}

#endregion

#endregion

#region ---Disable CAD---

# ======================================================================
# Disable-CtrlAltDel (Ctrl+Alt+Del Secure Logon Requirement)
# usage:
#       Disable-CtrlAltDel -Disable $true   # Disable requirement
#       Disable-CtrlAltDel -Disable $false  # Enable requirement
# ======================================================================
function Disable-CtrlAltDel {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][bool]$Disable
    )

    # Registry path & name
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regName = "DisableCAD"

    try {
        if ($Disable) {
            Write-Verbose "Disabling Ctrl+Alt+Del requirement..."
            Set-ItemProperty -Path $regPath -Name $regName -Value 1 -Type DWord -Force -ErrorAction Stop
            Write-Verbose "Ctrl+Alt+Del requirement disabled."
        } else {
            Write-Verbose "Enabling Ctrl+Alt+Del requirement..."
            Set-ItemProperty -Path $regPath -Name $regName -Value 0 -Type DWord -Force -ErrorAction Stop
            Write-Verbose "Ctrl+Alt+Del requirement enabled."
        }
    }
    catch {
        Write-Warning "Disable-CtrlAltDel failed: $_"
    }
}

#endregion

#region ---Set-TimeZoneConfig---

# ======================================================================
# Set-TimeZoneConfig (Set system timezone)
# usage:
#      Set-TimeZoneConfig -TimeZone "<Your TimeZone>"
# ======================================================================
function Set-TimeZoneConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TimeZone
    )


    Write-Verbose "Setting timezone to $TimeZone..."
    try {
        Set-TimeZone -Name $TimeZone -ErrorAction Stop
        Write-Verbose "Timezone set to $TimeZone."
    } catch { Write-Warning "Failed: $_" }
}

#endregion

#region ---Rename-ComputerSystem---
# ======================================================================
# Rename-ComputerSystem (Rename the computer)
# usage:
#      Rename-ComputerSystem -Name "<NewComputerName>" 
# ======================================================================
function Rename-ComputerSystem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    Write-Verbose "Renaming computer to $Name..."
    try {
        Rename-Computer -NewName $Name -Force -ErrorAction Stop
        Write-Verbose "Computer renamed. Restarting..."
        Restart-Computer -Force
    } catch { Write-Warning "Failed: $_" }
}

#endregion

#region ---Set-ServerManagerStartup---
# ======================================================================
# Set-ServerManagerStartup (Enable/Disable Server Manager at logon)
# usage:
#      Set-ServerManagerStartup -Disable $true   # Disable opening at logon
#      Set-ServerManagerStartup -Disable $false  # Enable opening at logon
# ======================================================================
function Set-ServerManagerStartup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [bool]$Disable = $true
    )
    $reg = "HKLM:\SOFTWARE\Microsoft\ServerManager" 
    $key = "DoNotOpenServerManagerAtLogon"
    try {
        if ($Disable) {
            Set-ItemProperty -Path  $reg -Name $key -Value 1
            Write-Verbose "Server Manager will NOT open at startup."
        } else {
            Set-ItemProperty -Path $reg -Name $key -Value 0
            Write-Verbose "Server Manager WILL open at startup."
        }
    } catch {
        Write-Warning "Failed to update Server Manager setting: $_"
    }
}

#endregion

#region ---Enable-RemoteDesktop---
# ======================================================================
# Enable-RemoteDesktop (Enable Remote Desktop and update firewall rules)
# usage:
#      Enable-RemoteDesktop
# ======================================================================

function Enable-RemoteDesktop {
    [CmdletBinding()]
    param ( )

    Write-Verbose "Enabling RDP..."
    try {
        # Enable RDP via registry
        $reg = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
        Set-ItemProperty -Path $reg -Name fDenyTSConnections -Value 0 -ErrorAction Stop
        # Enable firewall rules
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop
        Write-Verbose "RDP enabled + firewall rules updated."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion

#region ---Update-WindowsSystem---
# ======================================================================
# Update-WindowsSystem (Check and install Windows updates)
# usage:
#      Update-WindowsSystem
# ======================================================================

function Update-WindowsSystem {
    [CmdletBinding()]
    param ()

    Write-Verbose "Checking for updates ..."
    try {
        # Install and Import PSWindowsUpdate Module 
        Set-ExecutionPolicy RemoteSigned -Scope Process -Force

        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force }

        if ((Get-PSRepository -Name "PSGallery").InstallationPolicy -ne "Trusted") {
            Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted }

        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Install-Module -Name PSWindowsUpdate -Force  }

        # Import module quietly (suppress verbose stream)
        Import-Module PSWindowsUpdate -Force -Verbose:$false

        # Check for available updates quietly
        $updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot -Verbose:$false
        if ($updates) {
            Write-Verbose "Available updates :"
            $updates | Select-Object KB, Size, Title | Format-Table -AutoSize | Out-String | Write-Output
        } else {
            Write-Verbose "No updates available."
        }

        # Install updates (quiet mode, but still shows progress)
        Write-Verbose "Installing updates..."
        Install-WindowsUpdate -AcceptAll -AutoReboot -Verbose

    } catch {
        Write-Warning "Update failed: $($_.Exception.Message)"
    }
}

#endregion

#region ---AD Instalation and Congiguration---

# ======================================================================
# Install-CustomADForest (Install and configure a new Active Directory forest)
# Usage:
#      $pass = ConvertTo-SecureString "StrongP@ssw0rd2025!" -AsPlainText -Force
#      Install-CustomADForest -DomainName "test.local" -NetbiosName "TEST" -SafeModePassword $pass -Verbose
# ======================================================================


function Install-CustomADForest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$DomainName,
        [Parameter(Mandatory=$true)][string]$NetbiosName,
        [Parameter(Mandatory=$true)][SecureString]$SafeModePassword
    )
	
    # Install AD DS role and management tools
    Write-Verbose "Installing AD DS role and management tools..."
    try {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
        Write-Verbose "AD DS role installed successfully."
    }
    catch {
        Write-Error "Failed to install AD DS role: $_"
        exit
    }

    # Root Forest installation 
    Write-Verbose "Creating new AD forest for $DomainName..."

    $SYSVOL = "C:\Windows\SYSVOL"
    $NTDS   = "C:\Windows\NTDS"

    try {
        Install-ADDSForest `
            -SkipPreChecks `
            -DomainName $DomainName `
            -DomainNetbiosName $NetbiosName `
            -DomainMode "WinThreshold" `
            -ForestMode "WinThreshold" `
            -CreateDnsDelegation:$false `
            -InstallDns:$true `
            -SysvolPath $SYSVOL `
            -LogPath $NTDS `
            -DatabasePath $NTDS `
            -SafeModeAdministratorPassword $SafeModePassword `
            -NoRebootOnCompletion:$true `
            -Force:$true `
            -Verbose:$false `
            -ErrorAction Stop

        Write-Verbose "AD forest created successfully. The server will reboot."
        Write-Verbose "Rebooting..."
        Start-Sleep -Seconds 1
        Restart-Computer -Force
    }
    catch {
        Write-Error "Failed to create AD forest: $_"
        exit
    }
}


#endregion 

#region ---DNS Function---

#region ---Add-DnsPrimaryForwardZone---
# ======================================================================
# Add-DnsPrimaryForwardZone
# Creates a primary forward DNS zone (hostnames → IP addresses)
# Usage:
#      Add-DnsPrimaryForwardZone -Name "example.local" -ComputerName "DC01"
# ======================================================================

function Add-DnsPrimaryForwardZone {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$ComputerName
    )
    Write-Verbose "Creating Primary Forward Zone $Name..."
    try {
        Add-DnsServerPrimaryZone -Name $Name -ComputerName $ComputerName -ReplicationScope 'Domain' -DynamicUpdate 'Secure' 
        Write-Verbose "Zone $Name created successfully."
    } catch {
        Write-Warning "Failed to create zone $Name : $_"
    }
}

#endregion

#region ---Add-DnsPrimaryReverseZone---

# ======================================================================
# Add-DnsPrimaryReverseZone
# Creates a primary reverse DNS zone (IP addresses → hostnames)
# Usage:
#       Add-DnsPrimaryReverseZone -NetworkID "192.168.1"
# ======================================================================
function Add-DnsPrimaryReverseZone {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$NetworkID
    )
    Write-Verbose "Creating Primary Reverse Zone for $NetworkID..."
    try {
        Add-DnsServerPrimaryZone -NetworkID $NetworkID -ReplicationScope 'Forest' -DynamicUpdate 'NonsecureAndSecure' 
        Write-Verbose "Reverse Zone $NetworkID created successfully."
    } catch {
        Write-Warning "Failed to create reverse zone $NetworkID : $_"
    }
}


#endregion

#region ---Add-DnsFileBasedZone---

# ======================================================================
# Add-DnsFileBasedZone
# Creates a file-based DNS zone (zone stored in a file)
# Usage:
#      Add-DnsFileBasedZone -Name "example.local" -ZoneFile "example.dns"
# ======================================================================

function Add-DnsFileBasedZone {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$ZoneFile
    )
    Write-Verbose "Creating File-based Zone $Name..."
    try {
        Add-DnsServerPrimaryZone -Name $Name -ZoneFile $ZoneFile -DynamicUpdate 'None' 
        Write-Verbose "File-based zone $Name created successfully."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion

#region ---Set-DnsZoneNotification---

# ======================================================================
# Set-DnsZoneNotification
# Configures DNS zone notifications to other servers
# Usage:
#      Set-DnsZoneNotification -Name "example.local" -NotifyServers "192.168.2.10","192.168.2.11"
# ======================================================================

function Set-DnsZoneNotification {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string[]]$NotifyServers
    )
    Write-Verbose "Setting notifications for $Name..."
    try {
        Set-DnsServerPrimaryZone -Name $Name -Notify 'NotifyServers' -NotifyServers $NotifyServers 
        Write-Verbose "Notifications set for $Name."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion

#region ---Export-DnsZone---
# ======================================================================
# Export-DnsZone
# Exports a DNS zone to a file
# Usage:
#      Export-DnsZone -ZoneName "example.local" -FileName "C:\Backup\example.dns"
# ======================================================================

function Export-DnsZone {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$ZoneName,
        [Parameter(Mandatory=$true)][string]$FileName
    )
    Write-Verbose "Exporting zone $ZoneName to $FileName..."
    try {
        Export-DnsServerZone -Name $ZoneName -Filename $FileName
        Write-Verbose "Zone exported successfully."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion 

#region ---Add-DnsSecondaryZone---
# ======================================================================
# Add-DnsSecondaryZone
# Creates a read-only (secondary) copy of a primary DNS zone
# Usage:
#       Add-DnsSecondaryZone -Name "example.local" -ZoneFile "example.dns" -MasterServers "192.168.2.10","192.168.2.11"
# ======================================================================

function Add-DnsSecondaryZone {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$ZoneFile,
        [Parameter(Mandatory=$true)][string[]]$MasterServers
    )
    Write-Verbose "Creating Secondary Zone $Name..."
    try {
        Add-DnsServerSecondaryZone -Name $Name -ZoneFile $ZoneFile -LoadExisting -MasterServers $MasterServers 
        Write-Verbose "Secondary zone $Name created successfully."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion

#region ---Add-DnsStubZone---

# ======================================================================
# Add-DnsStubZone
# Creates a stub DNS zone (keeps only NS records to forward queries)
# Usage:
#      Add-DnsStubZone -Name "example.local" -MasterServers "192.168.2.10","192.168.2.11"
# ======================================================================

function Add-DnsStubZone {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string[]]$MasterServers
    )
    Write-Verbose "Creating Stub Zone $Name..."
    try {
        Add-DnsServerStubZone -Name $Name -MasterServers $MasterServers -ReplicationScope 'Domain' 
        Write-Verbose "Stub zone $Name created successfully."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion 

#region ---Add-DnsConditionalForwarder---

# ======================================================================
# Add-DnsConditionalForwarder
# Forward queries for a specific domain to designated DNS servers
# Usage:
#      Add-DnsConditionalForwarder -Name "otherdomain.local" -MasterServers "192.168.2.10","192.168.2.11" 
# ======================================================================

function Add-DnsConditionalForwarder {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string[]]$MasterServers,
        [int]$Timeout = 5
    )
    Write-Verbose "Creating Conditional Forwarder $Name..."
    try {
        Add-DnsServerConditionalForwarderZone -Name $Name -MasterServers $MasterServers -ForwarderTimeout $Timeout -ReplicationScope "Forest"
        Write-Verbose "Conditional forwarder $Name created successfully."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion

#region ---Add-DnsZoneDelegation---

# ======================================================================
# Add-DnsZoneDelegation
# Delegates a subdomain to other DNS servers
# Usage:
#      Add-DnsZoneDelegation -ParentZone "example.local" -ChildZone "sub.example.local" -IPAddresses "192.168.2.10","192.168.2.11" -NameServers "ns1.example.local","ns2.example.local"
# ======================================================================

function Add-DnsZoneDelegation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$ParentZone,
        [Parameter(Mandatory=$true)][string]$ChildZone,
        [Parameter(Mandatory=$true)][string[]]$IPAddresses,
        [Parameter(Mandatory=$true)][string[]]$NameServers
    )
    Write-Verbose "Delegating $ChildZone under $ParentZone..."
    try {
        for ($i=0; $i -lt $IPAddresses.Length; $i++) {
            Add-DnsServerZoneDelegation -Name $ParentZone -ChildZoneName $ChildZone -IPAddress $IPAddresses[$i] -NameServer $NameServers[$i] 
        }
        Write-Verbose "Delegation created successfully."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion

#region ---Add-DnsARecord--- 

# ======================================================================
# Add-DnsARecord
# Adds an A record (hostname → IP address) and optionally creates PTR
# Usage:
#      Add-DnsARecord -ZoneName "example.local" -Name "host1" -IPv4Address "192.168.2.50"
# ======================================================================

function Add-DnsARecord {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$ZoneName,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$IPv4Address
    )
    Write-Verbose "Adding A record $Name -> $IPv4Address..."
    try {
        Add-DnsServerResourceRecordA -ZoneName $ZoneName -Name $Name -IPv4Address $IPv4Address -CreatePtr 
        Write-Verbose "A record added."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion

#region ---Add-DnsCnameRecord---

# ======================================================================
# Add-DnsCnameRecord
# Creates a CNAME (alias) record in a DNS zone
# Usage:
#      Add-DnsCnameRecord -ZoneName "example.local" -AliasName "www" -HostName "host1.example.local"
# ======================================================================

function Add-DnsCnameRecord {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$ZoneName,
        [Parameter(Mandatory=$true)][string]$AliasName,
        [Parameter(Mandatory=$true)][string]$HostName
    )
    Write-Verbose "Adding CNAME $AliasName -> $HostName..."
    try {
        Add-DnsServerResourceRecordCName -ZoneName $ZoneName -Name $AliasName -HostNameAlias $HostName 
        Write-Verbose "CNAME record added."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion

#region ---Add-DnsMxRecord---

# ======================================================================
# Add-DnsMxRecord
# Adds an MX record (mail server) for a DNS zone
# Usage:
#      Add-DnsMxRecord -ZoneName "example.local" -MailServer "mail.example.local" -Preference 10
# ======================================================================

function Add-DnsMxRecord {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$ZoneName,
        [Parameter(Mandatory=$true)][string]$MailServer,
        [int]$Preference = 10
    )
    Write-Verbose "Adding MX record $MailServer with preference $Preference..."
    try {
        Add-DnsServerResourceRecordMX -ZoneName $ZoneName -Name '@' -MailExchange $MailServer -Preference $Preference 
        Write-Verbose "MX record added."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion

#region ---Enable-DnsScavenging---

# ======================================================================
# Enable-DnsScavenging
# Enables DNS scavenging to remove stale records automatically
# Usage:
#      Enable-DnsScavenging -ScavengingInterval ([TimeSpan]"4.00:00:00")
# ======================================================================

function Enable-DnsScavenging {
    [CmdletBinding()]
    param (
        [TimeSpan]$ScavengingInterval = ([TimeSpan]"4.00:00:00")
    )
    Write-Verbose "Enabling DNS scavenging..."
    try {
        Set-DnsServerScavenging -ScavengingState $True -ScavengingInterval $ScavengingInterval -ApplyOnAllZones 
        Write-Verbose "Scavenging enabled."
    } catch {
        Write-Warning "Failed: $_"
    }
}

#endregion



#endregion

#region ---AD object Function---

#region ---New-RandomADUser---
# ======================================================================
# New-RandomADUser
# Creates multiple random AD users in a specified OU
# Usage:
#      $Password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
#      New-RandomADUser -Name "DemoUser" -Count 5 -Password $Password -Verbose
# ======================================================================

function New-RandomADUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Name,  
        [Parameter(Mandatory=$true)][int]$Count,  
        [Parameter(Mandatory=$true)][SecureString]$Password,
        [Parameter(Mandatory=$false)][string]$OuName,
        [Parameter(Mandatory=$false)][bool]$Enabled = $true,
        [Parameter(Mandatory=$false)][string]$Description = "Random User N:",
        [Parameter(Mandatory=$false)][bool]$ChangePasswordAtLogon = $false
    )

    #region Check AD feature
    Write-Verbose "Checking requirements..."
    
    # Check if AD module is available
    try {
        Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    } catch {
        Write-Warning "Active Directory module not available. Please install RSAT: Active Directory Domain Services Tools."
        return
    }

    # Check domain connectivity
    try {
        $ADDomain = Get-ADDomain -ErrorAction Stop -Verbose:$false
        $DomainDN = $ADDomain.DistinguishedName
        $DomainDNS = $ADDomain.DNSRoot

        if ([string]::IsNullOrEmpty($DomainDN) -or [string]::IsNullOrEmpty($DomainDNS)) {
            Write-Warning "Domain DN or DNS could not be detected. Check your AD connection and permissions."
            return
        }
        Write-Verbose "Detected domain DN: $DomainDN"
        Write-Verbose "Detected domain DNS: $DomainDNS"
    } catch {
        Write-Warning "Failed to detect domain. Ensure you have proper permissions and domain connectivity." 
        return
    }
    #endregion

    #region Use default OUName if not provided
    if (-not $OuName) { 
        $OuName = "Random_Users"
    }
    
    $OUPath = "OU=$OuName,$DomainDN"
    #endregion
    
    #region Check if OU exists, create if it doesn't
    try {
        Get-ADOrganizationalUnit -Identity $OUPath -ErrorAction Stop -Verbose:$false | Out-Null
        Write-Verbose "OU already exists: $OUPath"
    } catch {
        Write-Verbose "Creating new OU: $OUPath"
        try {
            New-ADOrganizationalUnit -Name $OuName -Path $DomainDN -ErrorAction Stop -Verbose:$false
            Write-Verbose "Successfully created OU: $OUPath"
        } catch {
            Write-Warning "Failed to create OU: $($_.Exception.Message)"
            return
        }
    }
    #endregion

    Write-Verbose "Starting random user creation in OU: $OUPath"

    # -----------------------------
    # Create users
    # -----------------------------
    $createdUsers = @()
    $skippedUsers = @()
    
    for ($i = 1; $i -le $Count; $i++) {
        $username = "$Name" + "_$i"

        # Check if user already exists
        $userExists = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
        
        if ($userExists) {
            Write-Warning "User '$username' already exists. Skipping creation."
            $skippedUsers += $username
            continue
        }
        
        try {
            $userParams = @{
                Name = $username
                SamAccountName = $username
                AccountPassword = $Password
                Path = $OUPath
                Description = "$Description $i"
                Enabled = $Enabled
                ChangePasswordAtLogon = $ChangePasswordAtLogon
            }
            
            New-ADUser @userParams -ErrorAction Stop -Verbose:$false
            Write-Verbose "Created random user: $username"
            $createdUsers += $username
            
        } catch {
            Write-Warning "Failed to create user '$username': $($_.Exception.Message)"
            $skippedUsers += $username
        }
    }
    
    # Output results
    Write-Host "[+] Creation Results:" -ForegroundColor Green -BackgroundColor Black
    Write-Host "[+] Created users: $($createdUsers.Count) users" -ForegroundColor Green -BackgroundColor Black
    
    if ($skippedUsers.Count -gt 0) {
        Write-Host "[+] Skipped users: $($skippedUsers -join ', ')" -ForegroundColor Yellow -BackgroundColor Black
    }
    
}

#endregion

#region ---Import-CsvADUser---

# ======================================================================
# Import-CsvADUser
# Creates AD users, OUs, and groups from a properly formatted CSV file
# Usage:
#      Import-CsvADUser -CsvPath "C:\ADUsers.csv" -Password $pass -Enabled $true -ChangePasswordAtLogon $true
# ======================================================================

function Import-CsvADUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$CsvPath,
        [Parameter(Mandatory = $true)][SecureString]$Password,
        [Parameter(Mandatory = $false)][bool]$Enabled = $true,
        [Parameter(Mandatory = $false)][bool]$ChangePasswordAtLogon = $true
    )

#region Check the CSV file existing 
    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV file does not exist: $CsvPath"
        return $false
    }else {
        Write-Verbose "Reading the CSV file: $CsvPath"
    }
#endregion

#region Get-current (DN and DNS root) 

    try {
    $ADDomain = Get-ADDomain -ErrorAction Stop
    $DomainDN = $ADDomain.DistinguishedName
    $DomainDNS = $ADDomain.DNSRoot

    if ([string]::IsNullOrEmpty($DomainDN) -or [string]::IsNullOrEmpty($DomainDNS)) {
        Write-Warning "Domain DN or DNS could not be detected. Check your AD connection and permissions."
        return
    }
    Write-Verbose "Detected domain DN: $DomainDN"
    Write-Verbose "Detected domain DNS: $DomainDNS"
    } catch {
        Write-Warning "Failed to detect domain. Ensure the Active Directory module is installed, and you are connected to a domain."
        return
    }

#endregion

#region Read and sort data from CSV-file
    $lines = Get-Content -Path $CsvPath
    $OU_Data = @(); $Group_Data = @(); $User_Data = @(); $section = $null

    foreach ($line in $lines) {
        if ($line -match '^:') { $section = $line.TrimStart(':'); continue }
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        switch ($section) {
            "OU"    { $OU_Data += $line }
            "Group" { $Group_Data += $line }
            "User"  { $User_Data += $line }
        }
    }

#endregion

#region --- CREATE OUs ---

    if ($OU_Data.Count -gt 1) {
        $ouCsv = $OU_Data | Select-Object -Skip 1 | ConvertFrom-Csv -Header Name
        foreach ($ou in $ouCsv) {
            if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.Name)'" -ErrorAction SilentlyContinue)) {
                try {
                    New-ADOrganizationalUnit -Name $ou.Name -Path $DomainDN -ErrorAction Stop
                    Write-Verbose "[+] Created OU: $($ou.Name)"
                } catch {
                    Write-Warning "[-] Failed to create OU $($ou.Name): $_"
                }
            } else {
                Write-Verbose "[+] OU already exists: $($ou.Name)"
            }
        }
    }

#endregion

#region --- CREATE GROUPS ---
    if ($Group_Data.Count -gt 1) {
        $groupCsv = $Group_Data | Select-Object -Skip 1 | ConvertFrom-Csv -Header Name,OU
        foreach ($group in $groupCsv) {
            $groupPath = "OU=$($group.OU),$DomainDN"
            if (-not (Get-ADGroup -Filter "Name -eq '$($group.Name)'" -SearchBase $groupPath -ErrorAction SilentlyContinue)) {
                try {
                    New-ADGroup -Name $group.Name -Path $groupPath -GroupScope Global -GroupCategory Security -ErrorAction Stop
                    Write-Verbose "[+] Created group: $($group.Name)"
                } catch {
                    Write-Warning "[-] Failed to create group $($group.Name): $_"
                }
            } else {
                Write-Verbose "[+] Group already exists: $($group.Name)"
            }
        }
    }
#endregion

#region --- CREATE USERS AND ADD TO GROUPS ---
    if ($User_Data.Count -gt 1) {
        $userCsv = $User_Data | Select-Object -Skip 1 | ConvertFrom-Csv -Header GivenName,Surname,Group,OU,Description,EmailAddress
        foreach ($user in $userCsv) {
            # SamAccountName = givenname.surname
            $Sam = ("$($user.GivenName).$($user.Surname)").ToLower()
            $UPN = "$Sam@$DomainDNS"

            if (-not (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue)) {
                try {
                    New-ADUser `
                        -Name "$($user.GivenName) $($user.Surname)" `
                        -GivenName $user.GivenName `
                        -Surname $user.Surname `
                        -SamAccountName $Sam `
                        -UserPrincipalName $UPN `
                        -EmailAddress $user.EmailAddress `
                        -Path "OU=$($user.OU),$DomainDN" `
                        -Description $user.Description `
                        -AccountPassword $Password `
                        -Enabled $Enabled `
                        -ChangePasswordAtLogon $ChangePasswordAtLogon -ErrorAction Stop

                    Write-Verbose "[+] Created user: $Sam"
                } catch {
                    Write-Warning "[-] Failed to create user $Sam : $_"
                    continue
                }
            } else {
                Write-Verbose "[+] User already exists: $Sam"
            }

#endregion

#region --- Add user to group only if group is provided ---
            if (-not [string]::IsNullOrWhiteSpace($user.Group)) {
                try {
                    if (-not (Get-ADGroupMember -Identity $user.Group -Recursive | Where-Object {$_.SamAccountName -eq $Sam})) {
                        Add-ADGroupMember -Identity $user.Group -Members $Sam -ErrorAction Stop
                        Write-Verbose "[+] Added $Sam to group $($user.Group)"
                    } else {
                        Write-Verbose "[+] $Sam is already a member of $($user.Group)"
                    }
                } catch {
                    Write-Warning "[-] Failed to add $Sam to group $($user.Group): $_"
                }
            } else {
                Write-Verbose "[-] No group specified for user $Sam — skipping group assignment."
            }
        }
    }

#endregion

}

#endregion

#region ---Test-CsvContent---

# ======================================================================
# Test-CsvContent
# Validates the content and format of a CSV file before importing to AD
# Usage:
#      Test-CsvContent -CsvPath "C:\ADUsers.csv"
# ======================================================================

function Test-CsvContent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$CsvPath
    )

    #region Check the CSV file existing 
    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV file does not exist: $CsvPath"
        return $false
    } else {
        Write-Verbose "Starting the Validating CSV file: $CsvPath"
        Write-Verbose "Reading ..."
    }
    #endregion

    #region Read and sort data from CSV-file
    $lines = Get-Content -Path $CsvPath
    $OU_Data = @(); $Group_Data = @(); $User_Data = @(); $section = $null

    foreach ($line in $lines) {
        if ($line -match '^:') { $section = $line.TrimStart(':').Trim(); continue } # Trim spaces
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        switch ($section) {
            "OU"    { $OU_Data += $line }
            "Group" { $Group_Data += $line }
            "User"  { $User_Data += $line }
        }
    }
    #endregion

    $valid = $true
    $invalidCharPattern = '[\\\/\*\?\<\>\|]' # NOTE: Use this variable consistently

    #region Check for unknown sections
    $allowedSections = @("OU", "Group", "User")
    $allSections = ($lines | Where-Object { $_ -match '^:' }) | ForEach-Object { $_.TrimStart(':').Trim() }

    foreach ($sec in $allSections) {
        if ($allowedSections -notcontains $sec) {
            Write-Warning "CSV contains unknown section: $sec"
            $valid = $false
        }
    }
    #endregion


    #region --- Validate OU Section ---
    $ouNames = @()

    if (-not $OU_Data -or $OU_Data.Count -eq 0) {
        Write-Warning "OU section is empty."
        $valid = $false
    } else {
        $ouCsv = $OU_Data | Select-Object -Skip 1 | ConvertFrom-Csv -Header Name
        $ouNames = $ouCsv.Name
        if ($ouCsv.Name -contains $null -or $ouCsv.Name -contains "") {
            Write-Warning "OU section contains empty Name field."
            $valid = $false
        }

        # Check for duplicates
        $dupOUs = $ouCsv.Name | Group-Object | Where-Object { $_.Count -gt 1 }
        foreach ($dup in $dupOUs) {
            Write-Warning "Duplicate OU name found: $($dup.Name)"
            $valid = $false
        }

        # Check for invalid characters in OU names
        foreach ($ou in $ouCsv.Name) {
            if ($ou -match $invalidCharPattern) {
                Write-Warning "OU name contains invalid characters: $ou"
                $valid = $false
            }
        }
    }
    #endregion

    #region --- Validate GROUP section ---
    $groupNames = @()

    if ($Group_Data.Count -gt 1) {
        $groupCsv = $Group_Data | Select-Object -Skip 1 | ConvertFrom-Csv -Header Name,OU
        $groupNames = $groupCsv.Name

        foreach ($group in $groupCsv) {
            if ([string]::IsNullOrWhiteSpace($group.Name) -or [string]::IsNullOrWhiteSpace($group.OU)) {
                Write-Warning "Group section contains empty fields."
                $valid = $false
            } elseif ($ouNames -notcontains $group.OU) {
                Write-Warning "Group '$($group.Name)' references OU '$($group.OU)' which does not exist in OU section."
                $valid = $false
            }

            if ($group.Name -match $invalidCharPattern) { # Fixed variable name
                Write-Warning "Group name contains invalid characters: $($group.Name)"
                $valid = $false
            }
        }

        $dupGroups = $groupCsv.Name | Group-Object | Where-Object { $_.Count -gt 1 }
        foreach ($dup in $dupGroups) {
            Write-Warning "Duplicate Group name found: $($dup.Name)"
            $valid = $false
        }
    }
    #endregion

    #region --- Validate USER section ---
    if ($User_Data.Count -gt 1) {
        $userCsv = $User_Data | Select-Object -Skip 1 | ConvertFrom-Csv -Header GivenName,Surname,Group,OU,Description,EmailAddress

        foreach ($u in $userCsv) {
            if ([string]::IsNullOrWhiteSpace($u.GivenName) -or [string]::IsNullOrWhiteSpace($u.Surname)) {
                Write-Warning "User entry missing GivenName or Surname."
                $valid = $false
            }

            if ($u.OU -notin $ouNames) {
                Write-Warning "User '$($u.GivenName) $($u.Surname)' references OU '$($u.OU)' which does not exist in OU section."
                $valid = $false
            }

            if ([string]::IsNullOrWhiteSpace($u.Group)) {
                Write-Warning "User '$($u.GivenName) $($u.Surname)' has no group assigned. User will be created without group membership."
            }

            # Fixed variable name to match $invalidCharPattern
            if ($u.GivenName -match $invalidCharPattern) {
                Write-Warning "User '$($u.GivenName) $($u.Surname)' contains invalid characters in GivenName."
                $valid = $false
            }
            if ($u.Surname -match $invalidCharPattern) {
                Write-Warning "User '$($u.GivenName) $($u.Surname)' contains invalid characters in Surname."
                $valid = $false
            }
        }

        # Check duplicate SamAccountNames
        $samNames = $userCsv | ForEach-Object { ("$($_.GivenName).$($_.Surname)").ToLower() }
        $dupUsers = $samNames | Group-Object | Where-Object { $_.Count -gt 1 }
        foreach ($dup in $dupUsers) {
            Write-Warning "Duplicate SamAccountName would be generated: $($dup.Name)"
            $valid = $false
        }

        foreach ($name in $samNames) {
            if ($name -match $invalidCharPattern) { # Fixed variable name
                Write-Warning "SamAccountName '$name' contains invalid characters."
                $valid = $false
            }
        }
    }
    #endregion

    if ($valid) {
        if ($VerbosePreference -eq 'Continue') {
            Write-Host "[+] CSV validation passed." -ForegroundColor Green
            Write-Host "[+] OU section validation completed. Total OUs found: $($ouNames.Count)" -ForegroundColor Green
            Write-Host "[+] GROUP section validation completed. Total Groups found: $($groupNames.Count)"  -ForegroundColor Green
            Write-Host "[+] USER section validation completed. Total Users found: $($userCsv.Count)" -ForegroundColor Green
        }
        
    } else {
        Write-Warning "CSV validation failed. Please fix errors before running New-Csv-U00ser."
    }

    return $valid
}

#endregion

#endregion

#region Check Internet & privileges 

#region ---Test-NetworkConnection---

# ======================================================================
# Test-NetworkConnection
# Checks if the system has internet connectivity by pinging 8.8.8.8
# Usage:
#      Test-NetworkConnection
# Returns: $true if internet is available, $false otherwise
# ======================================================================

function Test-NetworkConnection {
    try {
        $test = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction Stop
        if ($test) {
            Write-Host "[+] Internet connection: AVAILABLE" -ForegroundColor Green -BackgroundColor Black
            return $true
        } else {
            Write-Host "[-] Internet connection: UNAVAILABLE" -ForegroundColor Red -BackgroundColor Black
            return $false
        }
    }
    catch {
        Write-Host "[-] Internet connection: FAILED" -ForegroundColor Red -BackgroundColor Black
        return $false
    }
}

#endregion

#region ---Test-AdministratorPrivileges---

# ======================================================================
# Test-AdministratorPrivileges
# Checks if the current user has administrative privileges
# Usage:
#      Test-AdministratorPrivileges
# Returns: $true if the user is an administrator, $false otherwise
# ======================================================================

function Test-AdministratorPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $adminRole   = [Security.Principal.WindowsBuiltInRole]::Administrator
    $isAdmin     = ([Security.Principal.WindowsPrincipal]::new($currentUser)).IsInRole($adminRole)

    if ($isAdmin) {
        Write-Host "[+] Admin privileges: YES" -ForegroundColor Green -BackgroundColor Black
        return $true
    } else {
        Write-Host "[-] Admin privileges: NO" -ForegroundColor Red -BackgroundColor Black
        return $false
    }
}

#endregion

#region ---Test-SystemReadiness---

# ======================================================================
# Test-SystemReadiness
# Runs both internet connectivity and admin privilege checks
# Prints a formatted report in the console
# Terminates the script with exit code 1 if any check fails
# Usage:
#      Test-SystemReadiness
# ======================================================================

function Test-SystemReadiness {

    Write-Host "[*] System Check Started" -ForegroundColor Cyan -BackgroundColor Black  
    Write-Host "[*] Running at: $(Get-Date)" -ForegroundColor Yellow -BackgroundColor Black

    $internet = Test-NetworkConnection
    $admin    = Test-AdministratorPrivileges

    if ($internet -and $admin) {
        Write-Host "[+] Checks PASSED!" -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Host "[-] Checks FAILED!" -ForegroundColor Red -BackgroundColor Black
        exit 1  
    }
}

#endregion 

#endregion

#region ---Auto Login Function---

#region ---Set-AutoLogon---

# ======================================================================
# Set-AutoLogon
# Enable Windows auto-login for a specific user
# usage:
#      Set-AutoLogon -Username "<UserName>" -PasswordPlain "<Password>"
# ======================================================================

function Set-AutoLogon {
    param (
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][string]$PasswordPlain
    )
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value $Username
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $PasswordPlain
}

#endregion

#region ---Remove-AutoLogon---

# ======================================================================
# Remove-AutoLogon
# Disable Windows auto-login
# usage:
#      Remove-AutoLogon
# ======================================================================

function Remove-AutoLogon {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -ErrorAction SilentlyContinue
}

#endregion

#region ---Test-AutoLogon---

# ======================================================================
# Test-AutoLogon
# Check if auto-login is enabled for a user
# usage:
#      Test-AutoLogon -Username "<UserName>"
# ======================================================================

function Test-AutoLogon {
    param (
        [Parameter(Mandatory = $true)][string]$Username
    )
    $AutoAdminLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
    $DefaultUserName = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -ErrorAction SilentlyContinue
    
    if ($AutoAdminLogon.AutoAdminLogon -eq "1" -and $DefaultUserName.DefaultUserName -eq $Username) {
        return $true
    }
    return $false
}

#endregion

#region ---Get-AutoLogonCredential---

# ======================================================================
# Get-AutoLogonCredential
# Securely store or retrieve a user's password
# usage:
#      Get-AutoLogonCredential -CredFile "<PathToCredentialFile>" -Username "<UserName>"
# ======================================================================

function Get-AutoLogonCredential {
    param (
        [Parameter(Mandatory = $true)][string]$CredFile,
        [Parameter(Mandatory = $true)][string]$Username
    )
    if (-not (Test-Path $CredFile)) {
        $Password = Read-Host "Enter password for $Username" -AsSecureString
        $Password | Export-Clixml -Path $CredFile
        Write-Log "Credential saved securely to $CredFile" -Level "SUCCESS"
    }
    $SecurePassword = Import-Clixml $CredFile
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword))
}

#endregion

#endregion

#region ---Startup Script Function---

#region ---Add-StartupScript---

# ======================================================================
# Add-StartupScript
# Add a PowerShell script to Windows startup
# usage:
#      Add-StartupScript -ScriptPath "<PathToScript>" -TaskNumber <Number>
# ======================================================================

function Add-StartupScript {
    param (
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][int]$TaskNumber
    )
    $StartupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $ShortcutPath = Join-Path $StartupFolder "ServerConfigResume.lnk"

    # Remove existing shortcut to avoid conflicts
    Remove-Item $ShortcutPath -ErrorAction SilentlyContinue

    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -TaskNumber $TaskNumber -ScriptPath `"$ScriptPath`""
    $Shortcut.WorkingDirectory = Split-Path $ScriptPath -Parent
    $Shortcut.WindowStyle = 1
    $Shortcut.Save()
    Write-Log "Startup shortcut created for Task $TaskNumber : $ShortcutPath" -Level "SUCCESS"
}

#endregion

#region ---Remove-StartupScript---

# ======================================================================
# Remove-StartupScript
# Remove a startup script shortcut
# usage:
#      Remove-StartupScript
# ======================================================================

function Remove-StartupScript {
    $StartupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $ShortcutPath = Join-Path $StartupFolder "ServerConfigResume.lnk"
    Remove-Item $ShortcutPath -ErrorAction SilentlyContinue
}

#endregion

#region ---Test-StartupScript---

# ======================================================================
# Test-StartupScript
# Check if startup script exists
# usage:
#      Test-StartupScript
# ======================================================================

function Test-StartupScript {
    $StartupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $ShortcutPath = Join-Path $StartupFolder "ServerConfigResume.lnk"
    return (Test-Path $ShortcutPath)
}

#endregion

#endregion

#region ---Task Status Function---

# ======================================================================
# Show-TaskStatus
# Display the progress of tasks
# usage:
#      Show-TaskStatus -Current <CurrentTaskIndex> -Total <TotalTasks>
# ======================================================================


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
function Show-TaskSt111atus {
    param(
        [int]$Current,
        [int]$Total,
        [int[]]$FailedIndexes = @()
    )
    
    Clear-Host
    Show-Conflogo
    Write-Host ""
    Write-Host "[*]--- Task Status ---[*]" -ForegroundColor Cyan -BackgroundColor Black
    
    for ($i = 0; $i -lt $Total; $i++) {
        $taskNumber = $i + 1
        
        if ($FailedIndexes -contains $i) {
            Write-Host "[-] Task $taskNumber (failed)" -ForegroundColor Red -BackgroundColor Black
        }
        elseif ($i -lt $Current) {
            Write-Host "[+] Task $taskNumber (completed)" -ForegroundColor Green -BackgroundColor Black
        }
        elseif ($i -eq $Current) {
            Write-Host "[>] Task $taskNumber (in progress)" -ForegroundColor Yellow -BackgroundColor Black
        }
        else {
            Write-Host "[ ] Task $taskNumber (pending)" -ForegroundColor Gray -BackgroundColor Black
        }
    }
    Write-Host ""
}

function Show-TaskStatus {
    param(
        [int]$Current,
        [int]$Total,
        [int[]]$FailedIndexes = @()
    )
    
    # Clear screen and show logo
    Clear-Host
    Show-Conflogo
    Write-Host ""

    # Calculate statistics
    $completed = $Current
    $failed = $FailedIndexes.Count
    $pending = $Total - $completed - $failed
    
    # Display summary statistics
    Write-Host "[*] Task Status [*]" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "[*] Total Tasks: $Total" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "[*] Completed: $completed" -ForegroundColor Green -BackgroundColor Black
    Write-Host "[*] Failed: $failed" -ForegroundColor Red -BackgroundColor Black
    Write-Host "[*] Pending: $pending" -ForegroundColor Yellow -BackgroundColor Black
    Write-Host ""
}

#endregion

#region ---Log and Report Function---

#region ---New-ConfigurationReport---

# ======================================================================
# New-ConfigurationReport
# Generate a configuration summary report
# usage:
#      New-ConfigurationReport -Path "<Path>" -TasksExecuted <Number> -Username "<UserName>" -LogFile "<LogFile>" [-SuccessfulTasks <Number>] [-FailedTaskNumbers <Array>] [-SystemName "<Name>"] [-ConfigurationType "<Type>"]
# ======================================================================

function New-ConfigurationReport {
    param (
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TasksExecuted,
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][string]$LogFile,
        [Parameter(Mandatory = $false)][int]$SuccessfulTasks,
        [Parameter(Mandatory = $false)][array]$FailedTaskNumbers = @(),
        [Parameter(Mandatory = $false)][string]$SystemName = $env:COMPUTERNAME,
        [Parameter(Mandatory = $false)][string]$ConfigurationType = "Standard Configuration"
    )

    # Use safe timestamp for filenames
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $ReportPath = Join-Path $Path "${timestamp}_Configuration_Report.txt"
    
    # Ensure the directory exists
    $ReportDir = Split-Path $ReportPath -Parent
    if (!(Test-Path $ReportDir)) {
        try {
            New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
        }
        catch {
            Write-Log "Failed to create directory: $ReportDir. Error: $($_.Exception.Message)" -Level "ERROR"
            return
        }
    }

    # Calculate metrics properly - fix the inconsistency
    $FailedCount = if ($FailedTaskNumbers) { $FailedTaskNumbers.Count } else { 0 }
    $SuccessfulTasks = $TasksExecuted - $FailedCount
    
    $SuccessRate = if ($TasksExecuted -gt 0) { 
        [math]::Round(($SuccessfulTasks / $TasksExecuted) * 100, 2) 
    } else { 
        0 
    }
    
    $FailedNumbersList = if ($FailedTaskNumbers -and $FailedTaskNumbers.Count -gt 0) { 
        $FailedTaskNumbers -join ", " 
    } else { 
        "None" 
    }

    # Generate professional report content
    $ReportContent = @"
===============================================================
               CONFIGURATION EXECUTION REPORT
===============================================================

REPORT METADATA
----------------
Report Generated:    $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Configuration Type:  $ConfigurationType
System:              $SystemName
User:                $Username
Report ID:           $([System.Guid]::NewGuid().ToString())

EXECUTION SUMMARY
------------------
Total Tasks:         $TasksExecuted
Successful:          $SuccessfulTasks
Failed:              $FailedCount
Success Rate:        $SuccessRate%

DETAILED BREAKDOWN
-------------------
$(if ($SuccessfulTasks -gt 0) {
    "✓ Completed Tasks:  $SuccessfulTasks"
} else {
    "✗ No Tasks Completed"
})
✗ Failed Tasks:      $FailedCount
$(if ($FailedCount -gt 0) {
    "• Failed Task IDs:  $FailedNumbersList`n"
} else {
    "• All tasks completed successfully`n"
})
RECOMMENDATIONS
----------------
$(if ($FailedCount -gt 0) {
    @"

• Review failed tasks in the log file for detailed error information
• Verify system requirements and dependencies
• Consider re-executing failed tasks after addressing underlying issues
"@
} else {
    @"
• Configuration completed successfully - no action required
• Monitor system performance to ensure configuration stability
• Archive this report for documentation purposes
"@
})

LOG FILE 
---------
Location:            $LogFile
Size:                $(if (Test-Path $LogFile) { 
    $size = (Get-Item $LogFile).Length
    if ($size -gt 1MB) { 
        "{0:N1} MB" -f ($size / 1MB) 
    } elseif ($size -gt 1KB) { 
        "{0:N1} KB" -f ($size / 1KB) 
    } else { 
        "$size bytes" 
    }
} else { 
    "File not found" 
})
Last Modified:       $(if (Test-Path $LogFile) { 
    (Get-Item $LogFile).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
} else { 
    "N/A" 
})

===============================================================
               END OF REPORT
===============================================================
"@

    try {
        Set-Content -Path $ReportPath -Value $ReportContent -Encoding UTF8 -ErrorAction Stop
        Write-Log "Configuration report generated successfully: $ReportPath" -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to create configuration report: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

#endregion

#region ---Write-Log---

# ======================================================================
# Write-Log
# Log messages to console and file
# usage:
#      Write-Log -Message "<Message>" -Level "<INFO|SUCCESS|WARN|ERROR>"
# ======================================================================

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Level = "INFO"
    )


    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console with colors
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red -BackgroundColor Black }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow -BackgroundColor Black }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green -BackgroundColor Black }
        default { Write-Host $logEntry -ForegroundColor White -BackgroundColor Black }
    }
    
    # Write to log file
    try {
        Add-Content -Path $global:LogFile -Value $logEntry -ErrorAction Stop
    } catch {
        Write-Host "Failed to write to log file: $_" -ForegroundColor Red
    }
}

#endregion

#endregion

#region ---Cleanup Task Function---

#region ---Invoke-CleanupTask---

# ======================================================================
# Invoke-CleanupTask
# Perform final cleanup tasks after configuration
# usage:
#      Invoke-CleanupTask
# ======================================================================

function Invoke-CleanupTask {
    Write-Log "Running final cleanup task..." -Level "INFO"
    Remove-Item $global:FlagPath -ErrorAction SilentlyContinue
    Remove-StartupScript
    Remove-AutoLogon
    Write-Log "Cleanup task completed. Configuration finished." -Level "SUCCESS"
}

#endregion

#region ---Enable-AutoLogonWithScript---

# ======================================================================
# Enable-AutoLogonWithScript
# Enable auto-login and ensure startup script exists
# usage:
#      Enable-AutoLogonWithScript -TaskNumber <Number> -ScriptPath "<PathToScript>" -Username "<UserName>" -PasswordPlain "<Password>"
# ======================================================================

function Enable-AutoLogonWithScript {
    param (
        [Parameter(Mandatory = $true)][int]$TaskNumber,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][string]$PasswordPlain
    )
    
    # Check if auto-login is already enabled for the correct user
    if (Test-AutoLogon -Username $Username) {
        Write-Log "Auto-login is already enabled for $Username" -Level "INFO"
    } else {
        Write-Log "Enabling auto-login..." -Level "INFO"
        Set-AutoLogon -Username $Username -PasswordPlain $PasswordPlain
        Write-Log "Auto-login enabled for $Username" -Level "SUCCESS"
    }
    
    # Check if startup script already exists
    if (Test-StartupScript) {
        Write-Log "Startup script already exists" -Level "INFO"
    } else {
        Add-StartupScript -ScriptPath $ScriptPath -TaskNumber $TaskNumber
    }
}

#endregion

#endregion

#region ---DHCP---

#region ---New-Dhcp4Scope---

# ======================================================================
# New-Dhcp4Scope
# Create a DHCPv4 scope (installs DHCP role if missing).
# usage: New-Dhcp4Scope -ScopeName "MyScope" -StartRange 192.168.1.10 -EndRange 192.168.1.200
# ======================================================================

 function New-Dhcp4Scope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$ScopeName,
        [Parameter(Mandatory = $true)][string]$StartRange,
        [Parameter(Mandatory = $true)][string]$EndRange,
        [Parameter(Mandatory = $false)][string]$SubnetMask = "255.255.255.0",
        [Parameter(Mandatory = $false)][TimeSpan]$LeaseDuration = (New-TimeSpan -Days 8),
        [Parameter(Mandatory = $false)][string]$State = "Active",
        [Parameter(Mandatory = $false)][string]$Description
    )



# Set default description if not provided
if (-not $Description) {
    $Description = "New DHCP scope created at $(Get-Date) with name: $ScopeName"
}

#region Validate IP addresses
    function Test-ValidIPAddress($IP) {
        try {
            [System.Net.IPAddress]::Parse($IP) | Out-Null
            return $true
        }
        catch {
            return $false
        }
    }
    if (-not (Test-ValidIPAddress $StartRange)) { throw "Invalid IP address provided for -StartRange: $StartRange" }
    if (-not (Test-ValidIPAddress $EndRange)) { throw "Invalid IP address provided for -EndRange: $EndRange" }
    if (-not (Test-ValidIPAddress $SubnetMask)) { throw "Invalid subnet mask provided: $SubnetMask" }

#endregion

#region Check DHCP feature
    
    Write-Verbose "Checking if DHCP role is installed..."
    $dhcpFeature = Get-WindowsFeature -Name DHCP -ErrorAction Stop -Verbose:$false
    if (-not $dhcpFeature.Installed) {
        Write-Verbose "Installing DHCP Server role..."
        Install-WindowsFeature -Name DHCP -IncludeManagementTools -ErrorAction Stop -Verbose:$false
        Write-Verbose "DHCP Server role installed successfully."
    } else {
        Write-Verbose "DHCP Server role is already installed."
    }

#endregion

#region Create DHCP Scope
    
    try {
        $existingScope = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $ScopeName -or ($_.StartRange.ToString() -eq $StartRange -and $_.EndRange.ToString() -eq $EndRange) }
        if ($existingScope) {
            Write-Warning "A DHCP scope with name '$ScopeName' or range ($StartRange - $EndRange) already exists."
            $success = $false
        } else {
            Write-Verbose "Creating DHCP scope: $ScopeName ..."
            Add-DhcpServerv4Scope -Name $ScopeName `
                -StartRange $StartRange `
                -EndRange $EndRange `
                -SubnetMask $SubnetMask `
                -LeaseDuration $LeaseDuration `
                -Description $Description `
                -State $State -ErrorAction Stop
            Write-Verbose "DHCP scope '$ScopeName' created successfully."
            Restart-Service DHCPServer -Verbose:$false -Force:$true
            netsh dhcp add securitygroups > $null 2>&1
            Add-DhcpServerSecurityGroup -Verbose:$false
            Restart-Service DHCPServer -Verbose:$false -Force:$true
        
        }
    }
    catch {
        Write-Warning "Failed to create DHCP scope '$ScopeName'. Error: $($_.Exception.Message)"
        $success = $false
    }

#endregion

Write-Host "[+] DHCP Creating Scope Completed successfully" -ForegroundColor Green -BackgroundColor Black

}

#endregion

#region ---Install-DhcpAndAuthorize---

# ======================================================================
# Install-DhcpAndAuthorize
# Install DHCP role (if missing) and authorize DHCP server in AD
# usage: Install-DhcpAndAuthorize [-DnsName dns.example.com] [-IpAddress 192.168.1.5]
# ======================================================================

 function Install-DhcpAndAuthorize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)][string]$DnsName ,
        [Parameter(Mandatory = $false)][string]$IpAddress 
    )

#region Install DHCP Rool if missing
    
    try {
        $dhcpFeature = Get-WindowsFeature -Name DHCP -ErrorAction Stop -Verbose:$false
        if (-not $dhcpFeature.Installed) {            
            Write-Verbose "Installing DHCP Server role..."
            Install-WindowsFeature -Name DHCP -IncludeManagementTools -ErrorAction Stop -Verbose:$false
            Write-Verbose "DHCP Server role installed successfully." 
        } else {
            Write-Verbose "DHCP Server role is already installed."
        }
    }
    catch {
        Write-Warning "Failed to install DHCP Server role. Error: $($_.Exception.Message)"
    }

#endregion

function Test-ValidIPAddress($IP) {
        try {
            [System.Net.IPAddress]::Parse($IP) | Out-Null
            return $true
        }
        catch {
            return $false
        }
    }

#region Authorize DHCP in Active Directory
    
    if (-not $IpAddress) {
        $Pc_Name =  (Get-CimInstance Win32_ComputerSystem -Verbose:$false).Name 
        $Domain_Name = (Get-ADDomain -Verbose:$false ).DNSRoot    
        $DnsName = $Pc_Name +'.'+ $Domain_Name
    }

    if (-not $IpAddress) {
        $IpAddress = (Get-NetIPAddress -AddressFamily IPv4 -Verbose:$false | Where-Object { $_.IPAddress -notmatch '^169\.|^127\.' }).IPAddress 
    }else {
        if (-not (Test-ValidIPAddress $IpAddress )) { throw "Invalid IP address provided for -IpAddress: $IpAddress" }
    }

    try {
        $isAuthorized = Get-DhcpServerInDC -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $IpAddress -and $_.DnsName -eq $DnsName }
        if (-not $isAuthorized) {
            Write-Verbose "Authorizing DHCP server in Active Directory..."
            Add-DhcpServerInDC -DnsName $DnsName -IPAddress $IpAddress -ErrorAction Stop -Verbose:$false
            Write-Verbose "DHCP server authorized successfully in Active Directory." 
        } else {
            Write-Verbose "DHCP server ($DnsName, $IpAddress) is already authorized in Active Directory."
        }
    }
    catch {
        Write-Warning "Failed to authorize DHCP server in AD. Error: $($_.Exception.Message)"
    }

#endregion

Write-Host "[+] DHCP Installing and Authorizing Completed" -ForegroundColor Green -BackgroundColor Black

}

#endregion

#region ---Add-DhcpServer---

# ======================================================================
# Add-DhcpServer
# Convenience wrapper: install & authorize (if needed) then create scope
# usage: Add-DhcpServer -ScopeName "MyScope" -StartRange 192.168.1.10 -EndRange 192.168.1.200
# ======================================================================

 function Add-DhcpServer {
   [CmdletBinding()]
    param (

        # DHCP Authorization
        [Parameter(Mandatory = $false)][string]$DnsName ,
        [Parameter(Mandatory = $false)][string]$IpAddress ,

        # DHCP Scope parameters
        [Parameter(Mandatory = $true)][string]$ScopeName,
        [Parameter(Mandatory = $true)][string]$StartRange,
        [Parameter(Mandatory = $true)][string]$EndRange,
        [Parameter(Mandatory = $false)][string]$SubnetMask = "255.255.255.0",
        [Parameter(Mandatory = $false)][TimeSpan]$LeaseDuration = (New-TimeSpan -Days 8), 
        [Parameter(Mandatory = $false)][ValidateSet("Active", "Inactive")][string]$State = "Active",
        [Parameter(Mandatory = $false)][string]$Description
    )

 $success = $true
 Write-Host "[+] Running..." -ForegroundColor Green -BackgroundColor Black

#region Validate IP addresses

    function Test-ValidIPAddress($IP) {
        try {
            [System.Net.IPAddress]::Parse($IP) | Out-Null
            return $true
        }
        catch {
            return $false
        }
    }
    if (-not (Test-ValidIPAddress $StartRange)) { throw "Invalid IP address provided for -StartRange: $StartRange" }
    if (-not (Test-ValidIPAddress $EndRange)) { throw "Invalid IP address provided for -EndRange: $EndRange" }
    if (-not (Test-ValidIPAddress $SubnetMask)) { throw "Invalid subnet mask provided: $SubnetMask" }

#endregion
    
#region Set default description if not provided

    if (-not $Description) {
        $Description = "New DHCP scope created at $(Get-Date) with name: $ScopeName"
    }

#endregion

#region Install DHCP Rool if missing
    
    try {
        $dhcpFeature = Get-WindowsFeature -Name DHCP -ErrorAction Stop -Verbose:$false
        if (-not $dhcpFeature.Installed) {            
            Write-Verbose "Installing DHCP Server role..."
            Install-WindowsFeature -Name DHCP -IncludeManagementTools -ErrorAction Stop -Verbose:$false
            Write-Verbose "DHCP Server role installed successfully." 
        } else {
            Write-Verbose "DHCP Server role is already installed."
        }
    }
    catch {
        Write-Warning "Failed to install DHCP Server role. Error: $($_.Exception.Message)"
        $success = $false
    }

#endregion

#region Authorize DHCP in Active Directory
    
    if (-not $IpAddress) {
        $Pc_Name =  (Get-CimInstance Win32_ComputerSystem -Verbose:$false).Name 
        $Domain_Name = (Get-ADDomain -Verbose:$false ).DNSRoot    
        $DnsName = $Pc_Name +'.'+ $Domain_Name
    }

    if (-not $IpAddress) {
        $IpAddress = (Get-NetIPAddress -AddressFamily IPv4 -Verbose:$false | Where-Object { $_.IPAddress -notmatch '^169\.|^127\.' }).IPAddress 
    }else {
        if (-not (Test-ValidIPAddress $IpAddress )) { throw "Invalid IP address provided for -IpAddress: $IpAddress" }
    }

    try {
        $isAuthorized = Get-DhcpServerInDC -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $IpAddress -and $_.DnsName -eq $DnsName }
        if (-not $isAuthorized) {
            Write-Verbose "Authorizing DHCP server in Active Directory..."
            Add-DhcpServerInDC -DnsName $DnsName -IPAddress $IpAddress -ErrorAction Stop -Verbose:$false
            Write-Verbose "DHCP server authorized successfully in Active Directory." 
        } else {
            Write-Verbose "DHCP server ($DnsName, $IpAddress) is already authorized in Active Directory."
        }
    }
    catch {
        Write-Warning "Failed to authorize DHCP server in AD. Error: $($_.Exception.Message)"
        $success = $false
    }

#endregion

#region Create DHCP Scope
    
    try {
        #$existingScope = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $ScopeName -or ($_.StartRange -eq $StartRange -and $_.EndRange -eq $EndRange) }
        $existingScope = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $ScopeName -or ($_.StartRange.ToString() -eq $StartRange -and $_.EndRange.ToString() -eq $EndRange) }
        if ($existingScope) {
            Write-Warning "A DHCP scope with name '$ScopeName' or range ($StartRange - $EndRange) already exists."
            $success = $false
        } else {
            Write-Verbose "Creating DHCP scope: $ScopeName ..."
            Add-DhcpServerv4Scope -Name $ScopeName `
                -StartRange $StartRange `
                -EndRange $EndRange `
                -SubnetMask $SubnetMask `
                -LeaseDuration $LeaseDuration `
                -Description $Description `
                -State $State -ErrorAction Stop
            Write-Verbose "DHCP scope '$ScopeName' created successfully."
        }
    }
    catch {
        Write-Warning "Failed to create DHCP scope '$ScopeName'. Error: $($_.Exception.Message)"
        $success = $false
    }

#endregion



    if ($success) {
        Restart-Service DHCPServer -Verbose:$false -Force:$true
        netsh dhcp add securitygroups > $null 2>&1
        Add-DhcpServerSecurityGroup -Verbose:$false
        Restart-Service DHCPServer -Verbose:$false -Force:$true
        Write-Host "[+] DHCP Deployment Completed" -ForegroundColor Green -BackgroundColor Black

    } else {
        Write-Warning "DHCP Deployment completed with errors. Check logs for details."
    }

}

#endregion

#endregion

