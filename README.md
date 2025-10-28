
# ⚙️ AD-CONF – Active Directory & Network Configuration Module  

<img width="921" height="286" alt="image" src="https://github.com/user-attachments/assets/7f339b54-f78a-413b-bb08-89781d0841fd" />

> Developed by **Y. Janboubi** | Version: `1.0`

## 📌 Overview

**AD-CONF** is a PowerShell module for Windows Server infrastructure automation, providing comprehensive functions for Active Directory deployment, DNS/DHCP configuration, network setup, and user management. It is designed to help system administrators streamline Windows Server setup and configuration, while also supporting lab and test environments for efficient management and deployment.

---

## 🚀 Key Features  

- 🏢 **Active Directory**: Forest/domain deployment & object management  
- 🌐 **DNS**: Zone & record management (A, CNAME, MX, stub, secondary, conditional forwarders)  
- 📡 **DHCP**: Server configuration, scopes, and authorization  
- 🔧 **Network**: IPv4/IPv6 configuration, enable/disable features  
- 👤 **Users**: Bulk AD user creation, CSV import, random demo users  
- ⚙️ **System**: Computer rename, timezone, updates, RDP enablement  
- 📜 **Automation**: Sequential configuration tasks with auto-reboot & resume  

---

## 📦 Requirements  
 
- **Administrator privileges**  
- Active Directory PowerShell modules  
- Network connectivity  

---

## 📥 Installation

### Method 1: Clone Repository
### 🚀 Method 1: Clone Repository

```powershell
# Clone the AD-CONF repository
git clone https://github.com/Y-JANBOUBI/Ad-Conf

# Clone for Windows 
 curl "https://github.com/Y-JANBOUBI/Ad-Conf/archive/refs/heads/main.zip" -o "Ad-Conf.zip" ; Expand-Archive -Path "Ad-Conf.zip" -DestinationPath "." -Force

# Navigate into the project directory
cd Ad-Conf

# Run with interactive menu
.\Server-config.ps1 

# Or run in automated mode
.\Run_Option_0_.ps1 
````
---

### 📦 Method 2: Download ZIP

1. Go to the [AD-CONF GitHub repository](https://github.com/Y-JANBOUBI/Ad-Conf).
2. Click **Code** → **Download ZIP**.
3. Extract the archive to your desired folder.
4. Open **PowerShell** and navigate to the extracted folder 
5. Run the script as described in Method 1 
---

### 📝 Notes

* **Git required** for Method 1 (`git --version` to check).
* **Run PowerShell as Administrator** if elevated permissions are needed.
* If you face execution policy issues, set:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
---


## ⚡ Quick Start  

```powershell
# Import the module
Import-Module .\ADConf-Module.psm1

# Example: Install new AD Forest
$pass = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
Install-CustomADForest -DomainName "corp.local" -NetbiosName "CORP" -SafeModePassword $pass
````

For detailed help:
```powershell
# Import the ADConf module from the current directory
Import-Module -Name .\ADConf-Module.psm1

# List all commands/functions exported by the ADConf module
Get-Command -Module ADConf-Module

# Get detailed help/documentation for a specific function in the module
# Replace <FunctionName> with the actual function name you want help for
Get-Help <FunctionName> -Full
```

## 📊 Example Workflow

```powershell
# 1. Configure network
Set-StaticIPv4 -IPv4 "192.168.1.10" -Gateway "192.168.1.1" -DNS "8.8.8.8"

# 2. Rename server
Rename-ComputerSystem -Name "DC01"

# 3. Install AD Forest
$pass = ConvertTo-SecureString "StrongPass123!" -AsPlainText -Force
Install-CustomADForest -DomainName "company.local" -NetbiosName "COMPANY" -SafeModePassword $pass

# 4. Add DNS Zone
Add-DnsPrimaryForwardZone -Name "company.local" -ComputerName "DC01"
```

---

## 🛠️ Automation & Execution

The module includes **pre-configured automation scripts**:

```powershell
.\Server-config.ps1 # Interactive Menu

.\Run_Option_0_.ps1 # Automated Mode
```

### Interactive Menu

<img width="909" height="439" alt="image" src="https://github.com/user-attachments/assets/d95e097c-a542-4cac-8a04-3076c7700f54" />

### Automated Mode

<img width="1015" height="342" alt="image" src="https://github.com/user-attachments/assets/6e360330-44a0-44c8-a0ef-08c83c5ef079" />

---


## 📚 Functions Summary

### 🔹 Network Configuration

* `Set-StaticIPv4` – Configure IPv4, gateway & DNS
* `Set-StaticIPv6` – Configure IPv6, gateway & DNS
* `Disable-IPv6` – Disable IPv6

### 🔹 System Configuration

* `Disable-CtrlAltDel` – Enable/disable secure logon
* `Set-TimeZoneConfig` – Configure timezone
* `Rename-ComputerSystem` – Rename computer
* `Enable-RemoteDesktop` – Enable RDP + firewall rules
* `Update-WindowsSystem` – Install Windows updates

### 🔹 Active Directory

* `Install-CustomADForest` – Install AD DS & create new forest

### 🔹 DNS Management

* Zone functions: `Add-DnsPrimaryForwardZone`, `Add-DnsSecondaryZone`, `Add-DnsStubZone`, etc.
* Record functions: `Add-DnsARecord`, `Add-DnsCnameRecord`, `Add-DnsMxRecord`, etc.

### 🔹 AD Object Management

* `New-RandomADUser` – Bulk demo users
* `Import-CsvADUser` – Create OUs, groups & users from CSV
* `Test-CsvContent` – Validate CSV structure

### 🔹 DHCP Server

* `New-Dhcp4Scope` – Create new DHCP scope
* `Install-DhcpAndAuthorize` – Install & authorize DHCP server
* `Add-DhcpServer` – Complete DHCP setup

👉 Full list of **40+ functions** is included in the module.

---

# 👤 CSV User Import Format  

The CSV (`AD-Object.csv`) has **3 sections**, each starting with `:<Type>`:  

1- **:OU** → Organizational Units (`Name`)  
2- **:Group** → Groups (`Name,OU`)  
3- **:User** → Users (`GivenName,Surname,Group,OU,Description,EmailAddress`)  

---

## 📑 Example

```csv
:OU
Name
IT
Sales

:Group
Name,OU
Admins,IT
Managers,Sales

:User
GivenName,Surname,Group,OU,Description,EmailAddress
John,Doe,Admins,IT,IT Administrator,john.doe@corp.local
Jane,Smith,Managers,Sales,Sales Manager,jane.smith@corp.local
```
---

## 📂 Project Structure

```
AD-CONF/
│── ADConf-Module.psm1        # Core PowerShell module
│── Run_Option_0_.ps1         # Auto-execution script
│── Server-config.ps1         # Interactive menu script
│── AD-Object.csv             # CSV template for bulk users
│── Repo/
│    ├── ServerConfig.log     # Logs
│    ├── ConfigReport.txt     # Reports
```
---

## 📬 Contact

For questions, bug reports, contact me at [https://github.com/Y-JANBOUBI].

---

*Developed by Y. Janboubi.*  
*Version: 1.0*
