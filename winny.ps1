# Powershell script to enumerate Windows OS for privilege escalation vectors.
# Project was created for use in OSCP Exam environments to automate manual enumeration commands.
# Author: Br41n41 (https://github.com/Br14n41)
# Version: 1.0
# Date: 2024-05-13
# Usage: powershell -ep bypass -File winny.ps1

# Let's gather whoami details
Write-Host "Whoami Details" -ForegroundColor Green
Write-Host "==============" -ForegroundColor Green
whoami /all

# Let's get a tree view of the C:\Users directory
# Write-Host "C:\Users Directory Tree" -ForegroundColor Green
# Write-Host "======================" -ForegroundColor Green
# tree C:\Users 

# Let's enumerate the kernel details
Write-Host "Kernel Details" -ForegroundColor Green
Write-Host "==============" -ForegroundColor Green
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)" /C:"Domain" 
Write-Host "`n"

# Let's enumerate the Environment Variables
Write-Host "Environment Variables" -ForegroundColor Green
Write-Host "=====================" -ForegroundColor Green
Get-ChildItem Env: | ft Key,Value 

# Let's enumerate PowerShell History
Write-Host "PowerShell History" -ForegroundColor Green
Write-Host "===================" -ForegroundColor Green
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    Get-Content -Path $historyPath 
} else {
    Write-Host "PowerShell history file not found." -ForegroundColor Red
}
Write-Host "`n"

# Let's view drives
Write-Host "Drives" -ForegroundColor Green
Write-Host "======" -ForegroundColor Green
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root 

# Let's enumerate users and groups
Write-Host "Users and Groups" -ForegroundColor Green
Write-Host "=================" -ForegroundColor Green
Get-WmiObject -Class Win32_UserAccount 
Get-LocalUser | ft Name,Enabled,LastLogon 
Get-ChildItem C:\Users -Force | select Name 
Get-LocalGroupMember Administrators | ft Name, PrincipalSource 

# Let's check the clipboard content
Write-Host "Clipboard Content" -ForegroundColor Green
Write-Host "=================" -ForegroundColor Green
Get-Clipboard 
Write-Host "`n"

# Let's check for installed applications and ignore the Microsoft ones
Write-Host "Installed Applications" -ForegroundColor Green
Write-Host "======================" -ForegroundColor Green
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "Microsoft*" -and $_.DisplayName -notlike "Windows*"} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ft -AutoSize
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "Microsoft*" -and $_.DisplayName -notlike "Windows*"} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ft -AutoSize

# Let's check for installed applications in Program Files and Program Files (x86)
Write-Host "Installed Applications in Program Files" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime

# Let's check for installed applications in ProgramData
Write-Host "Installed Applications in ProgramData" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green
Get-ChildItem 'C:\ProgramData' | ft Parent,Name,LastWriteTime

# Let's check for installed applications in AppData
Write-Host "Installed Applications in AppData" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Get-ChildItem 'C:\Users\*\AppData\Local' | ft Parent,Name,LastWriteTime

# Let's check for scheduled tasks, omitting the Microsoft ones
Write-Host "Scheduled Tasks" -ForegroundColor Green
Write-Host "===============" -ForegroundColor Green
Get-ScheduledTask | where {$_.TaskPath -notlike "*Microsoft*" -or $_.TaskPath -notlike "*Windows*"} | ft TaskName,TaskPath,State 

# Let's check network interfaces and DNS
Write-Host "Network Interfaces and DNS" -ForegroundColor Green
Write-Host "===========================" -ForegroundColor Green
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address 
Get-DnsClientServerAddress -AddressFamily IPv4 | ft InterfaceAlias,ServerAddresses 

# Let's check for network shares
Write-Host "Network Shares" -ForegroundColor Green
Write-Host "==============" -ForegroundColor Green
Get-WmiObject -Class Win32_Share | Select-Object Name, Path 

# Let's check for network connections in Listen or Established state
Write-Host "Network Connections" -ForegroundColor Green
Write-Host "===================" -ForegroundColor Green 
Get-NetTCPConnection | where {$_.State -eq "Listen" -or $_.State -eq "Established"} | ft LocalAddress,LocalPort,RemoteAddress,RemotePort,State 

# Let's check for firewall status
Write-Host "Firewall Status" -ForegroundColor Green
Write-Host "==============" -ForegroundColor Green
Get-NetFirewallProfile | ft Name,Enabled 

# Let's check for web configuration files and print a message in the console if nothing is found
Write-Host "Web Configuration Files" -ForegroundColor Green
Write-Host "===================" -ForegroundColor Green
Get-Childitem -Path C:\inetpub\ -Filter web.config -Recurse -ErrorAction SilentlyContinue
Get-Childitem -Path C:\wwwroot\ -Filter web.config -Recurse -ErrorAction SilentlyContinue 
Get-Childitem -Path C:\xampp\ -Filter web.config -Recurse -ErrorAction SilentlyContinue 
Get-Childitem -Path C:\wamp\ -Filter web.config -Recurse -ErrorAction SilentlyContinue 
Get-Childitem -Path C:\apache\ -Filter web.config -Recurse -ErrorAction SilentlyContinue
if (-not (Get-Childitem -Path C:\inetpub\ -Filter web.config -Recurse -ErrorAction SilentlyContinue) -and -not (Get-Childitem -Path C:\wwwroot\ -Filter web.config -Recurse -ErrorAction SilentlyContinue) -and -not (Get-Childitem -Path C:\xampp\ -Filter web.config -Recurse -ErrorAction SilentlyContinue) -and -not (Get-Childitem -Path C:\wamp\ -Filter web.config -Recurse -ErrorAction SilentlyContinue) -and -not (Get-Childitem -Path C:\apache\ -Filter web.config -Recurse -ErrorAction SilentlyContinue)) {
    Write-Host "No web configuration files found." -ForegroundColor Red
}

