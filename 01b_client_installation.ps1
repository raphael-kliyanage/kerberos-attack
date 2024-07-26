# Name          : 01b_client_installation.ps1
# Description   : Configure IP Address and Computer Name
# Param 1       : N/A
# Param 2       : N/A
#
# Exemple       : .\01b_client_installation.ps1
#
# Author        : Mathis THOUVENIN, Raphaël KATHALUWA-LIYANAGE, Lyronn LEVY
# Changelog     :
# Version       : 1
#
#

# Ask for elevated permissions if required
## Escalating privilege to run the script on Windows
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

### Edit these values to match your desired configuration
$computer_name = "LPT01"
$domain = "EXAM.LOCAL"
# adjust the DNS record only and keep the D.N.S.1,D.N.S.2 format
# make sure the primary DNS is your Domain Controller's IP address
$dns = "192.168.1.52,192.168.1.1"

### IP configuration
# get interface name
Get-NetAdapter | Select-Object ifIndex, Name, Description, MacAddress, Status
$interface_name = Read-Host "Select the Name of the interface to configure (e.g. `"Ethernet`")"

# configuring new stattic DNS for IPv4
Write-Host "Configuring DNS addresses..."
Set-DnsClientServerAddress -InterfaceAlias $interface_name -ServerAddresses $dns -Confirm:$false

# IPv6
Write-Host "Disabling IPv6..."
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -Confirm:$false

# joining a domain and rename in one go
Write-Host "Joining $domain..."
Add-Computer -ComputerName $env:COMPUTERNAME -DomainName $domain -NewName $computer_name -Restart