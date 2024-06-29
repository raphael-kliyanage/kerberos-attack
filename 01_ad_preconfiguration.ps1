# Name          : 01_ad_preconfiguration.ps1
# Description   : Configure IP Address and Computer Name
# Param 1       : N/A
# Param 2       : N/A
#
# Exemple       : .\01_ad_preconfiguration.ps1
#
# Author        : Mathis THOUVENIN, Raphaël KATHALUWA-LIYANAGE, Lyronn LEVY
# Changelog     :
# Version       : 1.0.1
#
#

### Edit these values to match your desired configuration
$computer_name = "DC01"
$ip_addr = "192.168.1.52"
$cidr = 24
$gateway = "192.168.1.1"
$dns = "192.168.1.52,192.168.1.1"

### IP configuration
# get interface name
Get-NetAdapter | Select-Object ifIndex, Name, Description, MacAddress, Status
$interface_name = Read-Host "Select the Name of the interface to configure"

# Remove the static ip
Remove-NetIPAddress -InterfaceAlias $interface_name -Confirm:$false
# Remove the default gateway
Remove-NetRoute -InterfaceAlias $interface_name - -Confirm:$false

# configuring new static IPv4
New-NetIPAddress -InterfaceAlias $interface_name -AddressFamily IPv4 -IPAddress $ip_addr -PrefixLength $cidr -DefaultGateway $gateway -Confirm:$false -Verbose
# configuring new stattic DNS for IPv4
Set-DnsClientServerAddress -InterfaceAlias $interface_name -ServerAddresses $dns -Confirm:$false

# IPv6
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -Confirm:$false

# choose to either rename or rename and join a domain in one go
$renaming = 0
while($renaming -ne 1) {
    $choice = Read-Host "Would you like to join a domain? (y/n)"
    switch ($choice) {
        "n" {Rename-Computer -ComputerName $env:COMPUTERNAME -NewName $computer_name -Restart; Break}
        "y" {Add-Computer -ComputerName $env:COMPUTERNAME -DomainName $domain -NewName $computer_name -Restart; Break}
        Default {"Please answer by either 'y' or 'n'!"}
    }
}
