# Name          : Script_Install_AD_DNS.ps1
# Description   : Install AD & DNS
# Param 1       :
# Param 2       :
#
# Exemple       : ./Script_Install_AD_DNS.ps1
#
# Author        : Mathis THOUVENIN, Raphaël KATHALUWA-LIYANAGE, Lyronn LEVY
# Changelog     :
# Version       : 0.7
#
#

### Edit these values to match your desired configuration
$computer_name = "DC01"
$ip_addr = "10.0.0.1"
$cidr = 24
$gateway = "10.0.0.251"
$dns = "10.0.0.1,1.0.0.1"
$interface_name = "Ethernet"

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

