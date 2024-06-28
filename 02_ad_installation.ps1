# Name          : 02_ad_installation.ps1
# Description   : Install ADDS & DNS
# Param 1       : N/A
# Param 2       : N/A
#
# Exemple       : .\02_ad_installation.ps1
#
# Author        : Mathis THOUVENIN, Raphaël KATHALUWA-LIYANAGE, Lyronn LEVY
# Changelog     :
# Version       : 1
#
#

# Parameters
$domainName = "EXAM.LOCAL"
$domainNetBIOSName = "EXAM"
$mode = "WinThreshold"

### Install AD DS and DNS roles
Install-WindowsFeature -Name AD-Domain-Services,DNS -IncludeManagementToo

# Promoting the server to domain controller
Install-ADDSForest -DomainName $domainName -DomainNetBIOSName $domainNetBIOSName -ForestMode $mode -DomainMode $mode -Force:$true -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -LogPath "C:\Windows\NTDS" -SysvolPath "C:\Windows\SYSVOL" -NoRebootOnCompletion:$false

# Restart the server to apply the changes
Restart-Computer -Force
