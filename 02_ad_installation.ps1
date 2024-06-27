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
