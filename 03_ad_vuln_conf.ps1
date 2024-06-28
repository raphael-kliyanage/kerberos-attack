# Name          : 03_ad_vuln_conf.ps1
# Description   : Configure in a vulnerable way 3 users
# Param 1       : N/A
# Param 2       : N/A
#
# Exemple       : .\02_ad_installation.ps1
#
# Author        : Mathis THOUVENIN, Raphaël KATHALUWA-LIYANAGE, Lyronn LEVY
# Changelog     :
# Version       : 0.3.1
#
#

# creating the users
net.exe user u_kerberoast "P@ssw0rd" /add /domain
net.exe user u_asreproast "P@ssw0rd" /add /domain
net.exe user u_generic "P@ssw0rd" /add /domain

# adding an arbitrary SPN for u_kerberoast
setspn.exe -S HTTP/FAKE01.ADTEST.LOCAL u_kerberoast

# disable pre-authentication on u_asreproast
Set-ADAccountControl -DoesNotRequirePreAuth $True -Identity u_asreproast

# Add GenericWrite for u_generic user on DC01
Import-Module ActiveDirectory

# Define the computer and user
$computerName = "DC01"
$user = "u_generic"

# Get the current security descriptor of the computer object
$computer = Get-ADComputer $computerName -Properties nTSecurityDescriptor
$acl = $computer.nTSecurityDescriptor

# Define the new access rule
$identity = New-Object System.Security.Principal.NTAccount($user)
$rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
$type = [System.Security.AccessControl.AccessControlType]::Allow
$accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, $type)

# Add the new access rule to the security descriptor
$acl.AddAccessRule($accessRule)

# Apply the modified security descriptor back to the computer object
Set-ADComputer $computerName -Replace @{nTSecurityDescriptor=$acl}

