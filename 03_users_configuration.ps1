<#
.SYNOPSIS
    Creating users in an Active Directory. 

.DESCRIPTION
    This script creates three users and ask the administrator to enter their
    password. For education purposes, an SPN is added, pre-authentication is
    deactivated and Generic rights are added.

.EXAMPLE
    .\03_users_configuration.ps1
#>

[String[]] $UserList = @(
    'u_kerberoast',
    'u_asreproast',
    'u_generic'
)

foreach ($Item in $UserList) {

        $SecurePassword = Read-Host "Enter a password for the user ` 
         ${Item}: " -AsSecureString -MaskInput 
        New-ADUser -Name $Item -AccountPassword $SecurePassword `
         -Enabled $True

}

# Add SPN to u_kerberoast user

Set-ADUser $UserList[0] `
 -ServicePrincipalNames @{Add="HTTP/FAKE01.ADTEST.LOCAL"}

# Deactivate pre-authentication for u_asreproasting user

Set-ADAccountControl -DoesNotRequirePreAuth $True -Identity $UserList[1]

### Add GenericWrite for u_generic user on DC01
Import-Module ActiveDirectory

# Define the computer and user
$computerName = "DC01"

# Get the current security descriptor of the computer object
$computer = Get-ADComputer $computerName -Properties nTSecurityDescriptor
$ace = $computer.nTSecurityDescriptor

# Grant GenericWrite permission to u_generic user on DC01
$identity = New-Object System.Security.Principal.NTAccount($UserList[2])
$rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
$type = [System.Security.AccessControl.AccessControlType]::Allow
$accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, $type)

# Add the new access rule to the security descriptor
$ace.AddAccessRule($accessRule)

# Apply the modified security descriptor back to the computer object
Set-ADComputer $computerName -Replace @{nTSecurityDescriptor=$ace}

# updating the machine account of LPT01$ which acts as a compromised laptop
# to generate tickets on behalf of DC01$
net user 'LPT01$' 'P@ssw0rd' /domain