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

# Deactivate pre-authentication for u_asreproas user

Set-ADAccountControl -DoesNotRequirePreAuth $True -Identity $UserList[1]
