<#
.SYNOPSIS
   Remediation for Kerberos attacks 

.DESCRIPTION
    This script remediates asreproast, kerberoast and RBCD attacks 

.EXAMPLE
    .\04_remediation_script.ps1
#>

# Asreproasting attack
# List users with pre-authentication deactivated and disable this setting

Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $True' `
| Set-ADAccountControl -DoesNotRequirePreAuth $False
