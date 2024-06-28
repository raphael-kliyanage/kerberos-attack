<#
.SYNOPSIS
   Remediation for Kerberos attacks 

.DESCRIPTION
    This script remediates asreproast, kerberoast and RBCD attacks.
    We tried to follow the ANSSI guidelines for passowrd policy:
    - R10: Lockout threshold
    - R21: Minimum password length
    - R22: No Maximum password lenght
    - R23: Complex passwords
    - R24: No password expiration for unprivileged users

.EXAMPLE
    .\04_remediation_script.ps1
#>

# Asreproasting attack
# List users with pre-authentication deactivated and disable this setting

Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $True' `
| Set-ADAccountControl -DoesNotRequirePreAuth $False

# Kerberoasting
# Create a strong password policy

New-ADFineGrainedPasswordPolicy `
 -Name "PSO_BasicPasswordPolicy" `
 -DisplayName "PSO_BasicPasswordPolicy" `
 -Precedence 10 `
 -MinPasswordLength 12 `
 -PasswordHistoryCount 6 `
 -ReversibleEncryptionEnabled $False `
 -ComplexityEnabled $True `
 -LockoutThreshold 3 `
 -LockoutObservationWindow "0.01:00:00" `
 -LockoutDuration "0.01:00:00" `
 -MinPasswordAge "1.00:00:00" `
 -MaxPasswordAge "0.00:00:00" `
 -ProtectedFromAccidentalDeletion $True

# Apply the password policy to a specific group

Add-ADFineGrainedPasswordPolicySubject "PSO_BasicPasswordPolicy" `
 -Subjects "MyGroup"

# List all Password Settings Object

Get-ADFineGrainedPasswordPolicy -Filter *
