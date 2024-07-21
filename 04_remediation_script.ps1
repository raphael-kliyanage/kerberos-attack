<#
.SYNOPSIS
   Remediation for Kerberos attacks 

.DESCRIPTION
    This script remediates asreproast, kerberoast and RBCD attacks.
    We tried to follow the ANSSI guidelines for password policy:
    - R10: Lockout threshold
    - R21: Minimum password length
    - R22: No Maximum password length
    - R23: Complex passwords
    - R24: No password expiration for unprivileged users

.EXAMPLE
    .\04_remediation_script.ps1
#>
# Ask for elevated permissions if required
## Escalating privilege to run the script on Windows
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

Import-Module ActiveDirectory

function Repair-Asreproasting {
    # Asreproasting attack
    # List users with pre-authentication deactivated and disable this setting

    Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $True' `
    | Set-ADAccountControl -DoesNotRequirePreAuth $False
}

function Repair-Kerberoasting {
    # Kerberoasting
    # Create a strong password policy for unprivileged users

    New-ADFineGrainedPasswordPolicy `
     -Name "PSO_UserPasswordPolicy" `
     -DisplayName "PSO_UserPasswordPolicy" `
     -Precedence 10 `
     -MinPasswordLength 12 `
     -PasswordHistoryCount 6 `
     -ReversibleEncryptionEnabled $False `
     -ComplexityEnabled $True `
     -LockoutThreshold 3 `
     -LockoutObservationWindow "0.01:00:00" `
     -LockoutDuration "0.00:30:00" `
     -MinPasswordAge "1.00:00:00" `
     -MaxPasswordAge "0.00:00:00" `
     -ProtectedFromAccidentalDeletion $True

    # Apply the password policy to domain users

    Add-ADFineGrainedPasswordPolicySubject "PSO_UserPasswordPolicy" `
     -Subjects "Utilisateurs du domaine"

    # Create a strong password policy for privileged users

    New-ADFineGrainedPasswordPolicy `
     -Name "PSO_AdminPasswordPolicy" `
     -DisplayName "PSO_AdminPasswordPolicy" `
     -Precedence 10 `
     -MinPasswordLength 16 `
     -PasswordHistoryCount 6 `
     -ReversibleEncryptionEnabled $False `
     -ComplexityEnabled $True `
     -LockoutThreshold 3 `
     -LockoutObservationWindow "0.01:00:00" `
     -LockoutDuration "0.01:00:00" `
     -MinPasswordAge "1.00:00:00" `
     -MaxPasswordAge "90.00:00:00" `
     -ProtectedFromAccidentalDeletion $True

    # Apply the password policy to domain admins

    Add-ADFineGrainedPasswordPolicySubject "PSO_AdminPasswordPolicy" `
     -Subjects "Admins du domaine"

    # List all Password Settings Object

    Get-ADFineGrainedPasswordPolicy -Filter *
}

function Repair-RBCD {
    ### RBCD remediations
    # Get the list of all the ad computer objects
    $computers = Get-ADComputer -Filter *

    ### Clear the msDS-AllowedToActOnBehalfOfOtherIdentity for all computers
    foreach ($computer in $computers) {
        Set-ADComputer -Identity $computer.DistinguishedName `
            -Clear "msDS-AllowedToActOnBehalfOfOtherIdentity"
    }

    # List of legitimate computers that must be kept
    $legit_computers = @("DC01", "LPT01")
    # List of non admin and legitimate users
    [String[]] $UserList = @(
        'u_kerberoast',
        'u_asreproast',
        'u_generic'
    )

    foreach ($Item in $UserList) {
        foreach($computer in $computers) {
            # Get the current security descriptor of the computer object
            $computer = Get-ADComputer $computer -Properties nTSecurityDescriptor
            $ace = $computer.nTSecurityDescriptor

            # Creating the GenericWrite permission to a user on a computer
            $identity = New-Object System.Security.Principal.NTAccount($Item)
            $rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
            $type = [System.Security.AccessControl.AccessControlType]::Allow
            $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, $type)

            # Remove the GenericWrite ace on the computer
            $ace.RemoveAccessRule($accessRule)

            # Apply the modified security descriptor back to the computer object
            Set-ADComputer $computer -Replace @{nTSecurityDescriptor=$ace}

            # Creating the GenericAll permission to a user on a computer
            $identity = New-Object System.Security.Principal.NTAccount($Item)
            $rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
            $type = [System.Security.AccessControl.AccessControlType]::Allow
            $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, $type)

            # Remove the GenericAll ace on the computer
            $ace.RemoveAccessRule($accessRule)

            # Apply the modified security descriptor back to the computer object
            Set-ADComputer $computer -Replace @{nTSecurityDescriptor=$ace}
        }
    }

    # For safety reason (in the event of failures in the scripts)
    # unlegitimate computers will be deleted after clearing the attributes
    # and removing the ACEs
    foreach ($computer in $computers) {
        # if not in the whitelist, delete the computer object
        if ($legit_computers -notcontains $computer.Name.ToLower()) {
            Write-Host "Deleting computer: $($computer.Name)"
            Remove-ADComputer -Identity $computer.DistinguishedName `
                -Confirm:$false
        } else {
            Write-Host "Keeping computer: $($computer.Name)"
        }
    }

    # add privileged users in the Protected Users
    Get-ADGroupMember "Administrateurs clés" | ForEach-Object {Add-ADGroupMember "Protected Users" $_ -Confirm:$false}
    Get-ADGroupMember "Administrateurs clés Enterprise" | ForEach-Object {Add-ADGroupMember "Protected Users" $_ -Confirm:$false}
    Get-ADGroupMember "Administrateurs de l’entreprise" | ForEach-Object {Add-ADGroupMember "Protected Users" $_ -Confirm:$false}
    Get-ADGroupMember "Administrateurs du schéma" | ForEach-Object {Add-ADGroupMember "Protected Users" $_ -Confirm:$false}
    Get-ADGroupMember "Admins du domaine" | ForEach-Object {Add-ADGroupMember "Protected Users" $_ -Confirm:$false}
    Get-ADGroupMember "Propriétaires créateurs de la stratégie de groupe" | ForEach-Object {Add-ADGroupMember "Protected Users" $_ -Confirm:$false}
    Get-ADGroupMember "Admins du domaine" | ForEach-Object {Add-ADGroupMember "Protected Users" $_ -Confirm:$false}

    # Getting all the members of the Schema Admins to empty it
    Get-ADGroupMember "Administrateurs du schéma" | ForEach-Object {Remove-ADGroupMember "Administrateurs du schéma" $_ -Confirm:$false}
    
    # Set all users with password never expires to false
    Get-ADUser -Filter 'Name -like "*"' | ForEach-Object {Set-ADUser $_ -PasswordNeverExpires 0}

    # Importing GPOs to apply a general and modern password policy
    # Only domain admins can add computers to the domain
    Write-Host "Importing GPOs..."
    Import-GPO -BackupGpoName 'Default Domain Policy' `
     -TargetName 'Default Domain Policy' `
     -path '.\gpo' `
     -CreateIfNeeded:$true `
     -Confirm:$false
    Import-GPO -BackupGpoName 'Default Domain Controllers Policy' `
     -TargetName 'Default Domain Controllers Policy' `
     -path '.\gpo' `
     -CreateIfNeeded:$true `
     -Confirm:$false

    # Applying the new GPOs
    gpupdate /force
}

function Main {
    [String[]] $MainMenu = @(
    '1: Fix Asreproasting',
    '2: Fix Kerberoasting',
    '3: Fix RBCD',
    '4: Quit program'
    )

    # Display main menu
    $MainMenu

    $Choice = Read-Host "Please enter a number"
    While (( $Choice -lt 1 ) -or ( $Choice -gt $MainMenu.Length)) {
        Write-Output "Please select a number displayed on the screen"
        $Choice = Read-Host "Please enter a number"
    }

    $MenuFunction = @(
    (Repair-Asreproasting),
    (Repair-Kerberoasting),
    (Repair-RBCD),
    {Exit}
    )

    $MenuFunction[$Choice - 1]
}

Main-Function
