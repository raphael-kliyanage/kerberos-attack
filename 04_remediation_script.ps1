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
Import-Module ActiveDirectory

function Repair-Asreproasting {
    # Asreproasting attack
    # List users with pre-authentication deactivated and disable this setting

    Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $True' `
    | Set-ADAccountControl -DoesNotRequirePreAuth $False

    Write-Host "[-] Pre-authentication deactivated for each users" -ForegroundColor Red

    Exit
}

function Repair-Kerberoasting {
    # Kerberoasting

    # Create a strong password policy for privileged users
    New-ADFineGrainedPasswordPolicy -Name "PSO_AdminPasswordPolicy" `
     -DisplayName "PSO_AdminPasswordPolicy" `
     -Precedence 1 `
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

    Write-Host "[+] Adminisatrator PSO created and applied!" -ForegroundColor Green
    
    # List all Password Settings Object

    Get-ADFineGrainedPasswordPolicy -Filter *

    # Importing GPOs to apply a general and modern password policy
    # Only domain admins can add computers to the domain
    Write-Host "[!] Importing ANSSI compliant GPOs..." -ForegroundColor Yellow
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

    Write-Host "[+] 2 ANSSI complaint GPOs imported successfuly!" -ForegroundColor Green

    # Applying the new GPOs
    gpupdate /force

    Write-Host "[+] New GPOs enforced!" -ForegroundColor Green
    Write-Host "[!] Reboot the device to apply printer spooler GPO." -ForegroundColor Yellow

    Exit
}

function Repair-RBCD {
    ### RBCD remediations
    # Get the list of all the ad computer objects
    $computers = Get-ADComputer -Filter *

    ### Clear the msDS-AllowedToActOnBehalfOfOtherIdentity for all computers
    foreach ($computer in $computers) {
        Set-ADComputer -Identity $computer.DistinguishedName `
            -Clear "msDS-AllowedToActOnBehalfOfOtherIdentity"
        Write-Host "[-] Remove 'msDS-AllowedToActOnBehalfOfOtherIdentity' attribute on $($computer.Name)" -ForegroundColor Red
    }

    # List of legitimate computers that must be kept
    $legit_computers = @("DC01", "LPT01")
    
    # List of non admin and legitimate users
    [String[]] $UserList = @(
        'u_kerberoast',
        'u_asreproast',
        'u_generic'
    )

    # List of priviledge and legitimate users
    [String[]] $AdminList = @(
        'Administrateur',
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
            Write-Host "[-] Removed GenericWrite on $($computer.Name)" -ForegroundColor Red

            # Creating the GenericAll permission to a user on a computer
            $identity = New-Object System.Security.Principal.NTAccount($Item)
            $rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
            $type = [System.Security.AccessControl.AccessControlType]::Allow
            $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, $type)

            # Remove the GenericAll ace on the computer
            $ace.RemoveAccessRule($accessRule)

            # Apply the modified security descriptor back to the computer object
            Set-ADComputer $computer -Replace @{nTSecurityDescriptor=$ace}
            Write-Host "[-] Removed GenericAll on $($computer.Name)" -ForegroundColor Red
        }
    }

    # Adding priviledged users in the "Protected Users" group
    foreach ($admin in $AdminList) {
        Add-ADGroupMember -Identity "Protected Users" -Members $admin
        Write-Host "[+] $admin added to `"Protected Users`" group" -ForegroundColor Green
    }

    # For safety reason (in the event of failures in the scripts)
    # unlegitimate computers will be deleted after clearing the attributes
    # and removing the ACEs
    foreach ($computer in $computers) {
        # if not in the whitelist, delete the computer object
        if ($legit_computers -notcontains $computer.Name.ToLower()) {
            Remove-ADComputer -Identity $computer.DistinguishedName `
                -Confirm:$false
            Write-Host "[-] Deleting $($computer.Name)" -ForegroundColor Red
        } else {
            Write-Host "[!] Keeping $($computer.Name)" -ForegroundColor Yellow
        }
    }

    Exit
}
function Main {
    [String[]] $MainMenu = @(
    '1: Fix Asreproasting',
    '2: Fix Kerberoasting',
    '3: Fix RBCD',
    '4: Quit program'
    )

    $quit = 0
    While ( $quit -ne 1 ) {
        # Display main menu
        $MainMenu
        $Choice = Read-Host "Please enter a number"
        Switch ( $Choice ) {
            1 { Repair-Asreproasting; $quit = 1 }
            2 { Repair-Kerberoasting; $quit = 1 }
            3 { Repair-RBCD; $quit = 1 }
            4 { Exit; $quit = 1  }
            Default { Write-Output "/!\ Please select a number displayed on the screen" }
        }
    }
}

Main
