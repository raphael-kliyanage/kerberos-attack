# PowerShell AD Configuration Project

This PowerShell project includes several scripts to configure a domain controller and clients, as well as manage user security. The scripts are designed to automate and simplify the configuration and remediation process in an Active Directory environment.

## Included Scripts

### 1. 01_ad_preconfiguration.ps1

**Description**: This script prepares for the installation of a domain controller by setting the machine name and necessary network parameters.

**Features**:
- Configures the domain controller's name.
- Sets network parameters (IP address, subnet mask, gateway, etc.).

### 2. 01b_client_installation.ps1

**Description**: This script configures a Windows 10 client to join the domain once the domain controller is installed.

**Features**:
- Initial setup of Windows 10.
- Prepares the client for integration into the Active Directory domain.

### 3. 02_ad_installation.ps1

**Description**: This script installs a primary domain controller in the Active Directory environment.

**Features**:
- Installs and promotes the server as a domain controller.
- Configures the necessary roles and services for the domain.

### 4. 03_users_configuration.ps1

**Description**: This script sets up three users in the domain with intentionally vulnerable configurations to test and evaluate security risks.

**Features**:
- Creates three user accounts.
- Configures the accounts to be intentionally vulnerable for attack scenarios.

### 5. 04_remediation_script.ps1

**Description**: This script remediates the vulnerabilities of the three previously configured users, while anticipating and managing related risks.

**Features**:
- Fixes vulnerabilities in user accounts.
- Implements security measures to prevent future attacks.