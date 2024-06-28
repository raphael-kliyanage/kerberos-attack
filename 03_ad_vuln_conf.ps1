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