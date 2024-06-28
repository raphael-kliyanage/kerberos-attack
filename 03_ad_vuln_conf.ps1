# creating the users
net.exe user u_kerberoast "P@ssw0rd" /add /domain
net.exe user u_asreproast "P@ssw0rd" /add /domain
net.exe user u_generic "P@ssw0rd" /add /domain

# adding an arbitrary SPN for u_kerberoast
setspn.exe -S HTTP/FAKE01.ADTEST.LOCAL u_kerberoast

# disable pre-authentication on u_asreproast
Set-ADAccountControl -DoesNotRequirePreAuth $True -Identity u_asreproast