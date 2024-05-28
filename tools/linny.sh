## Collects basic system information 
## Kernel Information
echo "Kernel version: $(user -r)"
echo "Searchsploit database:"
searchsploit $(user -a | awk '{print $1, $3}')
echo

## Writable
echo "Directories with write permissions:"
echo ""
find / -writable -type d 2>/dev/null
echo ""
find / -perm -222 -type d 2>/dev/null
echo ""

## Installed Applications, mounted drives, loaded drivers
echo "Installed Applications:"
echo ""
dpkg -l
echo ""
echo "Mounted drives:"
echo ""
cat /etc/fstab 
echo ""

## Grepping for easy passwords
echo "Grepping for passwords..."
echo ""
watch -n 1 "ps -aux | grep pass"
echo ""

## Sensitive Information
echo "Sensitive Information:"
echo ""
cat .bashrc
echo ""
env 
echo ""

## Sudo/SUID/Capabilities

echo "Check out GTFOBins (https://gtfobins.github.io/)"
echo "SUID files:"
echo ""
find / -perm -u=s -type f 2>/dev/null
echo ""
getcap -r / 2>/dev/null
echo ""

## Cron Jobs

echo "Detecting Cronjobs..."
echo ""
cat /etc/crontab
echo ""
crontab -l
echo ""

## Inpsecting cron logs
echo "Inspecting cron logs..."
echo ""
grep "CRON" /var/log/syslog
echo ""

## Mountable shares
echo "Checking for NFS shares..."
echo ""
cat /etc/exports
