# Script to automate manual OSCP Linux privesc enumeration
# Prepare the script by running: chmod +x linny.sh
# Usage: ./linny.sh

# Check for kernel version and search against Searchsploit database
echo "\e[31mKernel version:\e[0m"
echo "\e[31mTo test if a kernel exploit works you must know OS, architecture and kernel version.\e[0m"
echo "OS: $(uname -o)"
echo "Architecture: $(uname -m)"
echo "Kernel version: $(uname -r)"
echo "Searchsploit database:"
searchsploit $(uname -a | awk '{print $1, $3}')
echo

# Find SUID/SGIDs to abuse
echo "\e[31mFiles run as group, not user:\e[0m"
find / -perm -g=s -type f 2>/dev/null
echo
echo "\e[31mFiles run as owner, not user:\e[0m"
find / -perm -u=s -type f 2>/dev/null
echo
echo "\e[31mDouble-check GTFOBin for easy wins\e[0m"
echo


# Find files with write permissions
echo "\e[31mFiles with write permissions:\e[0m"
find / -writable -type f 2>/dev/null
find / -perm -222 -type f 2>/dev/null
find / -perm -o w -type f 2>/dev/null
echo

# Find folders with write permissions
echo "\e[31mFolders with write permissions:\e[0m"
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null
echo

# Find world executable files and folders
echo "\e[31mWorld executable files and folders:\e[0m"
find / -perm -o x 2>/dev/null
find / -perm -o x -type d 2>/dev/null
echo

# Find files with sticky bit
echo "\e[31mFiles with sticky bit:\e[0m"
find / -perm -1000 -type d 2>/dev/null
echo

# Find files with capabilities
echo "\e[31mFiles with capabilities:\e[0m"
getcap -r / 2>/dev/null
echo

# Find cronjobs
echo "\e[31Cronjob Info:\e[0m"
echo "\e[31Look for anything that is owned by privileged users but writable by you.\e[0m"
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow*
cat /etc/at.deny*
cat /etc/cron.allow*
cat /etc/cron.deny*
cat /etc/crontab*
cat /etc/anacrontab*
cat /var/spool/cron/crontabs/root*
echo

# Find root processes
if [[ $( ps aux | grep "root" )!="" ]]; then echo "Services running under root: " ; ps aux | grep "root" ; fi 
echo

# Find services running as root
echo "\e[31mServices running as root:\e[0m"
ps aux | grep root
