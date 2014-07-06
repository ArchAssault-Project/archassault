#!/bin/bash
#
# Clean up an AMI to get ready for Public release
#
# list auth keys
find / -name "authorized_keys" -print -exec cat {} \;
# list users
cat /etc/passwd /etc/shadow | grep -E '^[^:]*:[^:]{3,}' | cut -d: -f1
# Start the cleaning of things
echo "Starting the cleaning of things. "
# clean pacman package cache
rm -f /var/cache/pacman/pkg/*
# Clean up all history
history -c 
find /root/.*history /home/*/.*history -exec shred -zn70 -u {} \;
# Clean up all auth key files
find / -name "authorized_keys" -exec shred -zn70 -u {} \;
# Clean up any cvspass files
find /root/ /home/*/ -name .cvspass -exec shred -zn70 -u {} \;
# Clean up any subversion auth stuff
find /root/.subversion/auth/svn.simple/ /home/*/.subversion/auth/svn.simple/ -exec shred -zn70 -u {} \;
# Force regeneration of new unique ssh host key pairs.
find /etc/ssh -type f -name "ssh_host_*" -exec shred -zn70 -u {} \;
# list auth keys after clean up
find / -name "authorized_keys" -print -exec cat {} \;
# Clean up lastlog stuff
>/var/log/wtmp
>/var/log/btmp
# clean up some other logs
rm -rf /var/log/air/ /var/log/auth.log /var/log/cloud-init.log /var/log/couchdb/ /var/log/crond.log /var/log/daemon.log /var/log/dashcam.log /var/log/errors.log /var/log/everything.log /var/log/inetsim/ /var/log/kernel.log /var/log/lastlog /var/log/messages.log /var/log/old/ /var/log/openvas/ /var/log/pacman.log /var/log/radius/ /var/log/samba/ /var/log/snort/ /var/log/syslog.log /var/log/tiger/ /var/log/user.log
# finished
echo "We should be clean now verify"
# list auth keys
find / -name "authorized_keys" -print -exec cat {} \;
# list users
cat /etc/passwd /etc/shadow | grep -E '^[^:]*:[^:]{3,}' | cut -d: -f1
