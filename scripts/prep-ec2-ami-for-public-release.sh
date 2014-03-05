#!/bin/bash
#
# Clean up an AMI to get ready for Public release
#
# list auth keys
find / -name "authorized_keys" -print -exec cat {} \;
# list users
cat /etc/passwd /etc/shadow | grep -E '^[^:]*:[^:]{3,}' | cut -d: -f1
# Start the cleaning of things
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
