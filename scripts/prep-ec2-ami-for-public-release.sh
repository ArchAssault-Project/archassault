#!/bin/bash
#
# Clean up an AMI to get ready for Public release
#
#
# list auth keys
# find / -name "authorized_keys" -print -exec cat {} \;
# list users
# cat /etc/passwd /etc/shadow | grep -E '^[^:]*:[^:]{3,}' | cut -d: -f1


find /root/.*history /home/*/.*history -exec shred -zn70  {} \;
find / -name "authorized_keys" -exec shred -zn70  {} \;
find /root/ /home/*/ -name .cvspass -exec shred -zn70  {} \;
find /root/.subversion/auth/svn.simple/ /home/*/.subversion/auth/svn.simple/ -exec shred -zn70 {} \;
