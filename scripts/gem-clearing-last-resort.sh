#!/bin/bash
#
# Delete all installed gems 2.0 1.9
#
# Last resort for clearing gems out that were not installed 100% properly yet
# you need root privs 
#
pacman -Rnscd ruby ruby1.9 ruby1.8 && pacman -S ruby ruby1.9 ruby1.8
for i in `gem list --no-versions`; do gem uninstall -aIx $i; done
for i in `gem-1.9 list --no-versions`; do gem-1.9 uninstall -aIx $i; done
pacman -Rnscd ruby ruby1.9 ruby1.8 && pacman -S ruby ruby1.9 ruby1.8