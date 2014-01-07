#!/bin/bash
#
# Clean me down to base
#
# Be very careful with this script
#
pacman -Rs $(comm -23 <(pacman -Qeq|sort) <((for i in $(pacman -Qqg base); do pactree -ul $i; done)|sort -u|cut -d ' ' -f 1))