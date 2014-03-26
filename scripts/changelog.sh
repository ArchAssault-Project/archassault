#!/bin/bash
# Generates changelog day by day
# ArchAssault
echo "CHANGELOG"
echo ----------------------
git log --no-merges --format="%cd" --date=short | sort -u -r | while read DATE ; do
    echo
    echo [$DATE] 
    echo
    GIT_PAGER=cat git log --no-merges --pretty=tformat:"[%ae] %h %ad %s%n" --graph --since="$DATE 00:00:00" --until="$DATE 24:00:00"
 #   NEXT=$DATE
    echo
done
