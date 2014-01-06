#!/bin/bash

# Generate list of installed packages (leaves in package dependency tree).
# Give it a list with packages that should be ignored in the final list, each
# package on a separate line.
x=`pacman -Qs expac`
if [ -n "$x" ] ; then
sudo pacman -S expac
fi

# Temporary files
IGNORED=$(mktemp)
[ -n "$1" ] && cat "$1" >$IGNORED
LIST="$(mktemp)"

expac "%n %N" -Q $(expac "%n %G" | grep -v ' base') | awk '$2 == "" {print $1}' > "$LIST"

# Sort both lists, so they can be diffed.
TMPF=$(mktemp)
sort "$IGNORED" | grep -v '^$' > "$TMPF"
sort -o "$LIST" "$LIST"
IGNORED="$TMPF"
# Diff the lists.
comm -13 "$IGNORED" "$LIST"