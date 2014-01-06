#!/bin/bash
# Move desktop files from menu repo to their proper folders
#
# This is bulk only
#
# Useage: mvdesktopfiles.sh DirDesktopFileAreIn DirWherePackagesAreStored
#
#

find $1/ -name "*.desktop" -print0 | while IFS= read -d '' -r file
do
  f="${file##*/}"
  cp $1/$f  $2/${f/.*/}/
done





