#!/bin/bash
#
# Delete all installed gems 2.0 1.9
#
# Last resort for clearing gems out that were not installed 100% properly yet
#
for i in `gem list --no-versions`; do gem uninstall -aIx $i; done
or i in `gem-1.9 list --no-versions`; do gem-1.9 uninstall -aIx $i; done