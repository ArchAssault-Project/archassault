#!/usr/bin/env bash

# Show usage output
[[ -n "$1" ]] && ([[ "$1" = "-h" ]] || [[ "$1" = "--help" ]]) && echo -e "Usage:\n    ${0##*/}: create (if !exists) and enter chroot\n    ${0##*/} [pkgname.src.tar.gz]: create (if !exists) and enter chroot after building package\n\n    *note: chroot is in $ARCHROOT, set "'$ARCHROOT'" to override" && exit 0

# Check for root and that the required files exist
[[ ! "$UID" = 0 ]] && echo "Error: this script must be run as root" && exit 1
[[ ! $(pacman -Qs arch-install-scripts) ]] && echo "Error: the arch-install-scripts package is needed to run this script" && exit 1
[[ ! $(pacman -Qs devtools) ]] && echo "Error: the devtools package is needed to run this script" && exit 1
[[ -n "$1" ]] && [[ ! $(grep "\.src\.tar\.gz" <<< "$1") ]] && echo "Error: ${1} does not appear to be a package source archive" && exit 1
[[ -n "$1" ]] && [[ ! -f "$1" ]] && echo "Error: package source archive ${1} does not exist" && exit 1

# Use $ARCHROOT as the chroot path if set, otherwise use /dev/shm/archroot
[[ -z "$ARCHROOT" ]] && ARCHROOT=/dev/shm/archroot
[[ -d "$ARCHROOT" ]] || install -d "$ARCHROOT"

# Build the chroot if it doesn't exist
if [[ ! -d "${ARCHROOT}/root" ]]; then
    # Check to make sure the files we need exist
    [[ ! -f "/etc/pacman.conf" ]] && echo "Error: /etc/pacman.conf is required to build the chroot" && exit 1
    [[ ! -f "/etc/pacman.d/mirrorlist" ]] && echo "Error: /etc/pacman.d/mirrorlist is required to build the chroot" && exit 1
    [[ ! -f "/etc/pacman.d/archassault-mirrorlist" ]] && echo "Error: /etc/pacman.d/archassault-mirrorlist is required to build the chroot" && exit 1

    # Go ahead and build the chroot
    mkarchroot "${ARCHROOT}/root" base base-devel
    cp /etc/pacman.conf "${ARCHROOT}/root/etc/pacman.conf"
    cp /etc/pacman.d/mirrorlist "${ARCHROOT}/root/etc/pacman.d/mirrorlist"
    cp /etc/pacman.d/archassault-mirrorlist "${ARCHROOT}/root/etc/pacman.d/archassault-mirrorlist"
    arch-nspawn "${ARCHROOT}/root" pacman -Syyu
fi

# If a pkg source archive is given as an argument, copy it into the chroot and attempt to build it
if [[ -f "$1" ]]; then
    PKGNAME=$(sed 's|-[^-]*-[^\.]*\.src\.tar\.gz||' <<< "$1")
    cp "$1" "${ARCHROOT}/root/${PKGNAME}.tar.gz"
    [[ -d "${ARCHROOT}/root/${PKGNAME}" ]] && rm -rf "${ARCHROOT}/root/${PKGNAME}"
    arch-nspawn "${ARCHROOT}/root" tar zxf "/${PKGNAME}.tar.gz"
    arch-nspawn "${ARCHROOT}/root" sh -c "cd /${PKGNAME} && makepkg -s --asroot"
    [[ $(type -P namcap) ]] && namcap "${ARCHROOT}/root/${PKGNAME}/${PKGNAME}"*.pkg.*
fi

# Enter the chroot
TERM=rxvt arch-chroot "${ARCHROOT}/root" /usr/bin/bash
