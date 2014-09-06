#!/usr/bin/env bash

PACMANCONF="/etc/pacman.conf"

# Show usage output
[[ -n "$1" ]] && ([[ "$1" = "-h" ]] || [[ "$1" = "--help" ]]) && echo -e "Usage:\n    ${0##*/}: create (if !exists) and enter chroot\n    ${0##*/} [pkgname.src.tar.gz]: same as above + build source package\n    ${0##*/} -d | --delete: delete the chroot (if exists)\n    ${0##*/} -h | --help: show this help dialog\n\n    *note: chroot is in $ARCHROOT, set "'$ARCHROOT'" to override" && exit 0

# Use $ARCHROOT as the chroot path if set, otherwise use /dev/shm/archroot
[[ -z "$ARCHROOT" ]] && ARCHROOT=/dev/shm/archroot

# If the -d | --delete option is set, remove $ARCHROOT if it exists
[[ -n "$1" ]] && \
    if [ "$1" = "-d" ] || [ "$1" = "--delete" ]; then
        if [ -d "$ARCHROOT" ]; then
            # Unmount any directories still mounted
            [[ $(mount | grep "$ARCHROOT") ]] && \
                for mntpt in $(mount | grep "$ARCHROOT" | sed 's|^[^\ ]*\ on\ ||;s|\ .*$||' | sort -u); do
                    umount "$mntpt"
                done
            if [[ $(mount | grep "$ARCHROOT") ]]; then
                echo "Error: unable unmount some directories in ${ARCHROOT}"
                exit 1
            else
                echo -e "Deleting: ${ARCHROOT}"
                rm -rf "$ARCHROOT"
                exit 0
            fi
        else
            echo "Error: ${ARCHROOT} does not exist"
            exit 1
        fi
    fi

# Check for root and that the required files exist
[[ ! "$UID" = 0 ]] && echo "Error: this script must be run as root" && exit 1
[[ ! $(pacman -Qs arch-install-scripts) ]] && echo "Error: the arch-install-scripts package is needed to run this script" && exit 1
[[ ! $(pacman -Qs devtools) ]] && echo "Error: the devtools package is needed to run this script" && exit 1
[[ -n "$1" ]] && [[ ! $(grep "\.src\.tar\.gz" <<< "$1") ]] && echo "Error: ${1} does not appear to be a package source archive" && exit 1
[[ -n "$1" ]] && [[ ! -f "$1" ]] && echo "Error: package source archive ${1} does not exist" && exit 1

# Create $ARCHROOT if it doesn't exist
[[ -d "$ARCHROOT" ]] || install -d "$ARCHROOT"

# Build the chroot if it doesn't exist
if [[ ! -d "${ARCHROOT}/root" ]]; then
    # Check to make sure the files we need exist
    [[ ! -f "$PACMANCONF" ]] && echo "Error: ${PACMANCONF} is required to build the chroot" && exit 1
    [[ ! -f "/etc/pacman.d/mirrorlist" ]] && echo "Error: /etc/pacman.d/mirrorlist is required to build the chroot" && exit 1
    [[ ! -f "/etc/pacman.d/archassault-mirrorlist" ]] && echo "Error: /etc/pacman.d/archassault-mirrorlist is required to build the chroot" && exit 1

    # Go ahead and build the chroot
    mkarchroot "${ARCHROOT}/root" base-devel
    cp "$PACMANCONF" "${ARCHROOT}/root${PACMANCONF}"
    cp /etc/pacman.d/mirrorlist "${ARCHROOT}/root/etc/pacman.d/mirrorlist"
    cp /etc/pacman.d/archassault-mirrorlist "${ARCHROOT}/root/etc/pacman.d/archassault-mirrorlist"
    arch-nspawn "${ARCHROOT}/root" pacman -Syyu
fi

# If a pkg source archive is given as an argument, copy it into the chroot and attempt to build it
[[ -n "$1" ]] && \
    if [[ -f "$1" ]]; then
        PKGNAME=$(sed 's|-[^-]*-[^\.]*\.src\.tar\.gz||' <<< "$1")
        cp "$1" "${ARCHROOT}/root/${PKGNAME}.tar.gz"
        [[ -d "${ARCHROOT}/root/${PKGNAME}" ]] && rm -rf "${ARCHROOT}/root/${PKGNAME}"
        arch-nspawn "${ARCHROOT}/root" tar zxf "/${PKGNAME}.tar.gz"
        arch-nspawn "${ARCHROOT}/root" sh -c "cd /${PKGNAME} && makepkg -s --asroot"
        ls "${ARCHROOT}/root/${PKGNAME}/"*.pkg.* >/dev/null 2>&1
        [[ $? ]] && [[ $(type -P namcap) ]] && namcap "${ARCHROOT}/root/${PKGNAME}/"*.pkg.*
    fi

# Enter the chroot
[[ $(mount | grep "$ARCHROOT") ]] && TERM=rxvt chroot "${ARCHROOT}/root" /usr/bin/bash || TERM=rxvt arch-chroot "${ARCHROOT}/root" /usr/bin/bash
