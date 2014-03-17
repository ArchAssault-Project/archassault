#!/usr/bin/env bash

# RUN FROM THE BASE DIRECTORY OF A C PROGRAM TO OUTPUT THE PACKAGE ASSOCIATED WITH EACH NON-BUILTIN, SYSTEM-INCLUDED HEADER FILE (<header.h>, not <header> or "header.h")

# CURRENTLY HEADERS ARE SEARCHED FOR IN /usr/include
# HEADERS THAT CANNOT BE FOUND IN THE SYSTEM ARE SIMPLY ANNOUNCED
# HEADERS ASSOCIATED WITH THE 'glibc' PACKAGE ARE EXCLUDED FROM RESULTS

grep -r -e "^#include\ <" | grep ".h>" | sed 's/^[^<]*<//g;s/>.*$//g' | while read line; do
    [[ -e "/usr/include/${line}" ]] \
        && pacman -Qo "/usr/include/${line}" \
        || echo "${line} not in /usr/include"
done | grep -v glibc
