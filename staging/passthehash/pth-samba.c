/*
 * pth-samba.c - wraps samba to accept password hashes in places of real passwords
 * based on the foofus samba patch by jmk <jmk@foofus.net> later modified
 * by Alva "Skip" Duckwall
 *
 * Copyright © 2013 Raphael Hertzog <buxy@kali.org>
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

enum {
    SMB_HASH_LM,
    SMB_HASH_NTLM
};

static bool (*real_E_md4hash)(const char *passwd, uint8_t p16[16]);
static bool (*real_E_deshash)(const char *passwd, uint8_t p16[16]);

#define ASSIGN_DLSYM_OR_DIE(name)					\
        real_##name = dlsym(RTLD_NEXT, #name);				\
        if (!real_##name || dlerror()) {				\
                fprintf(stderr, "Could not find symbol " #name "\n");   \
		_exit(1);						\
	}

void __attribute__ ((constructor))
pth_samba_init(void)
{
    if (real_E_md4hash) /* Symbols already looked up */
	return;
    ASSIGN_DLSYM_OR_DIE(E_md4hash);
    ASSIGN_DLSYM_OR_DIE(E_deshash);
}

static char *
smbhash_get_env(void)
{
    char *smbhash;
    
    smbhash = getenv("SMBHASH");
    if (smbhash) {
	int len = strlen(smbhash);
	if (len == 65 || len == 68)
	    return smbhash;
    }

    return NULL;
}

static bool
input_is_ntlm_hash(const char *passwd)
{
    int len = strlen(passwd);

    return (len == 65 || len == 68 || smbhash_get_env());
}

/*
   Support for using LM/NTLM hashes -- jmk@foofus.net 10/2006 
   Greets: Foofus, Phenfen, Omi, Fizzgig, pMonkey
*/
static void
E_set_hash(const char *passwd, int type, unsigned char hash[16])
{
    char p[1024], HexChar, *smbhash;
    int i, j, len, HexValue;

    //printf("%s\n", passwd);
    // substitute hashes lm:nt (65 char) or lm:nt::: (68 char)
    // lmlmlmlmlmlmlmlmlmlmlmlmlmlmlmlm:ntntntntntntntntntntntntntntntnt
    // based on the foofus samba patch by jmk 
    smbhash = smbhash_get_env();
    len = strlen(passwd);
    if (len == 65 || len == 68) {
	strncpy(p, passwd, sizeof(p));
    } else if (smbhash) {
	strncpy(p, smbhash, sizeof(p));
    } else {
	fprintf(stderr, "Error reading SMB HASH.\n");
	fprintf(stderr, "\tEx: export SMBHASH=\"_LM_HASH_:_NTLM_HASH_\"\n");
	exit(1);
    }
    for (i = 0; i < 16; i++) {
	HexValue = 0;
	for (j = 0; j < 2; j++) {
	    if (type == SMB_HASH_LM)
		HexChar = (char) p[2 * i + j];
	    else
		HexChar = (char) p[2 * i + j + 33];

	    if (HexChar > 0x39)
		HexChar = HexChar | 0x20;	/* convert upper case to lower */

	    if (!(((HexChar >= 0x30) && (HexChar <= 0x39)) ||	/* 0 - 9 */
		  ((HexChar >= 0x61) && (HexChar <= 0x66)))) {	/* a - f */
		fprintf(stderr, "Error invalid char (%c) for hash.\n",
			HexChar);
		exit(1);
	    }

	    HexChar -= 0x30;
	    if (HexChar > 0x09)	/* HexChar is "a" - "f" */
		HexChar -= 0x27;

	    HexValue = (HexValue << 4) | (char) HexChar;
	}
	hash[i] = (unsigned char) HexValue;
    }
}
/* jmk */

bool
E_md4hash(const char *passwd, uint8_t p16[16])
{
    fprintf(stderr, "E_md4hash wrapper called.\n");
    if (input_is_ntlm_hash(passwd)) {
	fprintf(stderr, "HASH PASS: Substituting user supplied NTLM HASH...\n");
	E_set_hash(passwd, SMB_HASH_NTLM, p16);
	return true;
    }

    return real_E_md4hash(passwd, p16);
}

bool
E_deshash(const char *passwd, uint8_t p16[16])
{
    fprintf(stderr, "E_deshash wrapper called.\n");
    if (input_is_ntlm_hash(passwd)) {
	fprintf(stderr, "HASH PASS: Substituting user supplied LM HASH...\n");
	E_set_hash(passwd, SMB_HASH_LM, p16);
	return true;
    }

    return real_E_deshash(passwd, p16);
}
