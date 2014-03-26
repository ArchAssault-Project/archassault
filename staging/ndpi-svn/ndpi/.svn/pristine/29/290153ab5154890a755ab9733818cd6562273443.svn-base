/*
 * ndpi_main.h
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#ifndef __NDPI_MAIN_INCLUDE_FILE__
#define __NDPI_MAIN_INCLUDE_FILE__

#ifndef __KERNEL__
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#endif

#ifndef WIN32
#ifndef __KERNEL__
#include <sys/time.h>
#endif

#if !defined __APPLE__ && !defined __FreeBSD__ && !defined __NetBSD__ && !defined __OpenBSD__

#ifndef __KERNEL__
#include <endian.h>
#include <byteswap.h>
#else
#include <asm/byteorder.h>
#include <linux/ctype.h>
#endif

#endif

/* default includes */

#ifndef __KERNEL__
#include <sys/param.h>
#include <limits.h>
#endif

#endif

#ifdef WIN32
#include <Winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#include <getopt.h> /* getopt from: http://www.pwilson.net/sample.html. */
#include <process.h> /* for getpid() and the exec..() family */

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#define snprintf	_snprintf

extern char* strsep(char **stringp, const char *delim);

#define __attribute__(x)
#include <stdint.h>
#ifndef __GNUC__
typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   uint;
typedef unsigned long  u_long;
#endif
typedef u_char  u_int8_t;
typedef u_short u_int16_t;
typedef uint   u_int32_t;
typedef unsigned __int64 u_int64_t;
#endif /* Win32 */


#include "linux_compat.h"

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <netinet/in.h>
#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <netinet/in_systm.h>
#if defined(__OpenBSD__)
#include <pthread.h>
#endif
#endif
#endif

#ifndef WIN32
#ifndef __KERNEL__

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#else
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#endif
#endif

#include "ndpi_define.h"
#include "ndpi_macros.h"
#include "ndpi_protocols_osdpi.h"

typedef enum {
  ndpi_preorder,
  ndpi_postorder,
  ndpi_endorder,
  ndpi_leaf
} ndpi_VISIT;

void *ndpi_tdelete(const void * __restrict, void ** __restrict,
		   int (*)(const void *, const void *));
void *ndpi_tfind(const void *, void *, int (*)(const void *, const void *));
void *ndpi_tsearch(const void *, void**, int (*)(const void *, const void *));
void ndpi_twalk(const void *, void (*)(const void *, ndpi_VISIT, int, void*), void *user_data);
void ndpi_tdestroy(void *vrootp, void (*freefct)(void *));


typedef struct node_t {
  char	  *key;
  struct node_t *left, *right;
} ndpi_node;

/* Least recently used cache */

struct ndpi_LruCacheNumEntry {
  u_int64_t key;
  u_int64_t value;
};

struct ndpi_LruCacheStrEntry {
  char *key, *value;
  time_t expire_time;
};

struct ndpi_LruCacheEntry {
  u_int8_t numeric_node;

  union {
    struct ndpi_LruCacheNumEntry num; /* numeric_node == 1 */
    struct ndpi_LruCacheStrEntry str; /* numeric_node == 0 */
  } u;

  struct ndpi_LruCacheEntry *next; /* Hash collision list */
};

struct ndpi_LruCache {
  u_int32_t max_cache_node_len, hash_size, mem_size;
  u_int32_t num_cache_add, num_cache_find, num_cache_misses;
  u_int32_t last_num_cache_add, last_num_cache_find, last_num_cache_misses;
  u_int32_t *current_hash_size; /* Allocated dynamically */
  struct ndpi_LruCacheEntry **hash;   /* Allocated dynamically */
};


u_int32_t ndpi_find_lru_cache_num(struct ndpi_LruCache *cache, u_int64_t key);
int ndpi_add_to_lru_cache_num(struct ndpi_LruCache *cache, u_int64_t key, u_int64_t value);

u_int16_t ntohs_ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);

u_int32_t ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);
u_int64_t ndpi_bytestream_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);
u_int32_t ndpi_bytestream_dec_or_hex_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);
u_int64_t ndpi_bytestream_dec_or_hex_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);
u_int32_t ndpi_bytestream_to_ipv4(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);

#include "ndpi_api.h"
#include "ndpi_protocol_history.h"
#include "ndpi_structs.h"


/* function to parse a packet which has line based information into a line based structure
 * this function will also set some well known line pointers like:
 *  - host, user agent, empty line,....
 */
extern void ndpi_parse_packet_line_info(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
extern void ndpi_parse_packet_line_info_unix(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
extern u_int16_t ndpi_check_for_email_address(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, u_int16_t counter);
extern void ndpi_int_change_packet_protocol(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow,
					    u_int16_t detected_protocol, ndpi_protocol_type_t protocol_type);
extern void ndpi_int_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow,
				     u_int16_t detected_protocol,
				     ndpi_protocol_type_t protocol_type);
extern void ndpi_set_proto_defaults(struct ndpi_detection_module_struct *ndpi_mod,
				    u_int16_t protoId, char *protoName,
				    ndpi_port_range *tcpDefPorts, ndpi_port_range *udpDefPorts);
extern void ndpi_int_reset_packet_protocol(struct ndpi_packet_struct *packet);
extern void ndpi_int_reset_protocol(struct ndpi_flow_struct *flow);
extern void ndpi_ip_clear(ndpi_ip_addr_t * ip);
extern int ndpi_ip_is_set(const ndpi_ip_addr_t * ip);
extern int ndpi_packet_src_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip);
extern int ndpi_packet_dst_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip);
extern void ndpi_packet_src_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip);
extern void ndpi_packet_dst_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip);
extern char *ndpi_get_ip_string(struct ndpi_detection_module_struct *ndpi_struct, const ndpi_ip_addr_t * ip);
extern char *ndpi_get_packet_src_ip_string(struct ndpi_detection_module_struct *ndpi_struct,
					   const struct ndpi_packet_struct *packet);
extern char* ndpi_get_proto_by_id(struct ndpi_detection_module_struct *ndpi_mod, u_int id);

#endif							/* __NDPI_MAIN_INCLUDE_FILE__ */
