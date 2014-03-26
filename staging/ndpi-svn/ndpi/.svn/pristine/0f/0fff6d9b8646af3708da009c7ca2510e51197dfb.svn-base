/*
 * ndpi_macros.h
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


#ifndef __NDPI_MACROS_H__
#define __NDPI_MACROS_H__

#define NDPI_NUM_BITS              256

typedef u_int32_t ndpi_ndpi_mask;
#define NDPI_BITS /* 32 */ (sizeof(ndpi_ndpi_mask) * 8 /* number of bits in a byte */)        /* bits per mask */
#define howmanybits(x, y)   (((x)+((y)-1))/(y))


#define NDPI_SET(p, n)    ((p)->fds_bits[(n)/NDPI_BITS] |= (1 << (((u_int32_t)n) % NDPI_BITS)))
#define NDPI_CLR(p, n)    ((p)->fds_bits[(n)/NDPI_BITS] &= ~(1 << (((u_int32_t)n) % NDPI_BITS)))
#define NDPI_ISSET(p, n)  ((p)->fds_bits[(n)/NDPI_BITS] & (1 << (((u_int32_t)n) % NDPI_BITS)))
#define NDPI_ZERO(p)      memset((char *)(p), 0, sizeof(*(p)))
#define NDPI_ONE(p)       memset((char *)(p), 0xFF, sizeof(*(p)))

#define NDPI_NUM_FDS_BITS     howmanybits(NDPI_NUM_BITS, NDPI_BITS)

#ifdef __cplusplus
extern "C" {
#endif
typedef struct ndpi_protocol_bitmask_struct {
  ndpi_ndpi_mask  fds_bits[NDPI_NUM_FDS_BITS];
} ndpi_protocol_bitmask_struct_t;
  
#define NDPI_PROTOCOL_BITMASK ndpi_protocol_bitmask_struct_t
  
int NDPI_BITMASK_COMPARE(NDPI_PROTOCOL_BITMASK a, NDPI_PROTOCOL_BITMASK b);
int NDPI_BITMASK_IS_EMPTY(NDPI_PROTOCOL_BITMASK a);
void NDPI_DUMP_BITMASK(NDPI_PROTOCOL_BITMASK a);

#define NDPI_BITMASK_ADD(a,b)     NDPI_SET(&a,b)
#define NDPI_BITMASK_DEL(a,b)     NDPI_CLR(&a,b)
#define NDPI_BITMASK_RESET(a)     NDPI_ZERO(&a)
#define NDPI_BITMASK_SET_ALL(a)   NDPI_ONE(&a)
#define NDPI_BITMASK_SET(a, b)    { memcpy(&a, &b, sizeof(NDPI_PROTOCOL_BITMASK)); }

/* this is a very very tricky macro *g*,
  * the compiler will remove all shifts here if the protocol is static...
 */
#define NDPI_ADD_PROTOCOL_TO_BITMASK(bmask,value)     NDPI_SET(&bmask,value)
#define NDPI_DEL_PROTOCOL_FROM_BITMASK(bmask,value)   NDPI_CLR(&bmask,value)
#define NDPI_COMPARE_PROTOCOL_TO_BITMASK(bmask,value) NDPI_ISSET(&bmask,value)

#define NDPI_SAVE_AS_BITMASK(bmask,value)  { NDPI_ZERO(&bmask) ; NDPI_ADD_PROTOCOL_TO_BITMASK(bmask, value); }


#define ndpi_min(a,b)   ((a < b) ? a : b)
#define ndpi_max(a,b)   ((a > b) ? a : b)

#define NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct,flow,packet)		\
                        if (packet->packet_lines_parsed_complete != 1) {        \
			  ndpi_parse_packet_line_info(ndpi_struct,flow);	\
                        }                                                       \

#ifdef __cplusplus
}
#endif
#endif
