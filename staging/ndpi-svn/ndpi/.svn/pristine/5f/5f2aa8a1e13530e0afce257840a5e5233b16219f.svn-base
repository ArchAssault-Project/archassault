/*
 * skype.c
 *
 * Copyright (C) 2011-13 - ntop.org
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


#include "ndpi_utils.h"

#ifdef NDPI_PROTOCOL_SKYPE

static u_int is_private_addr(u_int32_t addr) {
  addr = ntohl(addr);

  if(((addr & 0xFF000000) == 0x0A000000) /* 10.0.0.0/8  */
     || ((addr & 0xFFF00000) == 0xAC100000) /* 172.16/12   */
	|| ((addr & 0xFFFF0000) == 0xC0A80000) /* 192.168/16  */
     || ((addr & 0xFF000000) == 0x7F000000) /* 127.0.0.0/8 */
     )
    return(1);
  else
    return(0);
}

static u_int64_t get_skype_key(u_int32_t src_host, u_int32_t dst_host) {
  u_int64_t key;
  
  if(src_host < dst_host) {
    key = src_host;
    key = (key << 32)+dst_host;
  } else {
    key = dst_host;
    key = (key << 32)+src_host;
  }

  return(key);
}

#ifdef USE_SKYPE_HEURISTICS
u_int8_t is_skype_connection(struct ndpi_detection_module_struct *ndpi_struct,
			     u_int32_t src_host, u_int32_t dst_host) {
  u_int64_t key = get_skype_key(src_host, dst_host);
  int rc;

#ifndef __KERNEL__
  pthread_mutex_lock(&ndpi_struct->skypeCacheLock);
#else
  spin_lock_bh(&ndpi_struct->skypeCacheLock);
#endif
  rc = (u_int8_t)ndpi_find_lru_cache_num(&ndpi_struct->skypeCache, key);
#ifndef __KERNEL__
  pthread_mutex_unlock(&ndpi_struct->skypeCacheLock);
#else
  spin_unlock_bh(&ndpi_struct->skypeCacheLock);
#endif
  
  return(rc == 1 ? 1 : 0);
}

void add_skype_connection(struct ndpi_detection_module_struct *ndpi_struct,
			  u_int32_t src_host, u_int32_t dst_host) {
  u_int64_t key;
  
  if(is_private_addr(ntohl(src_host)) && is_private_addr(ntohl(dst_host)))
    return;

  key = get_skype_key(src_host, dst_host);

#ifndef __KERNEL__
  pthread_mutex_lock(&ndpi_struct->skypeCacheLock);
#else
  spin_lock_bh(&ndpi_struct->skypeCacheLock);
#endif

  ndpi_add_to_lru_cache_num(&ndpi_struct->skypeCache, key, 1);

#ifndef __KERNEL__
  pthread_mutex_unlock(&ndpi_struct->skypeCacheLock);
#else
  spin_unlock_bh(&ndpi_struct->skypeCacheLock);
#endif
}
#endif /* USE_SKYPE_HEURISTICS */

static void ndpi_check_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  // const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;

#if 0
  printf("[len=%u][%02X %02X %02X %02X]\n", payload_len,
	 packet->payload[0] & 0xFF,
	 packet->payload[1] & 0xFF,
	 packet->payload[2] & 0xFF,
	 packet->payload[3] & 0xFF);
#endif

  /*
    Skype AS8220
    212.161.8.0/24
  */
  if(((ntohl(packet->iph->saddr) & 0xFFFFFF00 /* 255.255.255.0 */) == 0xD4A10800 /* 212.161.8.0 */)
     || ((ntohl(packet->iph->daddr) & 0xFFFFFF00 /* 255.255.255.0 */) == 0xD4A10800 /* 212.161.8.0 */)
     /* || is_skype_connection(ndpi_struct, packet->iph->saddr, packet->iph->daddr) */
     ) {
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE, NDPI_REAL_PROTOCOL);
    return;
  }

  if(packet->udp != NULL) {
    flow->l4.udp.skype_packet_id++;

    if(flow->l4.udp.skype_packet_id < 5) {
      /* skype-to-skype */
      if(((payload_len == 3) && ((packet->payload[2] & 0x0F)== 0x0d))
	 || ((payload_len >= 16)
	     && (packet->payload[0] != 0x30) /* Avoid invalid SNMP detection */
	     && (packet->payload[2] == 0x02))) {
	NDPI_LOG(NDPI_PROTOCOL_SKYPE, ndpi_struct, NDPI_LOG_DEBUG, "Found skype.\n");
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE, NDPI_REAL_PROTOCOL);
#ifdef USE_SKYPE_HEURISTICS
	add_skype_connection(ndpi_struct, packet->iph->saddr, packet->iph->daddr);
#endif
      }

      return;
    }

    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SKYPE);
    return;
  } else if(packet->tcp != NULL) {
    flow->l4.tcp.skype_packet_id++;

    if(flow->l4.tcp.skype_packet_id < 3) {
      ; /* Too early */
    } else if((flow->l4.tcp.skype_packet_id == 3)
	      /* We have seen the 3-way handshake */
	      && flow->l4.tcp.seen_syn
	      && flow->l4.tcp.seen_syn_ack
	      && flow->l4.tcp.seen_ack) {
      if((payload_len == 8) || (payload_len == 3)) {
	//printf("[SKYPE] %u/%u\n", ntohs(packet->tcp->source), ntohs(packet->tcp->dest));

	NDPI_LOG(NDPI_PROTOCOL_SKYPE, ndpi_struct, NDPI_LOG_DEBUG, "Found skype.\n");
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE, NDPI_REAL_PROTOCOL);
#ifdef USE_SKYPE_HEURISTICS
	add_skype_connection(ndpi_struct, packet->iph->saddr, packet->iph->daddr);
#endif
      }

      /* printf("[SKYPE] [id: %u][len: %d]\n", flow->l4.tcp.skype_packet_id, payload_len);  */
    } else
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SKYPE);

    return;
  }
}

void ndpi_search_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_SKYPE, ndpi_struct, NDPI_LOG_DEBUG, "skype detection...\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_SKYPE)
    ndpi_check_skype(ndpi_struct, flow);
}

#endif
