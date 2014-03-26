/*
 * pcapReader.c
 *
 * Copyright (C) 2011-13 - ntop.org
 * Copyright (C) 2009-2011 by ipoque GmbH
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

#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#include <getopt.h>
#define getopt getopt____
#else
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>

#include "../config.h"
#include "linux_compat.h"
#include "ndpi_main.h"

static void setupDetection(void);

// cli options
static char *_pcap_file = NULL;
static char *_bpf_filter = NULL;
static char *_protoFilePath = NULL;
static char *_output_mode = NULL;

// pcap
static char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
static pcap_t *_pcap_handle = NULL;
static int _pcap_datalink_type = 0;
static u_int8_t enable_protocol_guess = 1, verbose = 0;
static u_int32_t guessed_flow_protocols = 0;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0;

// detection
static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static u_int32_t detection_tick_resolution = 1000;
static time_t capture_until = 0;

// results
static u_int64_t raw_packet_count = 0;
static u_int64_t ip_packet_count = 0;
static u_int64_t total_bytes = 0;
static u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
static u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
static u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1] = { 0 };


#define GTP_U_V1_PORT      2152
#define	MAX_NDPI_FLOWS	2000000
// id tracking
typedef struct ndpi_id {
  u_int8_t ip[4];
  struct ndpi_id_struct *ndpi_id;
} ndpi_id_t;

static u_int32_t size_id_struct = 0;

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

// flow tracking
typedef struct ndpi_flow {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t detection_completed, protocol;
  struct ndpi_flow_struct *ndpi_flow;
  char lower_name[32], upper_name[32];

  u_int16_t packets, bytes;
  // result only, not used for flow identification
  u_int32_t detected_protocol;
  char host_server_name[256];

  void *src_id, *dst_id;
} ndpi_flow_t;

#define NUM_ROOTS        512

static u_int32_t size_flow_struct = 0;
static struct ndpi_flow *ndpi_flows_root[NUM_ROOTS] = { NULL };
static u_int32_t ndpi_flow_count = 0;


static void help(u_int long_help) {
  printf("pcapReader -i <file|device> [-f <filter>][-s <duration>]\n"
	 "           [-p <protos>][-l <loops>[-d][-h][-t][-o <color|plain>][-v <level>]\n\n"
	 "Usage:\n"
	 "  -i <file.pcap|device>     | Specify a pcap file to read packets from or a device for live capture\n"
	 "  -f <BPF filter>           | Specify a BPF filter for filtering selected traffic\n"
	 "  -s <duration>             | Maximum capture duration in seconds (live traffic capture only)\n"
	 "  -p <file>.protos          | Specify a protocol file (eg. protos.txt)\n"
	 "  -l <num loops>            | Number of detection loops (test only)\n"
	 "  -d                        | Disable protocol guess and use only DPI\n"
	 "  -t                        | Dissect GTP tunnels\n"
	 "  -o <color|plain>          | Specify the output text format. Default: color\n"
	 "  -h                        | This help\n"
	 "  -v <1|2>                  | Verbose 'unknown protocol' packet print. 1=verbose, 2=very verbose\n");

  if(long_help) {
    printf("\n\nSupported protocols:\n");
    setupDetection();
    ndpi_dump_protocols(ndpi_struct);
  }

  exit(-1);
}

static void parseOptions(int argc, char **argv)
{
  int opt;

  while ((opt = getopt(argc, argv, "df:i:hp:l:s:to:v:")) != EOF) {
    switch (opt) {
    case 'd':
      enable_protocol_guess = 0;
      break;

    case 'i':
      _pcap_file = optarg;
      break;

    case 'f':
      _bpf_filter = optarg;
      break;

    case 'l':
      num_loops = atoi(optarg);
      break;

    case 'p':
      _protoFilePath = optarg;
      break;

    case 's':
      capture_until = atoi(optarg);
      break;

    case 't':
      decode_tunnels = 1;
      break;

    case 'o':
      _output_mode = optarg;
      break;

    case 'v':
      verbose = atoi(optarg);
      break;

    case 'h':
      help(1);
      break;

    default:
      help(0);
      break;
    }
  }

  // check parameters
  if(_pcap_file == NULL || strcmp(_pcap_file, "") == 0) {
    help(0);
  }
}

static void debug_printf(u_int32_t protocol, void *id_struct,
			 ndpi_log_level_t log_level,
			 const char *format, ...) {

 printf("[DEBUG]%s\n",format);

}

static void *malloc_wrapper(unsigned long size)
{
  return malloc(size);
}

static void free_wrapper(void *freeable)
{
  free(freeable);
}


static char* ipProto2Name(u_short proto_id) {
  static char proto[8];

  switch(proto_id) {
  case IPPROTO_TCP:
    return("TCP");
    break;
  case IPPROTO_UDP:
    return("UDP");
    break;
  case IPPROTO_ICMP:
    return("ICMP");
    break;
  case 112:
    return("VRRP");
    break;
  }

  snprintf(proto, sizeof(proto), "%u", proto_id);
  return(proto);
}

/*
 * A faster replacement for inet_ntoa().
 */
char* intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  uint byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

static void printFlow(struct ndpi_flow *flow) {
  printf("\t%s %s:%u <-> %s:%u ",
	 ipProto2Name(flow->protocol),
	 flow->lower_name, ntohs(flow->lower_port),
	 flow->upper_name, ntohs(flow->upper_port));
  
  printf("[proto: %u/%s][%u pkts/%u bytes][%s]\n",
	 flow->detected_protocol,
	 ndpi_get_proto_name(ndpi_struct, flow->detected_protocol),
	 flow->packets, flow->bytes,
	 flow->host_server_name);
}

static void node_print_unknown_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow**)node;

  if(flow->detected_protocol != 0 /* UNKNOWN */) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) /* Avoid walking the same node multiple times */
    printFlow(flow);
}

static void node_print_known_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow**)node;

  if(flow->detected_protocol == 0 /* UNKNOWN */) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) /* Avoid walking the same node multiple times */
    printFlow(flow);
}

static unsigned int node_guess_undetected_protocol(struct ndpi_flow *flow) {
  flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_struct,
							   flow->protocol,
							   ntohl(flow->lower_ip),
							   ntohs(flow->lower_port),
							   ntohl(flow->upper_ip),
							   ntohs(flow->upper_port));

  if(flow->detected_protocol != 0)
    guessed_flow_protocols++;

  return flow->detected_protocol;
}

static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow**)node;

#if 0
  printf("<%d>Walk on node %s (%p)\n",
	 depth,
	 which == preorder?"preorder":
	 which == postorder?"postorder":
	 which == endorder?"endorder":
	 which == leaf?"leaf": "unknown",
	 flow);
#endif

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(enable_protocol_guess) {
      if(flow->detected_protocol == 0 /* UNKNOWN */) {
        node_guess_undetected_protocol(flow);
	// printFlow(flow);
      }
    }

    protocol_counter[flow->detected_protocol]       += flow->packets;
    protocol_counter_bytes[flow->detected_protocol] += flow->bytes;
    protocol_flows[flow->detected_protocol]++;
  }
}

static int node_cmp(const void *a, const void *b) {
  struct ndpi_flow *fa = (struct ndpi_flow*)a;
  struct ndpi_flow *fb = (struct ndpi_flow*)b;

  if(fa->lower_ip < fb->lower_ip) return(-1); else { if(fa->lower_ip > fb->lower_ip) return(1); }
  if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
  if(fa->upper_ip < fb->upper_ip) return(-1); else { if(fa->upper_ip > fb->upper_ip) return(1); }
  if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
  if(fa->protocol < fb->protocol) return(-1); else { if(fa->protocol > fb->protocol) return(1); }

  return(0);
}


static struct ndpi_flow *get_ndpi_flow(const u_int8_t version,
				       const struct ndpi_iphdr *iph,
				       u_int16_t ip_offset,
				       u_int16_t ipsize,
				       u_int16_t l4_packet_len,
				       struct ndpi_id_struct **src,
				       struct ndpi_id_struct **dst,
				       u_int8_t *proto,
				       const struct ndpi_ip6_hdr *iph6)
{
  u_int32_t idx, l4_offset;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  struct ndpi_flow flow;
  void *ret;

  /*
    Note: to keep things simple (pcapReader is just a demo app)
    we handle IPv6 a-la-IPv4.
   */
  if(version == 4) {
    if(ipsize < 20)
      return NULL;

    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
       || (iph->frag_off & htons(0x1FFF)) != 0)
      return NULL;
  }

  if(iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  *proto = iph->protocol;
  l4_offset = iph->ihl * 4;
  if(iph->protocol == 6 && l4_packet_len >= 20) {
    // tcp
    tcph = (struct ndpi_tcphdr *) ((u_int8_t *) iph + l4_offset);
    if(iph->saddr < iph->daddr) {
      lower_port = tcph->source;
      upper_port = tcph->dest;
    } else {
      lower_port = tcph->dest;
      upper_port = tcph->source;
    }
  } else if(iph->protocol == 17 && l4_packet_len >= 8) {
    // udp
    udph = (struct ndpi_udphdr *) ((u_int8_t *) iph + l4_offset);
    if(iph->saddr < iph->daddr) {
      lower_port = udph->source;
      upper_port = udph->dest;
    } else {
      lower_port = udph->dest;
      upper_port = udph->source;
    }
  } else {
    // non tcp/udp protocols
    lower_port = 0;
    upper_port = 0;
  }

  flow.protocol = iph->protocol;
  flow.lower_ip = lower_ip;
  flow.upper_ip = upper_ip;
  flow.lower_port = lower_port;
  flow.upper_port = upper_port;


  if(0)
    printf("[NDPI] [%u][%u:%u <-> %u:%u]\n",
	   iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

  idx = (lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
  ret = ndpi_tfind(&flow, (void*)&ndpi_flows_root[idx], node_cmp);

  if(ret == NULL) {
    if(ndpi_flow_count == MAX_NDPI_FLOWS) {
      printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_NDPI_FLOWS);
      exit(-1);
    } else {
      struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));

      if(newflow == NULL) {
	printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      memset(newflow, 0, sizeof(struct ndpi_flow));
      newflow->protocol = iph->protocol;
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;

      if(version == 4) {
	inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
      } else {
	inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
      }

      if((newflow->ndpi_flow = calloc(1, size_flow_struct)) == NULL) {
	printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      if((newflow->src_id = calloc(1, size_id_struct)) == NULL) {
	printf("[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      if((newflow->dst_id = calloc(1, size_id_struct)) == NULL) {
	printf("[NDPI] %s(4): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      ndpi_tsearch(newflow, (void*)&ndpi_flows_root[idx], node_cmp); /* Add */

      ndpi_flow_count += 1;

      //printFlow(newflow);

      *src = newflow->src_id, *dst = newflow->dst_id;
      return(newflow);
    }
  } else {
    struct ndpi_flow *flow = *(struct ndpi_flow**)ret;

    if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
       && flow->lower_port == lower_port && flow->upper_port == upper_port)
      *src = flow->src_id, *dst = flow->dst_id;
    else
      *src = flow->dst_id, *dst = flow->src_id;

    return flow;
  }
}

static struct ndpi_flow *get_ndpi_flow6(const struct ndpi_ip6_hdr *iph6,
					u_int16_t ip_offset,
					struct ndpi_id_struct **src,
					struct ndpi_id_struct **dst,
					u_int8_t *proto)
{
  struct ndpi_iphdr iph;

  memset(&iph, 0, sizeof(iph));
  iph.version = 4;
  iph.saddr = iph6->ip6_src.__u6_addr.__u6_addr32[2] + iph6->ip6_src.__u6_addr.__u6_addr32[3];
  iph.daddr = iph6->ip6_dst.__u6_addr.__u6_addr32[2] + iph6->ip6_dst.__u6_addr.__u6_addr32[3];
  iph.protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  return(get_ndpi_flow(6, &iph, ip_offset,
		       sizeof(struct ndpi_ip6_hdr),
		       ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen),
		       src, dst, proto, iph6));
}

static void setupDetection(void)
{
  NDPI_PROTOCOL_BITMASK all;

  // init global detection structure
  ndpi_struct = ndpi_init_detection_module(detection_tick_resolution, malloc_wrapper, free_wrapper, debug_printf);
  if(ndpi_struct == NULL) {
    printf("ERROR: global structure initialization failed\n");
    exit(-1);
  }
  // enable all protocols
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

  // allocate memory for id and flow tracking
  size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
  size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

  // clear memory for results
  memset(protocol_counter, 0, sizeof(protocol_counter));
  memset(protocol_counter_bytes, 0, sizeof(protocol_counter_bytes));
  memset(protocol_flows, 0, sizeof(protocol_flows));

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_struct, _protoFilePath);

  raw_packet_count = ip_packet_count = total_bytes = 0;
  ndpi_flow_count = 0;
}

static void free_ndpi_flow(struct ndpi_flow *flow) {
  if(flow->ndpi_flow) { ndpi_free(flow->ndpi_flow); flow->ndpi_flow = NULL; }
  if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL;       }
  if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL;       }
}

static void ndpi_flow_freer(void *node) {
  struct ndpi_flow *flow = (struct ndpi_flow*)node;
  free_ndpi_flow(flow);
  ndpi_free(flow);
}


static void terminateDetection(void)
{
  int i;

  for(i=0; i<NUM_ROOTS; i++) {
    ndpi_tdestroy(ndpi_flows_root[i], ndpi_flow_freer);
    ndpi_flows_root[i] = NULL;
  }

  ndpi_exit_detection_module(ndpi_struct, free_wrapper);
}

static unsigned int packet_processing(const u_int64_t time,
				      const struct ndpi_iphdr *iph,
				      struct ndpi_ip6_hdr *iph6,
				      u_int16_t ip_offset,
				      u_int16_t ipsize, u_int16_t rawsize)
{
  struct ndpi_id_struct *src, *dst;
  struct ndpi_flow *flow;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int32_t protocol = 0;
  u_int8_t proto;

  if(iph)
    flow = get_ndpi_flow(4, iph, ip_offset, ipsize,
			 ntohs(iph->tot_len) - (iph->ihl * 4),
			 &src, &dst, &proto, NULL);
  else
    flow = get_ndpi_flow6(iph6, ip_offset, &src, &dst, &proto);

  if(flow != NULL) {
    ndpi_flow = flow->ndpi_flow;
    flow->packets++, flow->bytes += rawsize;
  } else
    return(0);

  ip_packet_count++;
  total_bytes += rawsize + 24 /* CRC etc */;

  if(flow->detection_completed) return(0);

  protocol = (const u_int32_t)ndpi_detection_process_packet(ndpi_struct, ndpi_flow,
							    iph ? (uint8_t *)iph : (uint8_t *)iph6,
							    ipsize, time, src, dst);

  flow->detected_protocol = protocol;

  if((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
     || ((proto == IPPROTO_UDP) && (flow->packets > 8))
     || ((proto == IPPROTO_TCP) && (flow->packets > 10))) {
    flow->detection_completed = 1;

#if 0
    if(flow->ndpi_flow->l4.tcp.host_server_name[0] != '\0')
      printf("%s\n", flow->ndpi_flow->l4.tcp.host_server_name);
#endif

    snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);
    free_ndpi_flow(flow);

    if(verbose > 1) {
      char buf1[32], buf2[32];

      if(enable_protocol_guess) {
        if(flow->detected_protocol == 0 /* UNKNOWN */) {
          protocol = node_guess_undetected_protocol(flow);
        }
      }

      printFlow(flow);
    }
  }

#if 0
  if(ndpi_flow->l4.tcp.host_server_name[0] != '\0')
    printf("%s\n", ndpi_flow->l4.tcp.host_server_name);
#endif

  return 0;
}

/* ****************************************************** */


char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if(numBits < 1048576) {
    snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
	snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      } else {
	snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}

char* formatPackets(float numPkts, char *buf) {
  if(numPkts < 1000) {
    snprintf(buf, 32, "%.2f", numPkts);
  } else if(numPkts < 1000000) {
    snprintf(buf, 32, "%.2f K", numPkts/1000);
  } else {
    numPkts /= 1000000;
    snprintf(buf, 32, "%.2f M", numPkts);
  }

  return(buf);
}

static void printResults(u_int64_t tot_usec)
{
  u_int32_t i;
  int m = 0;			/* Default output mode: color (0) */
  if (_output_mode != NULL && strcmp(_output_mode, "plain") == 0) {
    m = 1;			/* Set output mode: plain (0) */
  }

  if (m) {
    printf("\n");
  } else {
    printf("\x1b[2K\n");
  }
  printf("pcap file contains\n");
  if (m) {
    printf("\tIP packets:   %-13llu of %llu packets total\n",
	   (long long unsigned int)ip_packet_count,
	   (long long unsigned int)raw_packet_count);
    if(total_bytes > 0)
      printf("\tIP bytes:     %-13llu (avg pkt size %u bytes)\n",
	     (long long unsigned int)total_bytes,
	     (unsigned int)(total_bytes/raw_packet_count));
    printf("\tUnique flows: %-13u\n", ndpi_flow_count);
  } else {
    printf("\tIP packets:   \x1b[33m%-13llu\x1b[0m of %llu packets total\n",
	   (long long unsigned int)ip_packet_count,
	   (long long unsigned int)raw_packet_count);
    printf("\tIP bytes:     \x1b[34m%-13llu\x1b[0m (avg pkt size %u bytes)\n",
	   (long long unsigned int)total_bytes,
	   (unsigned int)(total_bytes/raw_packet_count));
    printf("\tUnique flows: \x1b[36m%-13u\x1b[0m\n", ndpi_flow_count);
  }

  if(tot_usec > 0) {
    char buf[32], buf1[32];
    float t = (float)(ip_packet_count*1000000)/(float)tot_usec;
    float b = (float)(total_bytes * 8 *1000000)/(float)tot_usec;

    if (m) {
      printf("\tnDPI throughout: %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
    } else {
      printf("\tnDPI throughout: \x1b[36m%s pps / %s/sec\x1b[0m\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
    }
  }

  for(i=0; i<NUM_ROOTS; i++)
    ndpi_twalk(ndpi_flows_root[i], node_proto_guess_walker, NULL);

  if(enable_protocol_guess) {
    if (m) {
      printf("\tGuessed flow protocols: %-13u\n", guessed_flow_protocols);
    } else {
      printf("\tGuessed flow protocols: \x1b[35m%-13u\x1b[0m\n", guessed_flow_protocols);
    }
  }

  printf("\n\nDetected protocols:\n");
  for (i = 0; i <= ndpi_get_num_supported_protocols(ndpi_struct); i++) {
    if(protocol_counter[i] > 0) {
      if (m) {
        printf("\t\%-20s packets: %-13llu bytes: %-13llu "
	       "flows: %-13u\n",
	       ndpi_get_proto_name(ndpi_struct, i), (long long unsigned int)protocol_counter[i],
	       (long long unsigned int)protocol_counter_bytes[i], protocol_flows[i]);
      } else {
        printf("\t\x1b[31m%-20s\x1b[0m packets: \x1b[33m%-13llu\x1b[0m bytes: \x1b[34m%-13llu\x1b[0m "
	       "flows: \x1b[36m%-13u\x1b[0m\n",
	       ndpi_get_proto_name(ndpi_struct, i), (long long unsigned int)protocol_counter[i],
	       (long long unsigned int)protocol_counter_bytes[i], protocol_flows[i]);
      }
    }
  }

  if(verbose && (protocol_counter[0] > 0)) {
    printf("\n");

    for(i=0; i<NUM_ROOTS; i++)
      ndpi_twalk(ndpi_flows_root[i], node_print_known_proto_walker, NULL);

    printf("\n\nUndetected flows:\n");
    for(i=0; i<NUM_ROOTS; i++)
      ndpi_twalk(ndpi_flows_root[i], node_print_unknown_proto_walker, NULL);
  }

  printf("\n\n");
}

static void closePcapFile(void)
{
  if(_pcap_handle != NULL) {
    pcap_close(_pcap_handle);
  }
}

// executed for each packet in the pcap file
void sigproc(int sig) {
  static int called = 0;

  if(called) return; else called = 1;
  shutdown_app = 1;

  closePcapFile();
  printResults(0);
  terminateDetection();
  exit(0);
}

static void openPcapFileOrDevice(void)
{
  u_int snaplen = 1514;
  int promisc = 1;
  char errbuf[PCAP_ERRBUF_SIZE];

  if((_pcap_handle = pcap_open_live(_pcap_file, snaplen, promisc, 500, errbuf)) == NULL) {
    _pcap_handle = pcap_open_offline(_pcap_file, _pcap_error_buffer);
    capture_until = 0;

    if(_pcap_handle == NULL) {
      printf("ERROR: could not open pcap file: %s\n", _pcap_error_buffer);
      exit(-1);
    } else
      printf("Reading packets from pcap file %s...\n", _pcap_file);
  } else
    printf("Capturing live traffic from device %s...\n", _pcap_file);

  _pcap_datalink_type = pcap_datalink(_pcap_handle);

  if(_bpf_filter != NULL) {
    struct bpf_program fcode;

    if(pcap_compile(_pcap_handle, &fcode, _bpf_filter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(_pcap_handle));
    } else {
      if(pcap_setfilter(_pcap_handle, &fcode) < 0) {
	printf("pcap_setfilter error: '%s'\n", pcap_geterr(_pcap_handle));
      } else
	printf("Succesfully set BPF filter to '%s'\n", _bpf_filter);
    }
  }

  if(capture_until > 0) {
    printf("Capturing traffic up to %u seconds\n", (unsigned int)capture_until);

#ifndef WIN32
    alarm(capture_until);
    signal(SIGALRM, sigproc);
#endif
    capture_until += time(NULL);
  }
}

static void pcap_packet_callback(u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
  const struct ndpi_ethhdr *ethernet;
  struct ndpi_iphdr *iph;
  struct ndpi_ip6_hdr *iph6;
  u_int64_t time;
  static u_int64_t lasttime = 0;
  u_int16_t type, ip_offset, ip_len;
  u_int16_t frag_off = 0;
  u_int8_t proto = 0;

  raw_packet_count++;

  if((capture_until != 0) && (header->ts.tv_sec >= capture_until)) {
    if(_pcap_handle != NULL)
      pcap_breakloop(_pcap_handle);

    return;
  }

  time = ((uint64_t) header->ts.tv_sec) * detection_tick_resolution +
    header->ts.tv_usec / (1000000 / detection_tick_resolution);
  if(lasttime > time) {
    // printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", lasttime - time);
    time = lasttime;
  }
  lasttime = time;

  if(_pcap_datalink_type == DLT_EN10MB) {
    ethernet = (struct ndpi_ethhdr *) packet;
    ip_offset = sizeof(struct ndpi_ethhdr);
    type = ntohs(ethernet->h_proto);
  } else if(_pcap_datalink_type == 113 /* Linux Cooked Capture */) {
    type = (packet[14] << 8) + packet[15];
    ip_offset = 16;
  } else
    return;

  if(type == 0x8100 /* VLAN */) {
    type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
    ip_offset += 4;
  }

  iph = (struct ndpi_iphdr *) &packet[ip_offset];

  // just work on Ethernet packets that contain IP
  if(type == ETH_P_IP && header->caplen >= ip_offset) {
    frag_off = ntohs(iph->frag_off);

    proto = iph->protocol;
    if(header->caplen < header->len) {
      static u_int8_t cap_warning_used = 0;
      if(cap_warning_used == 0) {
	printf("\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
	cap_warning_used = 1;
      }
    }
  }

  if(iph->version == 4) {
    ip_len = ((u_short)iph->ihl * 4);
    iph6 = NULL;

    if((frag_off & 0x3FFF) != 0) {
      static u_int8_t ipv4_frags_warning_used = 0;

    v4_frags_warning:
      if(ipv4_frags_warning_used == 0) {
	printf("\n\nWARNING: IPv4 fragments are not handled by this demo (nDPI supports them)\n");
	ipv4_frags_warning_used = 1;
      }

      return;
    }

  } else if(iph->version == 6) {
    iph6 = (struct ndpi_ip6_hdr *)&packet[ip_offset];
    proto = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    ip_len = sizeof(struct ndpi_ip6_hdr);
    iph = NULL;
  } else {
    static u_int8_t ipv4_warning_used = 0;

  v4_warning:
    if(ipv4_warning_used == 0) {
      printf("\n\nWARNING: only IPv4/IPv6 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
      ipv4_warning_used = 1;
    }

    return;
  }

  if(decode_tunnels && (proto == IPPROTO_UDP)) {
    struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
    u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

    if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
      /* Check if it's GTPv1 */
      u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
      u_int8_t flags = packet[offset];
      u_int8_t message_type = packet[offset+1];

      if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) && (message_type == 0xFF /* T-PDU */)) {
	ip_offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr)+8 /* GTPv1 header len */;

	if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
	if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
	if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

	iph = (struct ndpi_iphdr *) &packet[ip_offset];

	if(iph->version != 4) {
	  // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)raw_packet_count);
	  goto v4_warning;
	}
      }
    }
  }

  // process the packet
  packet_processing(time, iph, iph6, ip_offset, header->len - ip_offset, header->len);
}

static void runPcapLoop(void)
{


  if((!shutdown_app) && (_pcap_handle != NULL))
    pcap_loop(_pcap_handle, -1, &pcap_packet_callback, NULL);
}

void test_lib() {
  struct timeval begin, end;
  u_int64_t tot_usec;

  setupDetection();
  openPcapFileOrDevice();
  signal(SIGINT, sigproc);

  gettimeofday(&begin, NULL);
  runPcapLoop();
  gettimeofday(&end, NULL);

  tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);
  closePcapFile();
  printResults(tot_usec);
  terminateDetection();
}

int main(int argc, char **argv)
{
  int i;

  parseOptions(argc, argv);

  printf("\n-----------------------------------------------------------\n"
	 "* NOTE: This is demo app to show *some* nDPI features.\n"
	 "* In this demo we have implemented only some basic features\n"
	 "* just to show you what you can do with the library. Feel \n"
	 "* free to extend it and send us the patches for inclusion\n"
	 "------------------------------------------------------------\n\n");

  printf("Using nDPI (%s)\n", ndpi_revision());

  for(i=0; i<num_loops; i++)
    test_lib();

  return 0;
}


/* ****************************************************** */

#ifdef WIN32
#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

struct timezone {
  int tz_minuteswest; /* minutes W of Greenwich */
  int tz_dsttime;     /* type of dst correction */
};

#if 0
int gettimeofday(struct timeval *tv, void *notUsed) {
  tv->tv_sec = time(NULL);
  tv->tv_usec = 0;
  return(0);
}
#endif

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
  FILETIME        ft;
  LARGE_INTEGER   li;
  __int64         t;
  static int      tzflag;

  if(tv)
    {
      GetSystemTimeAsFileTime(&ft);
      li.LowPart  = ft.dwLowDateTime;
      li.HighPart = ft.dwHighDateTime;
      t  = li.QuadPart;       /* In 100-nanosecond intervals */
      t -= EPOCHFILETIME;     /* Offset to the Epoch time */
      t /= 10;                /* In microseconds */
      tv->tv_sec  = (long)(t / 1000000);
      tv->tv_usec = (long)(t % 1000000);
    }

  if(tz) {
    if(!tzflag) {
      _tzset();
      tzflag++;
    }

    tz->tz_minuteswest = _timezone / 60;
    tz->tz_dsttime = _daylight;
  }

  return 0;
}
#endif /* WIN32 */
