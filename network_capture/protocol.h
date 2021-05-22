#ifndef NETWORK_CAPTURE_PROTOCOL_H
#define NETWORK_CAPTURE_PROTOCOL_H

#define TYPE_IPV4 0x0800
#define TYPE_IPV6 0x0806
#define TYPE_ARP 0x86dd

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321

#include <iostream>

typedef struct ethhdr {
  uint8_t dest[6];
  uint8_t src[6];
  uint16_t type;
} Ethhdr;

typedef struct arphdr {
  uint16_t ar_hrd;
  uint16_t ar_pro;
  uint8_t ar_hln;
  uint8_t ar_pln;
  uint16_t ar_op;
  uint8_t ar_srcmac[6];
  uint8_t ar_srcip[4];
  uint8_t ar_destmac[6];
  uint8_t ar_destip[4];
} ArpHdr;

typedef struct iphdr {
#if defined(LITTLE_ENDIAN)
  uint8_t ihl : 4;
  uint8_t version : 4;
#elif defined(BIG_ENDIAN)
  uint8_t version : 4;
  uint8_t ihl : 4;
#endif
  uint8_t tos;
  uint16_t tlen;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t proto;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
  uint32_t op_pad;
} IpHdr;

typedef struct tcphdr {
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack_seq;
#if defined(LITTLE_ENDIAN)
  uint16_t res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1,
      ack : 1, urg : 1, ece : 1, cwr : 1;
#elif defined(BIG_ENDIAN)
  uint16_t doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1,
      psh : 1, rst : 1, syn : 1, fin : 1;
#endif
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
  uint32_t opt;
} TcpHdr;

typedef struct udphdr {
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint16_t check;
} UdpHdr;

typedef struct icmphdr {
  uint8_t type;
  uint8_t code;
  uint8_t seq;
  uint8_t chksum;
} IcmpHdr;

typedef struct iphdr6 {
  uint32_t version : 4, flowtype : 8, flowid : 20;
  uint16_t plen;
  uint8_t nh;
  uint8_t hlim;
  uint16_t saddr[8];
  uint16_t daddr[8];
} IpHdr6;

typedef struct icmphdr6 {
  uint8_t type;
  uint8_t code;
  uint8_t seq;
  uint8_t chksum;
  uint8_t op_type;
  uint8_t op_len;
  uint8_t op_ethaddr[6];
} IcmpHdr6;

typedef struct pktcount {
  int32_t n_ip;
  int32_t n_ip6;
  int32_t n_arp;
  int32_t n_tcp;
  int32_t n_udp;
  int32_t n_icmp;
  int32_t n_icmp6;
  int32_t n_http;
  int32_t n_other;
  int32_t n_sum;
} PktCount;

#endif
