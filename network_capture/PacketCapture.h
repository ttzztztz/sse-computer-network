#ifndef NETWORK_CAPTURE_PACKETCAPTURE_H
#define NETWORK_CAPTURE_PACKETCAPTURE_H

#include <pcap.h>

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define PACKETS_NUM 100

struct sniff_udp {
  uint16_t sport;
  uint16_t dport;
  uint16_t udp_length;
  uint16_t udp_sum;
};

struct sniff_ethernet {
  uint8_t ether_dhost[ETHER_ADDR_LEN];
  uint8_t ether_shost[ETHER_ADDR_LEN];
  uint16_t ether_type;
};

struct sniff_ip {
  uint8_t ip_vhl;
  uint8_t ip_tos;
  uint16_t ip_len;
  uint16_t ip_id;
  uint16_t ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
  uint8_t ip_ttl;
  uint8_t ip_p;
  uint16_t ip_sum;
  struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)

typedef unsigned long tcp_seq;

struct sniff_tcp {
  uint16_t th_sport;
  uint16_t th_dport;
  tcp_seq th_seq;
  tcp_seq th_ack;

  uint8_t th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
  uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  uint16_t th_win;
  uint16_t th_sum;
  uint16_t th_urp;
};

struct record {
  int32_t receive;
  int32_t send;
};

#endif
