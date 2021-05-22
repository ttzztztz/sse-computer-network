#include "PacketCapture.h"

#include <zconf.h>
#include <cstdio>
#include <unordered_map>
#include <string>

using namespace std;

int tcp_num_count;
int udp_num_count;
unordered_map<string, record> record_map;
FILE *file = nullptr;

char *GetLocalIp() {
  char hostname[1024];
  int ret = gethostname(hostname, sizeof(hostname));
  if (ret == -1) {
    return nullptr;
  }
  struct hostent *hent;
  hent = gethostbyname(hostname);
  if (nullptr == hent) {
    return nullptr;
  }
  return inet_ntoa(*((struct in_addr *)hent->h_addr));
}

bool IsLocalIp(char *ip) {
  string ipStr = ip;
  string localIp;
  return true;
}

void GotPacket(u_char *args, const struct pcap_pkthdr *header,
               const u_char *packet) {
  static int count = 1;

  struct sniff_ethernet *ethernet;
  struct sniff_ip *ip;
  struct sniff_tcp *tcp;
  struct sniff_udp *udp;

  int size_ip;
  int size_tcp;
  int size_payload;
  int proto_flag = -1;

  fprintf(file, "\n No.%d:\n", count);
  count++;

  ethernet = (struct sniff_ethernet *)(packet);

  ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip) * 4;
  if (size_ip < 20) {
    fprintf(file, "   ip head error: %u bytes\n", size_ip);
    return;
  }
  if (IsLocalIp(inet_ntoa(ip->ip_src))) {
    record_map[inet_ntoa(ip->ip_dst)].send++;
  } else if (IsLocalIp(inet_ntoa(ip->ip_dst))) {
    record_map[inet_ntoa(ip->ip_src)].receive++;
  }

  switch (ip->ip_p) {
    case IPPROTO_TCP:
      fprintf(file, "protocol: TCP\n");
      proto_flag = 0;
      break;
    case IPPROTO_UDP:
      fprintf(file, "protocol: UDP\n");
      proto_flag = 1;
      break;
    case IPPROTO_IP:
      fprintf(file, "protocol: IP\n");
      proto_flag = 2;
      break;
    default:
      fprintf(file, "protocol: other\n");
      return;
  }

  if (proto_flag == 0) {
    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
      fprintf(file, "   * TCP head error: %u bytes\n", size_tcp);
      return;
    }

    fprintf(file, "From %s:%d ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
    fprintf(file, "To %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
    fprintf(file, "  Seq number: %d\n", ntohl(tcp->th_seq));

    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    fprintf(file, "size_payload: %d\n", size_payload);
    tcp_num_count++;
  } else if (proto_flag == 1) {
    // UDP包
    udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
    fprintf(file, "From %s:%d ", inet_ntoa(ip->ip_src), ntohs(udp->sport));
    fprintf(file, "To %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(udp->dport));
    fprintf(file, "      Length: %d ", ntohs(udp->udp_length));
    fprintf(file, "         Sum: %d\n", ntohs(udp->udp_sum));

    size_payload = ntohs(ip->ip_len) - (size_ip + 8);
    fprintf(file, "size_payload: %d\n", size_payload);
    udp_num_count++;
  }
}

int main(int argc, char **argv) {
  GetLocalIp();
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  char filter_exp[] = "ip";
  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;
  file = fopen("./dump.log", "w");

  if (argc == 2) {
    dev = argv[1];
  } else if (argc > 2) {
    exit(EXIT_FAILURE);
  } else {
    dev = pcap_lookupdev(errbuf);
    if (dev == nullptr) {
      fprintf(stderr, "no default device: %s\n", errbuf);
      exit(EXIT_FAILURE);
    }
  }

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "设备网络号或掩码捕获错误 %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }

  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "打开设备错误 %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s 设备不是DLT_EN10MB\n", dev);
    exit(EXIT_FAILURE);
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "filter exp error %s: %s\n", filter_exp,
            pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "can not apply rule %s: %s\n", filter_exp,
            pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  pcap_loop(handle, PACKETS_NUM, GotPacket, nullptr);
  pcap_freecode(&fp);
  pcap_close(handle);

  fprintf(file, "\nfinish.\n");
  fprintf(file, "udp total: %d\n", udp_num_count);
  fprintf(file, "tcp total: %d\n", tcp_num_count);

  for (auto &pair : record_map) {
    fprintf(file, "IP %s      send %d      receive %d\n", pair.first.c_str(),
            pair.second.send, pair.second.receive);
  }

  return 0;
}