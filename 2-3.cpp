#include "pcap.h"
#define PCAP_SRC_IF_STRING "rpcap://"
#define PCAP_SRC_FILE_STRING "file://"
#define PCAP_OPENFLAG_PROMISCUOUS 1
#define PCAP_OPENFLAG_DATATX_UDP 2
#define PCAP_OPENFLAG_NOCAPTURE_RPCAP 4
#define PCAP_OPENFLAG_NOCAPTURE_LOCAL 8
#define PCAP_OPENFLAG_MAX_RESPONSIVENESS 16

void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                    const u_char *pkt_data);

int main() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int inum;
  int i = 0;
  pcap_t *adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }

  for (d = alldevs; d; d = d->next) {
    printf("%d. %s", ++i, d->name);
    if (d->description)
      printf(" (%s)\n", d->description);
    else
      printf(" (No description available)\n");
  }

  if (i == 0) {
    printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    return -1;
  }

  printf("Enter the interface number (1-%d):", i);
  scanf("%d", &inum);

  if (inum < 1 || inum > i) {
    printf("\nInterface number out of range.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
    ;

  if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000,
                            NULL, errbuf)) == NULL) {
    fprintf(stderr,
            "\nUnable to open the adapter. %s is not supported by WinPcap\n",
            d->name);
    pcap_freealldevs(alldevs);
    return -1;
  }

  printf("\nlistening on %s...\n", d->description);

  pcap_freealldevs(alldevs);

  pcap_loop(adhandle, 0, packet_handler, NULL);

  return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                    const u_char *pkt_data) {
  struct tm *ltime;
  char timestr[16];
  time_t local_tv_sec;

  local_tv_sec = header->ts.tv_sec;
  ltime = localtime(&local_tv_sec);
  strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

  printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
}