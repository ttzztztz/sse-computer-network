#include <stdio.h>
#include <cstdlib>
#include "pcap.h"

#define PCAP_SRC_IF_STRING "rpcap://"
#define PCAP_SRC_FILE_STRING "file://"

int main() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int i = 0;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
    exit(1);
  }

  for (d = alldevs; d != NULL; d = d->next) {
    printf("%d. %s", ++i, d->name);
    if (d->description)
      printf(" (%s)\n", d->description);
    else
      printf(" (No description available)\n");
  }

  if (i == 0) {
    printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    return;
  }
  getchar();
  pcap_freealldevs(alldevs);
  return 0;
}