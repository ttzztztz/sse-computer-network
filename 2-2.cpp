#include <stdio.h>
#include <cstdlib>
#include "pcap.h"
#define PCAP_SRC_IF_STRING "rpcap://"
#define PCAP_SRC_FILE_STRING "file://"

#ifndef WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#else
#include <winsock.h>
#endif

void ifprint(pcap_if_t *d);
char *iptos(u_long in);

int main() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  char errbuf[PCAP_ERRBUF_SIZE + 1];
  char source[PCAP_ERRBUF_SIZE + 1];

  printf(
      "Enter the device you want to list:\n"
      "rpcap://              ==> lists interfaces in the local machine\n"
      "rpcap://hostname:port ==> lists interfaces in a remote machine\n"
      "                          (rpcapd daemon must be up and running\n"
      "                           and it must accept 'null' authentication)\n"
      "file://foldername     ==> lists all pcap files in the give folder\n\n"
      "Enter your choice: ");

  fgets(source, PCAP_ERRBUF_SIZE, stdin);
  source[PCAP_ERRBUF_SIZE] = '\0';

  if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }

  for (d = alldevs; d; d = d->next) {
    ifprint(d);
  }

  pcap_freealldevs(alldevs);
  getchar();
  return 0;
}

void ifprint(pcap_if_t *d) {
  pcap_addr_t *a;

  printf("%s\n", d->name);

  if (d->description) printf("\tDescription: %s\n", d->description);

  printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

  for (a = d->addresses; a; a = a->next) {
    printf("\tAddress Family: #%d\n", a->addr->sa_family);

    switch (a->addr->sa_family) {
      case AF_INET:
        printf("\tAddress Family Name: AF_INET\n");
        if (a->addr)
          printf("\tAddress: %s\n",
                 iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        if (a->netmask)
          printf("\tNetmask: %s\n",
                 iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
        if (a->broadaddr)
          printf("\tBroadcast Address: %s\n",
                 iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
        if (a->dstaddr)
          printf("\tDestination Address: %s\n",
                 iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
        break;

      default:
        printf("\tAddress Family Name: Unknown\n");
        break;
    }
  }
  printf("\n");
}

#define IPTOSBUFFERS 12
char *iptos(u_long in) {
  static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
  static short which;
  u_char *p;

  p = (u_char *)&in;
  which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
  sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
  return output[which];
}