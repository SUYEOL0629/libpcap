#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {

    struct ether_header* ethhd;
    struct pcap_pkthdr* header;
    const u_char* packet;
    struct ip* iphd;
    struct tcphdr* tcph;

    unsigned short ether_type;

    ether_type = ntohs(ethhd->ether_type);
    ethhd = (struct ether_header* )packet;
    packet += sizeof(struct ether_header);

    int res = pcap_next_ex(handle, &header, &packet);

//    if (res == 0) continue;
//    if (res == -1 || res == -2) break;

    if (ether_type == ETHERTYPE_IP){
        printf("===========================================================\n");
        printf("-----------------------Ethernet Header---------------------\n");
        printf("%u bytes captured\n", header->caplen);
        printf("Source MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n",
               ethhd->ether_shost[0], ethhd->ether_shost[1],
               ethhd->ether_shost[2], ethhd->ether_shost[3],
               ethhd->ether_shost[4], ethhd->ether_shost[5]);
        printf("Destination MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n",
               ethhd->ether_dhost[0], ethhd->ether_dhost[1],
               ethhd->ether_dhost[2], ethhd->ether_dhost[3],
               ethhd->ether_dhost[4], ethhd->ether_dhost[5]);
        printf("Ether Type : %x\n",ether_type);

        printf("--------------------------IP Header------------------------\n");
        if (ether_type == ETHERTYPE_IP){
            iphd = (struct ip* )(packet + sizeof (struct ether_header));
            printf("Version : %d\n",iphd->ip_v);
            printf("Header Len : %d\n",iphd->ip_hl);
            printf("Ident : %d\n",ntohs(iphd->ip_id));
            printf("TTL : %d\n",iphd->ip_ttl);
            printf("Sorce IP Address : %s\n", inet_ntoa(iphd->ip_src));
            printf("Destination IP Address : %s\n", inet_ntoa(iphd->ip_dst));
            printf("IP Portocol : %d\n", iphd->ip_p);

            printf("--------------------------TCP Header------------------------\n");
            if (iphd->ip_p == 17){
                // UDP protocol Decimal set == 17.
                tcph = (struct tcphdr* )(packet + sizeof (struct ether_header) + sizeof (struct ip));
                printf("Sorce Port : %d\n", ntohs(tcph->source));
                printf("Destination Port : %d\n", ntohs(tcph->dest));
            }

        }
    }

  }

  pcap_close(handle);
  return 0;
}
