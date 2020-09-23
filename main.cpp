#define LIBNET_LIL_ENDIAN 1
#define ETHER_ADDR_LEN 6
#include <pcap.h>
#include <stdio.h>
#include "libnet/libnet-headers.h"

typedef struct libnet_ethernet_hdr ethernet_hdr;
typedef struct libnet_ipv4_hdr ipv4_hdr;
typedef struct libnet_tcp_hdr tcp_hdr;


ethernet_hdr *ethernet;
ipv4_hdr *ip;
tcp_hdr *tcp;
const u_char *data;
int data_len;

int check_tcp_packet(u_int len, const u_char *packet) {
    if(len >= LIBNET_ETH_H) {
        ethernet = (ethernet_hdr *)packet;
        packet += LIBNET_ETH_H;
        len -= LIBNET_ETH_H;
        if(len >= LIBNET_IPV4_H && ethernet->ether_type == 0x08) {
            ip = (ipv4_hdr *)packet;
            packet += ip->ip_hl * 4;
            len -= ip->ip_hl * 4;
            if(len >= LIBNET_TCP_H && ip->ip_p == 0x06) {
                tcp = (tcp_hdr *)packet;
                packet += tcp->th_off * 4;
                len -= tcp->th_off * 4;
                data = packet;
                data_len = len;
            }
            else return 0;
        }
        else return 0;
    }
    else return 0;
    return 1;
}

void print_ethernet(ethernet_hdr *ethernet) {
    printf("src mac: ");
    for(int i = 0; i < 6; i++) {
        printf("%02x", ethernet->ether_shost[i]);
        if(i != 5) printf(":");
        else printf("\n");
    }
    printf("dst mac: ");
    for(int i = 0; i < 6; i++) {
        printf("%02x", ethernet->ether_dhost[i]);
        if(i != 5) printf(":");
        else printf("\n");
    }
}

void print_IP(ipv4_hdr *ip) {
    printf("src ip: %s\n", inet_ntoa(ip->ip_src));
    printf("src ip: %s\n", inet_ntoa(ip->ip_dst));
}

void print_tcp(tcp_hdr *tcp) {
    printf("src port: %d\n", ntohs(tcp->th_sport));
    printf("dst port: %d\n", ntohs(tcp->th_dport));
}

void print_data(const u_char *data) {
    if(data_len >= 16) {
        for(int i = 0; i < 16; i++) {
            printf("%02x", *(data + i));
            if(i != 15) printf("|");
            else printf("\n");
        }
    }
    else {
        printf("-\n");
    }
}

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if(check_tcp_packet(header->caplen, packet)) {
            print_ethernet(ethernet);
            print_IP(ip);
            print_tcp(tcp);
            print_data(data);
            printf("================================\n");
        }
        //printf("%u bytes captured\n", header->caplen);
    }

    pcap_close(handle);
}
