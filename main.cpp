#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>
#include <headers.h>

using namespace std;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void get_mymac(char* mymac, char* iface){
    int fd;

    struct ifreq ifr;
    char *mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char *)ifr.ifr_name , (const char *)iface , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);

    mac = (char *)ifr.ifr_hwaddr.sa_data;
    for(int i=0; i<6; i++) mymac[i] = mac[i];
}

void print_mac(uint8_t* mac){
    printf("MAC Address : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int main(int argc, char* argv[]) {

    if (argc < 4 ){
        printf("==================================================\n");
        printf("<<<<<<<<<<<<<<<<<<Out of arguments.>>>>>>>>>>>>>>>\n");
        printf("Check out your arguments again.\n");
        printf("./[program name] [dev] [sender_ip] [target_ip]\n");
        return -1;
    }

    if( (argc-2)%2 != 0){
        printf("==================================================\n");
        printf("Check that session arguments exists. ex) sender_ip or target_ip \n");
        printf("./[program name] [dev] [sender_ip] [target_ip]\n");
        return -1;
    }

    uint8_t my_mac[6]; // host mac address
        get_mymac((char*)my_mac, argv[1]); // get host mac address
        printf("[+] my ");
        print_mac(my_mac);

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
  }

  pcap_close(handle);
  return 0;
}
