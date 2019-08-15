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

using namespace std;

struct ethernet_header{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint8_t type[2];
};

struct arp_header{
    uint8_t hd_type[2];
    uint8_t pr_type[2];
    uint8_t hd_len;
    uint8_t pr_len;
    uint8_t opcode[2];
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t tmac[6];
    uint8_t tip[4];
};

struct ip_header{
    uint8_t version_and_length;
    uint8_t type;
    uint16_t length;
    uint16_t identification;
    uint16_t flag_and_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
};

struct packet{
    struct ethernet_header eth;
    struct arp_header arp;
};

struct packet2{
    struct ethernet_header eth;
    struct ip_header ip;
};

    // host -> me!
    // sender -> victim
    // target -> generally router
struct session{
    uint8_t sip[4];
    uint8_t smac[6];
    uint8_t tip[4];
    uint8_t tmac[6];
};
