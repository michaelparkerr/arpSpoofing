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

struct eth_h{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint8_t type[2];
};

struct arp_h{
    uint8_t hd_type[2];
    uint8_t pr_type[2];
    uint8_t hd_len;
    uint8_t pr_len;
    uint8_t opcode[2];
    uint8_t snd_mac[6];
    uint8_t snd_ip[4];
    uint8_t tgt_mac[6];
    uint8_t tgt_ip[4];
};

struct ip_h{
    uint8_t ver_len;
    uint8_t type;
    uint16_t len;
    uint16_t id;
    uint16_t flg_ofs;
    uint8_t ttl;
    uint8_t prtc;
    uint16_t chksm;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
};

struct arp_pckt{
    struct eth_h eth;
    struct arp_h arp;
};

struct ip_pckt{
    struct eth_h eth;
    struct ip_h ip;
};

    // host -> me!
    // sender -> victim
    // target -> generally router
struct sess{
    uint8_t snd_ip[4];
    uint8_t snd_mac[6];
    uint8_t tgt_ip[4];
    uint8_t tgt_mac[6];
};
