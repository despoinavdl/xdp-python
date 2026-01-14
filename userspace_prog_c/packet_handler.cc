#include <sys/socket.h>
#include <linux/if_packet.h> // AF_PACKET
#include <linux/if_ether.h>  // ETH_P_ALL
#include <net/if.h>          // if_nametoindex
#include <sys/ioctl.h>       // ioctl
#include <unistd.h>          // close()
#include <stdio.h>
#include <iostream>
#include <cstring>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "flow_headers.h"

int packet_handler()
{
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock_fd < 0)
    {
        perror("socket");
        return -1;
    }

    std::cout << "Raw socket created: " << sock_fd << std::endl;

    // Get interface index
    const char* interface_name = "veth0";
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl SIOCGIFINDEX");
        close(sock_fd);
        return -1;
    }

    int ifindex = ifr.ifr_ifindex;
    std::cout << "Interface " << interface_name << " has index: " << ifindex << std::endl;

    // Bind socket to the specific interface using sockaddr_ll
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock_fd, (struct sockaddr*)&sll, sizeof(sll)) < 0)
    {
        perror("bind");
        close(sock_fd);
        return -1;
    }

    std::cout << "Socket bound to interface: " << interface_name << std::endl;

    unsigned char *buffer = (unsigned char *) malloc(65536); 
    memset(buffer, 0, 65536);
    
    while (1) {
        int buflen = recv(sock_fd, buffer, 65536, 0);
        if(buflen < 0)
        {
            printf("error in reading recv function\n");
            free(buffer);
            close(sock_fd);
            return -1;
        }

        // Parse Ethernet header
        struct ethhdr *eth = (struct ethhdr *)buffer;

        // Check if it's an IP packet
        if (ntohs(eth->h_proto) == ETH_P_IP)
        {
            // Parse IP header
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            
            uint32_t src_ip = ip->saddr;
            uint32_t dst_ip = ip->daddr;
            uint32_t protocol = ip->protocol;
            
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            
            unsigned int ip_header_len = ip->ihl * 4;
            
            if (protocol == IPPROTO_TCP)
            {
                struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip_header_len);
                src_port = ntohs(tcp->source);
                dst_port = ntohs(tcp->dest);
            }
            else if (protocol == IPPROTO_UDP)
            {
                struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip_header_len);
                src_port = ntohs(udp->source);
                dst_port = ntohs(udp->dest);
            }
            
            flow_key test_key{src_ip, dst_ip, src_port, dst_port, protocol};
            
            struct in_addr src_addr, dst_addr;
            src_addr.s_addr = test_key.src_ip;
            dst_addr.s_addr = test_key.dst_ip;

            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);

            printf("Flow: %s:%u -> %s:%u (proto: %u)\n",
                src_ip_str, test_key.src_port,
                dst_ip_str, test_key.dst_port,
                test_key.protocol);
        
        // TODO: 
        // Check if key exists in flow map
        // if not, initialize it
        // calculate/update flow_info 
        // if number of packets of a flow >= PACKETS_SAMPLE is reached traverse the decision trees and classify
        // update firewall rules (iptables?)
        }
    }

    close(sock_fd);
    free(buffer);

    return 0;
}
