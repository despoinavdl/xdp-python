#include <sys/socket.h>
#include <linux/if_packet.h> // AF_PACKET
#include <linux/if_ether.h>  // ETH_P_ALL
#include <unistd.h>        // close()
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
        perror("socket");   // prints system error
        return -1;
    }

    // socket successfully created
    std::cout << "Raw socket created: " << sock_fd << std::endl;

    // Bind socket to specific interface
    const char* interface_name = "lo";
    if (setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) < 0) {
        perror("setsockopt SO_BINDTODEVICE");
        close(sock_fd);
        return -1;
    }

    unsigned char *buffer = (unsigned char *) malloc(65536); 
    memset(buffer, 0, 65536);
    while (1) {
        int buflen = recv(sock_fd, buffer, 65536, 0);
        if(buflen<0)
        {
            printf("error in reading recv function\n");
            return -1;
        }

        // Parse Ethernet header
        struct ethhdr *eth = (struct ethhdr *)buffer;

        // Check if it's an IP packet
        if (ntohs(eth->h_proto) == ETH_P_IP)
        {
            // Parse IP header
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            
            // Extract values in network byte order, convert to host byte order
            // use nthol to print if needed
            uint32_t src_ip = ip->saddr;
            uint32_t dst_ip = ip->daddr;
            uint32_t protocol = ip->protocol;  // Already a single byte, no conversion needed
            
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            
            // Calculate IP header length
            unsigned int ip_header_len = ip->ihl * 4;
            
            // Extract ports based on protocol
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
            // For ICMP and other protocols, ports remain 0
            
            // Initialize your flow_key
            flow_key test_key{src_ip, dst_ip, src_port, dst_port, protocol};
            
            // debug print
            struct in_addr src_addr, dst_addr;
            src_addr.s_addr = test_key.src_ip;  // If stored in network byte order
            dst_addr.s_addr = test_key.dst_ip;

            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);

            printf("Flow: %s:%u -> %s:%u (proto: %u)\n",
                src_ip_str, test_key.src_port,
                dst_ip_str, test_key.dst_port,
                test_key.protocol);
        
        // Check if key exists in flow map
        // if not, initialize it
        // calculate/update flow_info 
        // if PACKETS_SAMPLE is reached traverse the decision trees and classify
        // update firewall rules (iptables?)
        }

    }
    

    // close the socket when done
    close(sock_fd);
    free(buffer);

    return 0;
}
