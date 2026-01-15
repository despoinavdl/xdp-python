#include <sys/socket.h>
#include <linux/if_packet.h> // AF_PACKET
#include <linux/if_ether.h>  // ETH_P_ALL
#include <net/if.h>          // if_nametoindex
#include <sys/ioctl.h>       // ioctl
#include <unistd.h>          // close()
#include <stdio.h>
#include <iostream>
#include <cstring>
#include <unordered_map>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "packet-filtering.cc"


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
            bool is_new_flow = (flow_map.count(test_key) == 0);
            struct flow_info current_info;
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t current_time = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
            
            // Set basic packet info
            memset(&current_info, 0, sizeof(current_info)); // Initialize to zero
            current_info.last_seen = current_time;
            current_info.packets = 1;
            current_info.bytes = buflen;

            if (is_new_flow) {
                // Initialize new flow            
                current_info.first_seen = current_time;
                current_info.iat_min = UINT64_MAX;
                
                // Initialize state as Waiting
                sig_map[test_key] = Waiting;
            } else {
                // Update existing flow
                current_info.first_seen = flow_map[test_key].first_seen;
            }
            // calculate/update flow_info 
            update_map(test_key, current_info);
            update_passed_packets();
            
            // if number of packets of a flow >= PACKETS_SAMPLE is reached traverse the decision trees and classify
            if (flow_map[test_key].packets >= PACKETS_SAMPLE && sig_map[test_key] == Waiting) {
                printf("Flow reached %d packets, classifying...\n", PACKETS_SAMPLE);
                
                // traverse decision trees and classify
                int tree1_result = traverse_dt(1, 0, test_key, sig_map[test_key], &flow_map[test_key]);
                int tree2_result = traverse_dt(2, 0, test_key, sig_map[test_key], &flow_map[test_key]);
                int tree3_result = traverse_dt(3, 0, test_key, sig_map[test_key], &flow_map[test_key]);
                
                // Majority voting: sum the results (0=benign, 1=malicious)
                int malicious_votes = tree1_result + tree2_result + tree3_result;
                
                if (malicious_votes >= 2) {
                    // Majority says malicious
                    sig_map[test_key] = Malicious;
                    printf("Flow classified as MALICIOUS (votes: %d/3)\n", malicious_votes);
                    
                    // update firewall rules (iptables?)
                    char iptables_cmd[512];
                    snprintf(iptables_cmd, sizeof(iptables_cmd),
                            "iptables -A INPUT -s %s -p %s --sport %u -d %s --dport %u -j DROP",
                            src_ip_str,
                            (protocol == IPPROTO_TCP) ? "tcp" : (protocol == IPPROTO_UDP) ? "udp" : "all",
                            src_port,
                            dst_ip_str,
                            dst_port);
                    
                    printf("Executing: %s\n", iptables_cmd);
                    int ret = system(iptables_cmd);
                    if (ret != 0) {
                        printf("Warning: iptables command failed with code %d\n", ret);
                    }
                } else {
                    // Majority says benign
                    sig_map[test_key] = Benign;
                    printf("Flow classified as BENIGN (votes: %d/3)\n", malicious_votes);
                }
            }
            
            // Log current flow stats
            if (flow_map[test_key].packets % 10 == 0) {  // Every 10 packets
                printf("Flow stats - Packets: %lu, Bytes: %lu, Duration: %lu ns, PPS: %.2f, IAT Mean: %lu us\n",
                        flow_map[test_key].packets,
                        flow_map[test_key].bytes,
                        flow_map[test_key].duration,
                        flow_map[test_key].pps / 100000.0,  // Unscale for display,
                        flow_map[test_key].iat_mean);
            }
        }
    }

    close(sock_fd);
    free(buffer);

    return 0;
}

int main()
{
    load_tree_data("../decision-tree1/children_left", children_left1);
    load_tree_data("../decision-tree1/children_right", children_right1);
    load_tree_data("../decision-tree1/features", features1);
    load_tree_data("../decision-tree1/thresholds", thresholds1);
    load_tree_data("../decision-tree1/values", values1);
    load_tree_data("../decision-tree2/children_left", children_left2);
    load_tree_data("../decision-tree2/children_right", children_right2);
    load_tree_data("../decision-tree2/features", features2);
    load_tree_data("../decision-tree2/thresholds", thresholds2);
    load_tree_data("../decision-tree2/values", values2);
    load_tree_data("../decision-tree3/children_left", children_left3);
    load_tree_data("../decision-tree3/children_right", children_right3);
    load_tree_data("../decision-tree3/features", features3);
    load_tree_data("../decision-tree3/thresholds", thresholds3);
    load_tree_data("../decision-tree3/values", values3);

    return packet_handler();
}
