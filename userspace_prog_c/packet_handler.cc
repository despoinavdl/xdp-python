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
#include <signal.h>          // signal handling
#include <stdlib.h>          // exit()

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "packet-filtering.cc"

// Verbosity level: 0 = quiet, 1 = normal, 2 = verbose, 3 = very verbose
int verbosity = 3;
const char* interface_name = "veth0";


// Statistics counters
uint64_t total_flows = 0;
uint64_t malicious_flows = 0;
uint64_t benign_flows = 0;

// Global socket file descriptor for signal handler
int global_sock_fd = -1;

void print_statistics() {
    std::cout << "\n=== Final Statistics ===\n";
    std::cout << "Total flows processed: " << total_flows << "\n";
    std::cout << "Malicious flows: " << malicious_flows << "\n";
    std::cout << "Benign flows: " << benign_flows << "\n";
    std::cout << "Unclassified flows: " << (total_flows - malicious_flows - benign_flows) << "\n";
    std::cout << "========================\n";
}

// Signal handler for Ctrl+C
void signal_handler(int signum) {
    if (signum == SIGINT) {
        std::cout << "\n\n=== Caught SIGINT (Ctrl+C) - Shutting down ===\n";
        
        // Print statistics
        print_statistics();
        
        // Close the socket
        if (global_sock_fd >= 0) {
            close(global_sock_fd);
            if (verbosity >= 1) {
                std::cout << "Socket closed.\n";
            }
        }
        
        std::cout << "Exiting...\n";
        exit(0);
    }
}

int packet_handler(const char* interface_name)
{
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock_fd < 0)
    {
        perror("socket");
        return -1;
    }
    
    // Store globally for signal handler
    global_sock_fd = sock_fd;

    if (verbosity >= 1) {
        std::cout << "Raw socket created: " << sock_fd << std::endl;
    }

    // Get interface index
    // const char* interface_name = "veth0"; moved to global
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
    if (verbosity >= 1) {
        std::cout << "Interface " << interface_name << " has index: " << ifindex << std::endl;
    }

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

    if (verbosity >= 1) {
        std::cout << "Socket bound to interface: " << interface_name << std::endl;
    }

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

            if (verbosity >= 3) {
                printf("Flow: %s:%u -> %s:%u (proto: %u)\n",
                    src_ip_str, test_key.src_port,
                    dst_ip_str, test_key.dst_port,
                    test_key.protocol);
            }
        
            // Check if key exists in flow map
            bool is_new_flow = (flow_map.count(test_key) == 0);
            
            if (is_new_flow) {
                total_flows++;
            }
            
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
                if (verbosity >= 3) {
                    printf("Flow reached %d packets, classifying...\n", PACKETS_SAMPLE);
                }
                
                // traverse decision trees and classify
                int tree1_result = traverse_dt(1, 0, test_key, sig_map[test_key], &flow_map[test_key]);
                int tree2_result = traverse_dt(2, 0, test_key, sig_map[test_key], &flow_map[test_key]);
                int tree3_result = traverse_dt(3, 0, test_key, sig_map[test_key], &flow_map[test_key]);
                
                // Majority voting: sum the results (0=benign, 1=malicious)
                int malicious_votes = tree1_result + tree2_result + tree3_result;
                
                if (malicious_votes >= 2) {
                    // Majority says malicious
                    sig_map[test_key] = Malicious;
                    malicious_flows++;
                    
                    if (verbosity >= 2) {
                        printf("Flow classified as MALICIOUS (votes: %d/3): %s:%u -> %s:%u\n", 
                               malicious_votes, src_ip_str, src_port, dst_ip_str, dst_port);
                    }
                    
                    // update firewall rules (iptables?)
                    char iptables_cmd[512];
                    // If the protocol is TCP or UDP, include --sport and --dport
                    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
                    snprintf(iptables_cmd, sizeof(iptables_cmd),
                            "iptables -A INPUT -s %s -p %s --sport %u -d %s --dport %u -j DROP",
                            src_ip_str,
                                (protocol == IPPROTO_TCP) ? "tcp" : "udp",
                            src_port,
                                dst_ip_str,
                                dst_port);
                    } else {
                        // If the protocol is neither TCP nor UDP, use -p all without --sport and --dport
                        snprintf(iptables_cmd, sizeof(iptables_cmd),
                                "iptables -A INPUT -s %s -p all -d %s -j DROP",
                                src_ip_str,
                                dst_ip_str);
                    }
                    
                    if (verbosity >= 3) {
                        printf("Executing: %s\n", iptables_cmd);
                    }
                    
                    int ret = system(iptables_cmd);
                    if (ret != 0) {
                        printf("Warning: iptables command failed with code %d\n", ret);
                    }
                } else {
                    // Majority says benign
                    sig_map[test_key] = Benign;
                    benign_flows++;
                    
                    if (verbosity >= 3) {
                        printf("Flow classified as BENIGN (votes: %d/3)\n", malicious_votes);
                    }
                }
            }
            
            // Log current flow stats
            if (verbosity >= 3 && flow_map[test_key].packets % 10 == 0) {  // Every 10 packets
                printf("Flow stats - Packets: %lu, Bytes: %lu, Duration: %lu ns, PPS: %.2f, IAT Mean: %lu us\n",
                        flow_map[test_key].packets,
                        flow_map[test_key].bytes,
                        flow_map[test_key].duration,
                        flow_map[test_key].pps / 100000.0,  // Unscale for display
                        flow_map[test_key].iat_mean);
            }
        }
    }

    close(sock_fd);
    free(buffer);

    return 0;
}

int main(int argc, char *argv[])
{
    // Parse command-line arguments for verbosity
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            verbosity = 1;
        } else if (strcmp(argv[i], "-vv") == 0) {
            verbosity = 2;
        } else if (strcmp(argv[i], "-vvv") == 0) {
            verbosity = 3;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            std::cout << "Usage: " << argv[0] << " [OPTIONS]\n";
            std::cout << "Options:\n";
            std::cout << "  -v      Normal verbosity (basic info)\n";
            std::cout << "  -vv     Verbose (classification results)\n";
            std::cout << "  -vvv    Very verbose (all debug info)\n";
            std::cout << "  -h, --help  Show this help message\n";
            return 0;
        } else if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                interface_name = argv[i + 1];
                i++; // skip next argument since it's the interface name
            } else {
                std::cerr << "Error: -i requires an interface name\n";
                return 1;
            }
        }
    }

    if (!interface_name) {
        std::cerr << "Error: no interface specified. Use -i <interface>\n";
        return 1;
    }
    
    // Register signal handler for Ctrl+C
    signal(SIGINT, signal_handler);
    
    if (verbosity >= 1) {
        std::cout << "Loading decision tree data...\n";
    }
    
    if (!load_tree_data("../decision-tree1/children_left", children_left1)) return -1;
    if (!load_tree_data("../decision-tree1/children_right", children_right1)) return -1;
    if (!load_tree_data("../decision-tree1/features", features1)) return -1;
    if (!load_tree_data("../decision-tree1/thresholds", thresholds1)) return -1;
    if (!load_tree_data("../decision-tree1/values", values1)) return -1;
    if (!load_tree_data("../decision-tree2/children_left", children_left2)) return -1;
    if (!load_tree_data("../decision-tree2/children_right", children_right2)) return -1;
    if (!load_tree_data("../decision-tree2/features", features2)) return -1;
    if (!load_tree_data("../decision-tree2/thresholds", thresholds2)) return -1;
    if (!load_tree_data("../decision-tree2/values", values2)) return -1;
    if (!load_tree_data("../decision-tree3/children_left", children_left3)) return -1;
    if (!load_tree_data("../decision-tree3/children_right", children_right3)) return -1;
    if (!load_tree_data("../decision-tree3/features", features3)) return -1;
    if (!load_tree_data("../decision-tree3/thresholds", thresholds3)) return -1;
    if (!load_tree_data("../decision-tree3/values", values3)) return -1;

    if (verbosity >= 1) {
        std::cout << "All tree data loaded successfully!\n";
        std::cout << "Starting packet handler (Press Ctrl+C to stop)...\n";
    }

    return packet_handler(interface_name);
}
