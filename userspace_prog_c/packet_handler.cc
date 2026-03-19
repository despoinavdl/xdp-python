#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <iostream>
#include <vector>
#include <optional>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <nftables/libnftables.h>

#include "flow_types.h"
#include "decision_tree.h"
#include "flow_tracker.h"

// --- File-scoped state ---

static int verbosity = 3;
static const char* interface_name = "veth0";

static uint64_t total_flows = 0;
static uint64_t malicious_flows = 0;
static uint64_t benign_flows = 0;

static int global_sock_fd = -1;
static struct nft_ctx* nft = nullptr;
static bool persist_nft_rules = false;
static bool force_malicious = false;

// --- Packet parsing ---

struct PacketInfo {
    flow_key key;
    uint16_t size;
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
};

static std::optional<PacketInfo> parse_packet(const unsigned char* buffer, int buflen) {
    auto* eth = reinterpret_cast<const ethhdr*>(buffer);

    if (ntohs(eth->h_proto) != ETH_P_IP)
        return std::nullopt;

    auto* ip = reinterpret_cast<const iphdr*>(buffer + sizeof(ethhdr));

    uint32_t src_ip = ip->saddr;
    uint32_t dst_ip = ip->daddr;
    uint32_t protocol = ip->protocol;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    unsigned int ip_header_len = ip->ihl * 4;

    if (protocol == IPPROTO_TCP) {
        auto* tcp = reinterpret_cast<const tcphdr*>(buffer + sizeof(ethhdr) + ip_header_len);
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
    } else if (protocol == IPPROTO_UDP) {
        auto* udp = reinterpret_cast<const udphdr*>(buffer + sizeof(ethhdr) + ip_header_len);
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    }

    PacketInfo pkt{};
    pkt.key = {src_ip, dst_ip, src_port, dst_port, protocol};
    pkt.size = static_cast<uint16_t>(buflen);

    in_addr src_addr{}, dst_addr{};
    src_addr.s_addr = src_ip;
    dst_addr.s_addr = dst_ip;
    inet_ntop(AF_INET, &src_addr, pkt.src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, pkt.dst_ip_str, INET_ADDRSTRLEN);

    return pkt;
}

// --- nftables firewall management ---

static bool init_nft_table() {
    nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) {
        std::cerr << "Error: failed to create nftables context\n";
        return false;
    }

    // Suppress nft output to stdout
    nft_ctx_output_set_flags(nft, NFT_CTX_OUTPUT_HANDLE);

    // Create table and input chain with drop rules
    const char* setup_cmd =
        "add table ip userspace_filter\n"
        "add chain ip userspace_filter input { type filter hook input priority 0 ; policy accept ; }\n";

    if (nft_run_cmd_from_buffer(nft, setup_cmd) != 0) {
        std::cerr << "Error: failed to create nftables table/chain\n";
        nft_ctx_free(nft);
        nft = nullptr;
        return false;
    }

    return true;
}

static void cleanup_nft() {
    if (!nft) return;

    if (!persist_nft_rules) {
        const char* cleanup_cmd = "delete table ip userspace_filter\n";
        nft_run_cmd_from_buffer(nft, cleanup_cmd);
    } else if (verbosity >= 1) {
        std::cout << "Persisting nftables rules (table: userspace_filter)\n";
    }

    nft_ctx_free(nft);
    nft = nullptr;
}

static void apply_firewall_rule(const PacketInfo& pkt) {
    if (!nft) return;

    char cmd[512];

    if (pkt.key.protocol == IPPROTO_TCP || pkt.key.protocol == IPPROTO_UDP) {
        snprintf(cmd, sizeof(cmd),
                 "add rule ip userspace_filter input iifname \"%s\" ip saddr %s ip daddr %s %s sport %u dport %u drop\n",
                 interface_name,
                 pkt.src_ip_str,
                 pkt.dst_ip_str,
                 (pkt.key.protocol == IPPROTO_TCP) ? "tcp" : "udp",
                 pkt.key.src_port,
                 pkt.key.dst_port);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "add rule ip userspace_filter input iifname \"%s\" ip saddr %s ip daddr %s drop\n",
                 interface_name,
                 pkt.src_ip_str,
                 pkt.dst_ip_str);
    }

    if (verbosity >= 3) {
        printf("nft: %s", cmd);
    }

    if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
        printf("Warning: nftables rule insertion failed\n");
    }
}

// --- Socket creation ---

static int create_raw_socket(const char* iface) {
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }

    if (verbosity >= 1) {
        std::cout << "Raw socket created: " << sock_fd << std::endl;
    }

    ifreq ifr{};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sock_fd);
        return -1;
    }

    if (verbosity >= 1) {
        std::cout << "Interface " << iface << " has index: " << ifr.ifr_ifindex << std::endl;
    }

    sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock_fd, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
        perror("bind");
        close(sock_fd);
        return -1;
    }

    if (verbosity >= 1) {
        std::cout << "Socket bound to interface: " << iface << std::endl;
    }

    return sock_fd;
}

// --- Statistics and signal handling ---

static void print_statistics() {
    std::cout << "\n=== Final Statistics ===\n";
    std::cout << "Total flows processed: " << total_flows << "\n";
    std::cout << "Malicious flows: " << malicious_flows << "\n";
    std::cout << "Benign flows: " << benign_flows << "\n";
    std::cout << "Unclassified flows: " << (total_flows - malicious_flows - benign_flows) << "\n";
    std::cout << "========================\n";
}

static void signal_handler(int signum) {
    if (signum == SIGINT) {
        std::cout << "\n\n=== Caught SIGINT (Ctrl+C) - Shutting down ===\n";
        print_statistics();

        cleanup_nft();

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

// --- Main capture loop ---

static int run_capture_loop(int sock_fd, FlowTracker& tracker,
                            const std::vector<DecisionTree>& trees) {
    std::vector<unsigned char> buffer(65536, 0);

    while (true) {
        int buflen = recv(sock_fd, buffer.data(), buffer.size(), 0);
        if (buflen < 0) {
            printf("Error in recv()\n");
            return -1;
        }

        auto pkt = parse_packet(buffer.data(), buflen);
        if (!pkt)
            continue;

        if (verbosity >= 3) {
            printf("Flow: %s:%u -> %s:%u (proto: %u)\n",
                   pkt->src_ip_str, pkt->key.src_port,
                   pkt->dst_ip_str, pkt->key.dst_port,
                   pkt->key.protocol);
        }

        // Build flow_info for this packet
        timespec ts{};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t current_time = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;

        flow_info current_info{};
        current_info.last_seen = current_time;
        current_info.packets = 1;
        current_info.bytes = buflen;

        bool is_new = (tracker.get(pkt->key) == nullptr);

        if (is_new) {
            current_info.first_seen = current_time;
            current_info.iat_min = UINT64_MAX;
            tracker.set_state(pkt->key, Waiting);
            total_flows++;
        } else {
            current_info.first_seen = tracker.get(pkt->key)->first_seen;
        }

        tracker.update(pkt->key, current_info);

        // Classify once the flow has enough packets
        const flow_info* flow = tracker.get(pkt->key);
        if (flow->packets >= PACKETS_SAMPLE && tracker.get_state(pkt->key) == Waiting) {
            if (verbosity >= 3) {
                printf("Flow reached %d packets, classifying...\n", PACKETS_SAMPLE);
            }

            int result = force_malicious ? 1 : classify_flow(trees, *flow);

            if (result == 1) {
                tracker.set_state(pkt->key, Malicious);
                malicious_flows++;

                if (verbosity >= 2) {
                    printf("Flow classified as MALICIOUS: %s:%u -> %s:%u\n",
                           pkt->src_ip_str, pkt->key.src_port,
                           pkt->dst_ip_str, pkt->key.dst_port);
                }

                apply_firewall_rule(*pkt);
            } else {
                tracker.set_state(pkt->key, Benign);
                benign_flows++;

                if (verbosity >= 3) {
                    printf("Flow classified as BENIGN\n");
                }
            }
        }

        // Periodic flow stats logging
        if (verbosity >= 3 && flow->packets % 10 == 0) {
            printf("Flow stats - Packets: %lu, Bytes: %lu, Duration: %lu ns, PPS: %.2f, IAT Mean: %lu us\n",
                   flow->packets, flow->bytes, flow->duration,
                   flow->pps / 100000.0, flow->iat_mean);
        }
    }

    return 0;
}

// --- Entry point ---

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            verbosity = 1;
        } else if (strcmp(argv[i], "-vv") == 0) {
            verbosity = 2;
        } else if (strcmp(argv[i], "-vvv") == 0) {
            verbosity = 3;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            std::cout << "Usage: " << argv[0] << " [OPTIONS]\n"
                      << "Options:\n"
                      << "  -v              Normal verbosity\n"
                      << "  -vv             Verbose (classification results)\n"
                      << "  -vvv            Very verbose (all debug info)\n"
                      << "  -i <iface>      Network interface to capture on\n"
                      << "  --persist-rules Keep nftables rules after exit\n"
                      << "  --force-block   Classify all flows as malicious (debug)\n"
                      << "  -h, --help      Show this help message\n";
            return 0;
        } else if (strcmp(argv[i], "--persist-rules") == 0) {
            persist_nft_rules = true;
        } else if (strcmp(argv[i], "--force-block") == 0) {
            force_malicious = true;
        } else if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                interface_name = argv[++i];
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

    signal(SIGINT, signal_handler);

    // Load decision trees
    if (verbosity >= 1) {
        std::cout << "Loading decision tree data...\n";
    }

    std::vector<DecisionTree> trees(3);
    if (!trees[0].load("../decision-tree1") ||
        !trees[1].load("../decision-tree2") ||
        !trees[2].load("../decision-tree3")) {
        std::cerr << "Failed to load decision tree data\n";
        return 1;
    }

    if (verbosity >= 1) {
        std::cout << "All tree data loaded successfully!\n";
        std::cout << "Starting packet handler (Press Ctrl+C to stop)...\n";
    }

    // Initialize nftables
    if (!init_nft_table()) {
        std::cerr << "Failed to initialize nftables\n";
        return 1;
    }

    // Create socket and start capture
    int sock_fd = create_raw_socket(interface_name);
    if (sock_fd < 0) {
        cleanup_nft();
        return 1;
    }

    global_sock_fd = sock_fd;

    FlowTracker tracker;
    int ret = run_capture_loop(sock_fd, tracker, trees);

    cleanup_nft();
    close(sock_fd);
    return ret;
}
