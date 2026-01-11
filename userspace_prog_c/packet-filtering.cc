#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <vector>

#include <fstream>
#include <sstream>
#include <string>

#include "packet_handler.cc"
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h> // AF_PACKET
#include <linux/if_ether.h>  // ETH_P_ALL
#include <unistd.h>        // close()

// Constants
// #define UINT64_MAX (~0ULL) // Maximum value for 64-bit unsigned integer
// #define UINT32_MAX (~0U)   // Maximum value for 32-bit unsigned integer

std::unordered_map<struct flow_key, struct flow_info> flow_map;

// Counter for packets that passed through XDP
uint64_t passed_packets = 0;

// Map for tracking flow states (Waiting, Ready, Malicious, Benign)
std::unordered_map<struct flow_key, enum states> sig_map;

// Maps for tree_1
std::vector<int64_t> children_left1;
std::vector<int64_t> children_right1;
std::vector<int64_t> features1;
std::vector<int64_t> thresholds1;
std::vector<int64_t> values1;
// Maps for tree_2
std::vector<int64_t> children_left2;
std::vector<int64_t> children_right2;
std::vector<int64_t> features2;
std::vector<int64_t> thresholds2;
std::vector<int64_t> values2;
// Maps for tree_3
std::vector<int64_t> children_left3;
std::vector<int64_t> children_right3;
std::vector<int64_t> features3;
std::vector<int64_t> thresholds3;
std::vector<int64_t> values3;


/* Updates the packet counter for packets that pass through XDP */
static inline void update_passed_packets(void)
{
    passed_packets++;
}

/* Updates a hash map with flow information
 * key: Hashed flow key
 * info: Flow information to store/update
 * return 0 on success, -1 on error
 */
static inline int update_map(struct flow_key key, struct flow_info info)
{
    int ret;
    uint64_t packets_old;
    uint64_t last_seen_old;
    uint64_t iat_mean_old;
    uint64_t iat_total_old;
    uint64_t iat_min_old;
    uint64_t iat_max_old;
    uint64_t iat;

    // If entry doesn't exist yet, initialize it
    if (flow_map.count(key) == 0) {
        flow_map.emplace(key, info);
        return 0;
    }

    // Entry exists - update it with new information
    // Save old values for Mean IAT calculation
    packets_old = flow_map[key].packets;
    last_seen_old = flow_map[key].last_seen;
    iat_mean_old = flow_map[key].iat_mean;
    iat_total_old = flow_map[key].iat_total;
    iat_min_old = flow_map[key].iat_min;
    iat_max_old = flow_map[key].iat_max;

    // Update last_seen and calculate duration, IAT
    if (last_seen_old < info.last_seen) {
        flow_map[key].last_seen = info.last_seen;
        // Duration in nanoseconds
        flow_map[key].duration = flow_map[key].last_seen - flow_map[key].first_seen;
        
        // IAT Calculation, scale from ns to microseconds 
        // unit in dataset is microseconds
        if (packets_old > 0) {
            iat = (flow_map[key].last_seen - last_seen_old) / 1000;
            flow_map[key].iat_total = iat_total_old + iat;
            flow_map[key].iat_mean = (iat_total_old + iat) / packets_old;
            if(iat_min_old > iat) flow_map[key].iat_min = iat;
            if(iat_max_old < iat) flow_map[key].iat_max = iat;
        }
    }
    
    // Update packet and byte counters, if this packet is newer than what we've seen
    flow_map[key].packets += info.packets;
    flow_map[key].bytes += info.bytes;

    // Calculate rates if we have valid duration
    if (flow_map[key].duration >= 1000000000) { //if duration >= 1 second
        // Scaling packets per second like the values in the thresholds map
        // note: duration in map is in nanoseconds
        flow_map[key].pps = (flow_map[key].packets * 1000000000 * 100000) / flow_map[key].duration;
        // Bytes per second with no decimal point accuracy (!not using this feature!)
        flow_map[key].bps = (flow_map[key].bytes * 1000000000 * 100000) / flow_map[key].duration;
    }
    else {
        // Scale by 100_000
        flow_map[key].pps = flow_map[key].packets * 100000;
        flow_map[key].bps = flow_map[key].bytes;
    }

    return 0;
}

static inline int traverse_dt(int tree_id, uint64_t flow_feature, struct flow_key key, enum states state, struct flow_info *updated_flow) {
    int current_node = 0;
    for (int i=0; i<MAX_DEPTH; i++) {
        //bpf_trace_printk("Traversing tree %d", tree_id);
        // Lookup DT values
        int64_t current_left_child = 0;
        int64_t current_right_child = 0;
        int64_t current_feature = 0;
        int64_t current_threshold = 0;
         // Select maps based on tree_id
        switch (tree_id) {
            case 1:
                current_left_child = children_left1[current_node];
                current_right_child = children_right1[current_node];
                current_feature = features1[current_node];
                current_threshold = thresholds1[current_node];
                break;
            case 2:
                current_left_child = children_left2[current_node];
                current_right_child = children_right2[current_node];
                current_feature = features2[current_node];
                current_threshold = thresholds2[current_node];
                break;
            case 3:
                current_left_child = children_left3[current_node];
                current_right_child = children_right3[current_node];
                current_feature = features3[current_node];
                current_threshold = thresholds3[current_node];
                break;
            default:
                return -1;  // Invalid tree_id
        }
        
        // Check if leaf node
        // note: current_left_child and current_right_child are both < 0 when the node is a leaf
        // so checking only for one of them is enough
        if (current_left_child < 0)
                break;
        // Lookup flow values
        // Indices/Order of Features
        // 0: Total Length of Fwd Packets  1: Total Fwd Packets
        // 2: Fwd Packets/s                3: Fwd IAT Mean
        // 4: Fwd IAT Min                  5: Fwd IAT Max
        // 6: Fwd IAT Total
        switch (current_feature) {
            case 0: flow_feature = updated_flow->bytes; break;
            case 1: flow_feature = updated_flow->packets; break;
            case 2: flow_feature = updated_flow->pps; break;
            case 3: flow_feature = updated_flow->iat_mean; break;
            case 4: flow_feature = updated_flow->iat_min; break;
            case 5: flow_feature = updated_flow->iat_max; break;
            case 6: flow_feature = updated_flow->iat_total; break;
        }
        
        // All values are loaded
        if(flow_feature <= current_threshold) {
            // printf("testing, flow feature value %ld (idx: %ld)", flow_feature, current_feature);
            current_node = current_left_child;
        }
        else {
            current_node = current_right_child;
        }
    }

    // Benign: 0,  Malicious: 1
    // Get classification result from correct values map (on leaf node)
    int64_t current_value = -1;
    switch (tree_id) {
        case 1: current_value = values1[current_node]; break;
        case 2: current_value = values2[current_node]; break;
        case 3: current_value = values3[current_node]; break;
    }
    // printf("testing, classification result: %ld ", current_value);
    return current_value;
}

//------------------------------------------------------------------------------
// MAIN USERSPACE PACKET HANDLER
//------------------------------------------------------------------------------

/*
 * Main userspace packet processing function
 * 
 * This function:
 * 1. Parses the packet to extract flow information
 * 2. Checks if flow is already classified as malicious/benign
 * 3. Updates the flow_map with flow statistics
 * 4. Decides whether to pass or drop the packet
 * 
 */

int main()
{
    return packet_handler();
}



// int packet_handler(struct xdp_md *ctx)
// {
//     // Access packet data
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;
//     struct ethhdr *eth = data;
//     u64 size = data_end - data;

//     // Initialize flow key and info structures
//     struct flow_key key = {0};
//     struct flow_info info = {0};
//     int ret;

//     if ((void *)eth + sizeof(*eth) > data_end) {
//         // Malformed packet - drop it
//         return XDP_DROP;
//     }

//     // Only process IPv4 packets
//     if (ntohs(eth->h_proto) != ETH_P_IP) {
//         return XDP_DROP;
//         // update_passed_packets();
//         // printk("EtherType: 0x%x\n", ntohs(eth->h_proto));
//         // return XDP_PASS;
//     }

//     // Extract IP addresses and protocol
//     struct iphdr *ip = data + sizeof(*eth);
//     if ((void *)ip + sizeof(*ip) > data_end)
//     {
//         // Malformed packet - drop it
//         return XDP_DROP;
//     }

//     key.dst_ip = ip->daddr;
//     key.src_ip = ip->saddr;
//     key.protocol = ip->protocol;

//     // Extract ports based on protocol (TCP or UDP)
//     if (key.protocol == IPPROTO_TCP) // Handle TCP packets
//     {
//         struct tcphdr *tcp = (void *)ip + sizeof(*ip);
//         if ((void *)tcp + sizeof(*tcp) > data_end) {
//             update_passed_packets();
//             return XDP_PASS;
//         }

//         key.src_port = tcp->source; // Extract TCP source port
//         key.dst_port = tcp->dest;   // Extract TCP destination port
//     }
//     else if (key.protocol == IPPROTO_UDP) // Handle UDP packets
//     {
//         // return XDP_DROP;
//         struct udphdr *udp = (void *)ip + sizeof(*ip);
//         if ((void *)udp + sizeof(*udp) > data_end) {
//             update_passed_packets();
//             return XDP_PASS;
//         }

//         key.src_port = udp->source; // Extract UDP source port
//         key.dst_port = udp->dest;   // Extract UDP destination port
//     }
//     else
//     {
//         // Other protocols don't have ports
//         key.src_port = 0;
//         key.dst_port = 0;
//     }
    
//     enum states state = Waiting;

//     // Retrieve flow state 
//     enum states *state_ptr = sig_map.lookup(&key);

//     // Take action based on existing classification
//     if (state_ptr) {
//         state = *state_ptr;
//         if (state == Malicious) {
//             return XDP_DROP; // Drop malicious flows
//         } else if (state == Benign) {
//             update_passed_packets();
//             return XDP_PASS; // Pass benign flows
//         }
//     } else {
//         sig_map.update(&key, &state);
//     }

//     // Set initial state if not already classified
//     // sig_map.update(&key, &state);

//     // Initialize flow info structure with packet details
//     info.packets = 1;
//     info.bytes = size;
//     info.first_seen = bpf_ktime_get_ns();
//     info.last_seen = info.first_seen;
//     info.duration = 0;
//     info.pps = 0;
//     info.bps = 0;
//     info.iat_mean = 0;
//     info.iat_total = 0;
//     info.iat_min = UINT64_MAX;
//     info.iat_max = 0;

//     // Update flow_map
//     update_map(key, info);

//     // bpf_trace_printk("flow packets: %u, PACKETS_SAMPLE: %d\n", agg.packets, PACKETS_SAMPLE);

//     // Lookup can be avoided if update_map returns packet count [oxi?]
//     struct flow_info *updated_flow = flow_map.lookup(&key);
    
//     u64 flow_feature;
//     int result_1 = 0;
//     int result_2 = 0;
//     int result_3 = 0;
//     // Check if we've collected enough samples to make a decision (flow timeout? -> userspace)
//     if (updated_flow && updated_flow->packets >= PACKETS_SAMPLE && state == Waiting) // || ((current_time - agg.last_seen) > FLOW_TIMEOUT))
//     {
//         result_1 = traverse_dt(1, flow_feature, key, state, updated_flow);
//         bpf_trace_printk("result_1 %d", result_1);
//         result_2 = traverse_dt(2, flow_feature, key, state, updated_flow);
//         bpf_trace_printk("result_2 %d", result_2);
//         result_3 = traverse_dt(3, flow_feature, key, state, updated_flow);
//         bpf_trace_printk("result_3 %d", result_3);
//         state = (result_1 + result_2 + result_3 >= 2) ? Malicious : Benign;
//         sig_map.update(&key, &state);
//     }

//     // Increment the counter value for passed packets
//     update_passed_packets();
//     return XDP_PASS;
// }


// Function to load tree data from line-separated files
bool load_tree_data(const std::string& filename, 
                    std::vector<int64_t>& target_vector) {
    
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines
        if (line.empty()) continue;
        
        try {
            int64_t value = std::stoll(line);
            target_vector.push_back(value);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Could not parse line: " << line << " in " << filename << std::endl;
        }
    }
    
    file.close();
    std::cout << "Loaded " << target_vector.size() << " values from " << filename << std::endl;
    return true;
}


/* TESTING */
// int main() {
//     std::cout << "Testing flow monitoring system..." << std::endl;
    
//     // Load tree data from files - assuming separate files for each component
//     std::cout << "\nLoading decision tree data..." << std::endl;
    
//     // Tree 1 - assuming files like: children_left1, children_right1, etc.
//     if (!load_tree_data("/home/dvidali/xdp-python/decision-tree1/children_left", children_left1) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree1/children_right", children_right1) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree1/features", features1) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree1/thresholds", thresholds1) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree1/values", values1)) {
//         std::cerr << "Failed to load tree 1 data" << std::endl;
//         return 1;
//     }
    
//     // Tree 2
//     if (!load_tree_data("/home/dvidali/xdp-python/decision-tree2/children_left", children_left2) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree2/children_right", children_right2) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree2/features", features2) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree2/thresholds", thresholds2) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree2/values", values2)) {
//         std::cerr << "Failed to load tree 2 data" << std::endl;
//         return 1;
//     }
    
//     // Tree 3
//     if (!load_tree_data("/home/dvidali/xdp-python/decision-tree3/children_left", children_left3) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree3/children_right", children_right3) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree3/features", features3) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree3/thresholds", thresholds3) ||
//         !load_tree_data("/home/dvidali/xdp-python/decision-tree3/values", values3)) {
//         std::cerr << "Failed to load tree 3 data" << std::endl;
//         return 1;
//     }
    
//     // Verify all trees have the same number of nodes (optional)
//     if (children_left1.size() != children_right1.size() ||
//         children_left1.size() != features1.size() ||
//         children_left1.size() != thresholds1.size() ||
//         children_left1.size() != values1.size()) {
//         std::cerr << "Warning: Tree 1 data arrays have different sizes!" << std::endl;
//     }
    
//     std::cout << "\nTree 1 has " << children_left1.size() << " nodes" << std::endl;
//     std::cout << "Tree 2 has " << children_left2.size() << " nodes" << std::endl;
//     std::cout << "Tree 3 has " << children_left3.size() << " nodes" << std::endl;
    
//     // Create a test flow
//     flow_key test_key{0x0A000001, 0x0A000002, 12345, 80, 6};  // 10.0.0.1 -> 10.0.0.2, TCP
    
//     flow_info test_info;
//     test_info.packets = 10;
//     test_info.bytes = 1500;
//     test_info.first_seen = 1000000;
//     test_info.last_seen = 2000000;
//     test_info.iat_mean = 100;
//     test_info.iat_min = 50;
//     test_info.iat_max = 200;
//     test_info.iat_total = 1000;
//     test_info.pps = 100000;  // 1 packet per second * 100000 scaling
    
//     // Test update_map
//     std::cout << "\nTesting update_map..." << std::endl;
//     int result = update_map(test_key, test_info);
//     std::cout << "update_map returned: " << result << std::endl;
//     std::cout << "Flow map size: " << flow_map.size() << std::endl;
    
//     // Test passed packets counter
//     update_passed_packets();
//     std::cout << "Passed packets: " << passed_packets << std::endl;
    
//     // Test traverse_dt with loaded tree data
//     std::cout << "\nTesting decision tree traversal..." << std::endl;
    
//     // Get the updated flow info from map
//     if (flow_map.find(test_key) != flow_map.end()) {
//         flow_info& updated_flow = flow_map[test_key];
        
//         std::cout << "Traversing tree 1..." << std::endl;
//         int result1 = traverse_dt(1, 0, test_key, Benign, &updated_flow);
//         std::cout << "Tree 1 result: " << result1 << " (0=Benign, 1=Malicious)" << std::endl;
        
//         std::cout << "\nTraversing tree 2..." << std::endl;
//         int result2 = traverse_dt(2, 0, test_key, Benign, &updated_flow);
//         std::cout << "Tree 2 result: " << result2 << " (0=Benign, 1=Malicious)" << std::endl;
        
//         std::cout << "\nTraversing tree 3..." << std::endl;
//         int result3 = traverse_dt(3, 0, test_key, Benign, &updated_flow);
//         std::cout << "Tree 3 result: " << result3 << " (0=Benign, 1=Malicious)" << std::endl;
        
//         // Simple voting mechanism
//         int malicious_votes = result1 + result2 + result3;
//         std::cout << "\nVoting result: " << malicious_votes << "/3 votes for malicious" << std::endl;
//         if (malicious_votes >= 2) {
//             std::cout << "FINAL DECISION: MALICIOUS" << std::endl;
//             // Update sig_map
//             sig_map[test_key] = Malicious;
//         } else {
//             std::cout << "FINAL DECISION: BENIGN" << std::endl;
//             sig_map[test_key] = Benign;
//         }
//     } else {
//         std::cerr << "Error: Test flow not found in map" << std::endl;
//     }
    
//     // Test with multiple packets to update IAT
//     std::cout << "\n\nTesting with multiple packet updates..." << std::endl;
//     flow_info test_info2;
//     test_info2.packets = 1;
//     test_info2.bytes = 150;
//     test_info2.last_seen = 3000000;  // 1 second later
    
//     update_map(test_key, test_info2);
//     std::cout << "Updated flow with second packet" << std::endl;
//     std::cout << "Flow packets: " << flow_map[test_key].packets << std::endl;
//     std::cout << "Flow bytes: " << flow_map[test_key].bytes << std::endl;
//     std::cout << "Flow IAT mean: " << flow_map[test_key].iat_mean << std::endl;
//     std::cout << "Flow duration: " << flow_map[test_key].duration << std::endl;
//     std::cout << "Flow PPS: " << flow_map[test_key].pps << std::endl;
    
//     std::cout << "\nAll tests completed!" << std::endl;
//     return 0;
// }
