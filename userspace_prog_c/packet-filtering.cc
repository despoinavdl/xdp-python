#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <vector>

#include <fstream>
#include <sstream>
#include <string>

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h> // AF_PACKET
#include <linux/if_ether.h>  // ETH_P_ALL
#include <unistd.h>        // close()

#include "flow_headers.h"

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
    // std::cout << "Loaded " << target_vector.size() << " values from " << filename << std::endl;
    return true;
}
