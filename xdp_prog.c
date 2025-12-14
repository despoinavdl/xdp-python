#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/jhash.h>

#include "flow_headers.h"

// Constants
#define UINT64_MAX (~0ULL) // Maximum value for 64-bit unsigned integer
#define UINT32_MAX (~0U)   // Maximum value for 32-bit unsigned integer

BPF_HASH(flow_map, struct flow_key, struct flow_info, XDP_MAX_MAP_ENTRIES);

// Counter for packets that passed through XDP
BPF_HASH(passed_packets, u64, struct datarec, 1);

// Map for tracking flow states (Waiting, Ready, Malicious, Benign)
BPF_TABLE("lru_hash", struct flow_key, enum states, sig_map, 400000);

// Maps for tree_1
BPF_ARRAY(children_left1, s64, TREE_1_NODES);
BPF_ARRAY(children_right1, s64, TREE_1_NODES);
BPF_ARRAY(features1, s64, TREE_1_NODES);
BPF_ARRAY(thresholds1, s64, TREE_1_NODES);
BPF_ARRAY(values1, s64, TREE_1_NODES);
// Maps for tree_2
BPF_ARRAY(children_left2, s64, TREE_2_NODES);
BPF_ARRAY(children_right2, s64, TREE_2_NODES);
BPF_ARRAY(features2, s64, TREE_2_NODES);
BPF_ARRAY(thresholds2, s64, TREE_2_NODES);
BPF_ARRAY(values2, s64, TREE_2_NODES);
// Maps for tree_3
BPF_ARRAY(children_left3, s64, TREE_3_NODES);
BPF_ARRAY(children_right3, s64, TREE_3_NODES);
BPF_ARRAY(features3, s64, TREE_3_NODES);
BPF_ARRAY(thresholds3, s64, TREE_3_NODES);
BPF_ARRAY(values3, s64, TREE_3_NODES);



/* Updates the packet counter for packets that pass through XDP */
static __always_inline void update_passed_packets(void)
{
    u64 zero = 0;
    // struct datarec *rec = {0};
    struct datarec new_rec = {.packets = 1};

    struct datarec *rec = (struct datarec *)passed_packets.lookup(&zero);
    if (!rec)
    {
        // First entry - initialize the counter
        passed_packets.insert(&zero, &new_rec);
        return;
    }

    lock_xadd(&rec->packets, 1);
}

/* Updates a hash map with flow information
 * key: Hashed flow key
 * info: Flow information to store/update
 * return 0 on success, -1 on error
 */
static __always_inline int update_map(struct flow_key key, struct flow_info info)
{
    struct flow_info *rec;
    int ret;
    u64 packets_old;
    u64 last_seen_old;
    u64 iat_mean_old;
    u64 iat_total_old;
    u64 iat_min_old;
    u64 iat_max_old;
    u64 iat;

    rec = (struct flow_info *)flow_map.lookup(&key);

    // If entry doesn't exist yet, initialize it
    if (!rec) {
        // Insert new entry 
        flow_map.update(&key, &info);
        return 0;
    }

    // Entry exists - update it with new information
    // Acquire lock
    bpf_spin_lock(&rec->lock);

    // Save old values for Mean IAT calculation
    packets_old = rec->packets;
    last_seen_old = rec->last_seen;
    iat_mean_old = rec->iat_mean;
    iat_total_old = rec->iat_total;
    iat_min_old = rec->iat_min;
    iat_max_old = rec->iat_max;

    // Update last_seen and calculate duration, IAT
    if (rec->last_seen < info.last_seen) {
        rec->last_seen = info.last_seen;
        // Duration in nanoseconds
        rec->duration = rec->last_seen - rec->first_seen;
        
        // IAT Calculation, scale from ns to microseconds 
        // unit in dataset is microseconds
        if (packets_old > 0) {
            iat = (rec->last_seen - last_seen_old) / 1000;
            rec->iat_total = iat_total_old + iat;
            rec->iat_mean = (iat_total_old + iat) / packets_old;
            if(iat_min_old > iat) rec->iat_min = iat;
            if(iat_max_old < iat) rec->iat_max = iat;
        }
    }
    
    // Update packet and byte counters, if this packet is newer than what we've seen
    rec->packets += info.packets;
    rec->bytes += info.bytes;

    // Calculate rates if we have valid duration
    if (rec->duration >= 1000000000) { //if duration >= 1 second
        // Scaling packets per second like the values in the thresholds map
        // note: rec->duration is in nanoseconds
        rec->pps = (rec->packets * 1000000000 * 100000) / rec->duration;
        // Bytes per second with no decimal point accuracy (!not using this feature!)
        rec->bps = (rec->bytes * 1000000000 * 100000) / rec->duration;
    }
    else {
        // Scale by 100_000
        rec->pps = rec->packets * 100000;
        rec->bps = rec->bytes;
    }

    bpf_spin_unlock(&rec->lock);  // Release lock

    // flow_map.update(&key, rec); not needed since pointer is being updated

    return 0;
}


//------------------------------------------------------------------------------
// MAIN XDP PACKET HANDLER
//------------------------------------------------------------------------------

/*
 * Main XDP packet processing function
 * 
 * This function:
 * 1. Parses the packet to extract flow information
 * 2. Checks if flow is already classified as malicious/benign
 * 3. Updates the flow_map with flow statistics
 * 4. Decides whether to pass or drop the packet
 * 
 * ctx: XDP context containing packet data
 * return XDP action (XDP_PASS, XDP_DROP, XDP_ABORTED)
 */

int packet_handler(struct xdp_md *ctx)
{
    // Access packet data
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    u64 size = data_end - data;

    // Initialize flow key and info structures
    struct flow_key key = {0};
    struct flow_info info = {0};
    int ret;

    if ((void *)eth + sizeof(*eth) > data_end) {
        // Malformed packet - drop it
        return XDP_DROP;
    }

    // Only process IPv4 packets
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_DROP;
        // update_passed_packets();
        // printk("EtherType: 0x%x\n", ntohs(eth->h_proto));
        // return XDP_PASS;
    }

    // Extract IP addresses and protocol
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
    {
        // Malformed packet - drop it
        return XDP_DROP;
    }

    key.dst_ip = ip->daddr;
    key.src_ip = ip->saddr;
    key.protocol = ip->protocol;

    // Extract ports based on protocol (TCP or UDP)
    if (key.protocol == IPPROTO_TCP) // Handle TCP packets
    {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end) {
            update_passed_packets();
            return XDP_PASS;
        }

        key.src_port = tcp->source; // Extract TCP source port
        key.dst_port = tcp->dest;   // Extract TCP destination port
    }
    else if (key.protocol == IPPROTO_UDP) // Handle UDP packets
    {
        // return XDP_DROP;
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end) {
            update_passed_packets();
            return XDP_PASS;
        }

        key.src_port = udp->source; // Extract UDP source port
        key.dst_port = udp->dest;   // Extract UDP destination port
    }
    else
    {
        // Other protocols don't have ports
        key.src_port = 0;
        key.dst_port = 0;
    }
    
    enum states state = Waiting;

    // Retrieve flow state 
    enum states *state_ptr = sig_map.lookup(&key);

    // Take action based on existing classification
    if (state_ptr) {
        state = *state_ptr;
        if (state == Malicious) {
            return XDP_DROP; // Drop malicious flows
        } else if (state == Benign) {
            update_passed_packets();
            return XDP_PASS; // Pass benign flows
        }
    } else {
        sig_map.update(&key, &state);
    }

    // Set initial state if not already classified
    // sig_map.update(&key, &state);

    // Initialize flow info structure with packet details
    info.packets = 1;
    info.bytes = size;
    info.first_seen = bpf_ktime_get_ns();
    info.last_seen = info.first_seen;
    info.duration = 0;
    info.pps = 0;
    info.bps = 0;
    info.iat_mean = 0;
    info.iat_total = 0;
    info.iat_min = UINT64_MAX;
    info.iat_max = 0;

    // Update flow_map
    update_map(key, info);

    // bpf_trace_printk("flow packets: %u, PACKETS_SAMPLE: %d\n", agg.packets, PACKETS_SAMPLE);

    // Lookup can be avoided if update_map returns packet count
    struct flow_info *updated_flow = flow_map.lookup(&key);
    
    u64 flow_feature;
    // Check if we've collected enough samples to make a decision (flow timeout? -> userspace)
    if (updated_flow && updated_flow->packets >= PACKETS_SAMPLE && state == Waiting) // || ((current_time - agg.last_seen) > FLOW_TIMEOUT))
    {
        // Traverse DT 1
        int current_node = 0;
        for (int i=0; i<MAX_DEPTH; i++) {
            //bpf_trace_printk("Traversing tree 1");
            // Lookup DT values
            s64 * current_left_child = children_left1.lookup(&current_node);
            s64 * current_right_child = children_right1.lookup(&current_node);
            // Check if leaf node
            if (current_left_child == NULL || current_right_child == NULL || *current_left_child < 0) 
            // current_left_child and current_right_child are both < 0 when the node is a leaf
					break;

            s64 * current_feature = features1.lookup(&current_node);
            s64 * current_threshold = thresholds1.lookup(&current_node);
            if (current_feature == NULL || current_threshold == NULL) 
                break;
            // Lookup flow values
            // Indices/Order of Features
            // 0: Total Length of Fwd Packets  1: Total Fwd Packets
            // 2: Fwd Packets/s                3: Fwd IAT Mean
            // 4: Fwd IAT Min                  5: Fwd IAT Max
            // 6: Fwd IAT Total
            switch (*current_feature) {
                case 0:
                    flow_feature = updated_flow->bytes;
                    break;
                case 1:
                    flow_feature = updated_flow->packets;
                    break;
                case 2:
                    flow_feature = updated_flow->pps;
                    break;
                case 3:
                    flow_feature = updated_flow->iat_mean;
                    break;
                case 4:
                    flow_feature = updated_flow->iat_min;
                    break;
                case 5:
                    flow_feature = updated_flow->iat_max;
                    break;
                case 6:
                    flow_feature = updated_flow->iat_total;
                    break;
            }
            
            // All values are loaded
            if(flow_feature <= *current_threshold) {
                bpf_trace_printk("testing, flow feature value %lld (idx: %lld)", flow_feature, *current_feature);
                current_node = *current_left_child;
            }
            else {
                current_node = *current_right_child;
            }
        }
        // Check the classification decision on the leaf node
        // Benign: 0,  Malicious: 1
        s64 * current_value = values1.lookup(&current_node);
        if(current_value != NULL) {
            state = (*current_value == 1) ? Malicious : Benign;
            sig_map.update(&key, &state);
            bpf_trace_printk("testing, classification result: %lld ", *current_value);
        }
    }

    // Increment the counter value for passed packets
    update_passed_packets();
    return XDP_PASS;
}
