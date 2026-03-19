#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/jhash.h>

#include "flow_headers.h"

#define UINT64_MAX (~0ULL)

BPF_HASH(flow_map, struct flow_key, struct flow_info, XDP_MAX_MAP_ENTRIES);

// Counter for packets that passed through XDP
BPF_HASH(passed_packets, u64, struct datarec, 1);

// Map for tracking flow states (Waiting, Ready, Malicious, Benign)
BPF_TABLE("lru_hash", struct flow_key, enum states, sig_map, 400000);

// Decision tree maps (5 arrays per tree)
#define DECLARE_TREE_MAPS(N, NODES)           \
    BPF_ARRAY(children_left##N, s64, NODES);  \
    BPF_ARRAY(children_right##N, s64, NODES); \
    BPF_ARRAY(features##N, s64, NODES);       \
    BPF_ARRAY(thresholds##N, s64, NODES);     \
    BPF_ARRAY(values##N, s64, NODES);

DECLARE_TREE_MAPS(1, TREE_1_NODES)
DECLARE_TREE_MAPS(2, TREE_2_NODES)
DECLARE_TREE_MAPS(3, TREE_3_NODES)

/* Updates the packet counter for packets that pass through XDP */
static __always_inline void update_passed_packets(void)
{
    u64 zero = 0;
    struct datarec new_rec = {.packets = 1};

    struct datarec *rec = (struct datarec *)passed_packets.lookup(&zero);
    if (!rec) {
        passed_packets.insert(&zero, &new_rec);
        return;
    }

    lock_xadd(&rec->packets, 1);
}

/* Updates a hash map with flow information and returns pointer to the entry.
 * key: Flow key
 * info: Flow information to store/update
 * return pointer to the flow_info entry, or NULL on error
 */
static __always_inline struct flow_info *update_map(struct flow_key key, struct flow_info info)
{
    struct flow_info *rec = (struct flow_info *)flow_map.lookup(&key);

    // If entry doesn't exist yet, initialize it
    if (!rec) {
        flow_map.update(&key, &info);
        return flow_map.lookup(&key);
    }

    bpf_spin_lock(&rec->lock);

    u64 prev_packets = rec->packets;
    u64 prev_last_seen = rec->last_seen;

    // Update packet and byte counters
    rec->packets += info.packets;
    rec->bytes += info.bytes;

    // Update timestamps, duration, and IAT
    if (prev_last_seen < info.last_seen) {
        rec->last_seen = info.last_seen;
        rec->duration = rec->last_seen - rec->first_seen;

        // IAT calculation (ns -> microseconds to match dataset units)
        if (prev_packets > 0) {
            u64 iat = (info.last_seen - prev_last_seen) / 1000;
            rec->iat_total += iat;
            rec->iat_mean = rec->iat_total / prev_packets;
            if (rec->iat_min > iat) rec->iat_min = iat;
            if (rec->iat_max < iat) rec->iat_max = iat;
        }
    }

    // Calculate rates (scaled by 100_000 to match threshold map values)
    if (rec->duration >= 1000000000) {
        rec->pps = (rec->packets * 1000000000 * 100000) / rec->duration;
        rec->bps = (rec->bytes * 1000000000 * 100000) / rec->duration;
    } else {
        rec->pps = rec->packets * 100000;
        rec->bps = rec->bytes;
    }

    bpf_spin_unlock(&rec->lock);
    return rec;
}

static __always_inline int traverse_dt(int tree_id, struct flow_info *flow) {
    int current_node = 0;
    u64 flow_feature = 0;

    for (int i = 0; i < MAX_DEPTH; i++) {
        s64 *current_left_child = NULL;
        s64 *current_right_child = NULL;
        s64 *current_feature = NULL;
        s64 *current_threshold = NULL;
        switch (tree_id) {
            case 1:
                current_left_child = children_left1.lookup(&current_node);
                current_right_child = children_right1.lookup(&current_node);
                current_feature = features1.lookup(&current_node);
                current_threshold = thresholds1.lookup(&current_node);
                break;
            case 2:
                current_left_child = children_left2.lookup(&current_node);
                current_right_child = children_right2.lookup(&current_node);
                current_feature = features2.lookup(&current_node);
                current_threshold = thresholds2.lookup(&current_node);
                break;
            case 3:
                current_left_child = children_left3.lookup(&current_node);
                current_right_child = children_right3.lookup(&current_node);
                current_feature = features3.lookup(&current_node);
                current_threshold = thresholds3.lookup(&current_node);
                break;
            default: return -1;
        }
        
        // Check if leaf node (left_child < 0 indicates leaf)
        if (current_left_child == NULL || current_right_child == NULL ||
            current_feature == NULL || current_threshold == NULL ||
            *current_left_child < 0)
            break;
        // Feature indices:
        // 0: Total Length of Fwd Packets  1: Total Fwd Packets
        // 2: Fwd Packets/s               3: Fwd IAT Mean
        // 4: Fwd IAT Min                 5: Fwd IAT Max
        // 6: Fwd IAT Total
        switch (*current_feature) {
            case 0: flow_feature = flow->bytes; break;
            case 1: flow_feature = flow->packets; break;
            case 2: flow_feature = flow->pps; break;
            case 3: flow_feature = flow->iat_mean; break;
            case 4: flow_feature = flow->iat_min; break;
            case 5: flow_feature = flow->iat_max; break;
            case 6: flow_feature = flow->iat_total; break;
            default: return -1;
        }
        
        // All values are loaded
        if (flow_feature <= *current_threshold) {
#ifdef DEBUG_TRACE
            bpf_trace_printk("testing, flow feature value %lld (idx: %lld)", flow_feature, *current_feature);
#endif
            current_node = *current_left_child;
        }
        else {
            current_node = *current_right_child;
        }
    }

    // Benign: 0,  Malicious: 1
    // Get classification result from correct values map (on leaf node)
    s64 *current_value = NULL;
    switch (tree_id) {
        case 1: current_value = values1.lookup(&current_node); break;
        case 2: current_value = values2.lookup(&current_node); break;
        case 3: current_value = values3.lookup(&current_node); break;
    }
    if (current_value != NULL) {
#ifdef DEBUG_TRACE
        bpf_trace_printk("testing, classification result: %lld ", *current_value);
#endif
        return *current_value;
    }
    return -1;
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

    if ((void *)eth + sizeof(*eth) > data_end) {
        // Malformed packet - drop it
        return XDP_DROP;
    }

    // Only process IPv4 packets; pass everything else (ARP, IPv6, etc.)
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Extract IP addresses and protocol
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        // Malformed packet - drop it
        return XDP_DROP;
    }

    key.dst_ip = ip->daddr;
    key.src_ip = ip->saddr;
    key.protocol = ip->protocol;

    // Extract ports based on protocol (TCP or UDP)
    if (key.protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end) {
            update_passed_packets();
            return XDP_PASS;
        }
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (key.protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end) {
            update_passed_packets();
            return XDP_PASS;
        }
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    } else {
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

    struct flow_info *updated_flow = update_map(key, info);

    // Classify once we have enough samples
    if (updated_flow && updated_flow->packets >= PACKETS_SAMPLE && state == Waiting) {
        int result_1 = traverse_dt(1, updated_flow);
        int result_2 = traverse_dt(2, updated_flow);
        int result_3 = traverse_dt(3, updated_flow);

        // Only classify if all trees returned valid results
        if (result_1 >= 0 && result_2 >= 0 && result_3 >= 0) {
            int votes = result_1 + result_2 + result_3;
            state = (votes >= 2) ? Malicious : Benign;
            sig_map.update(&key, &state);
        }
    }

    // Increment the counter value for passed packets
    update_passed_packets();
    return XDP_PASS;
}
