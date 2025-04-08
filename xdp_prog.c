// This eBPF/XDP program implements a Count-Min Sketch (CMS) data structure
// to track network flow statistics/features with multiple hash functions for accuracy.
// It monitors packet flows and can classify them as malicious or benign with the help
// of a userspace program.

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

// Hash maps for count min sketch (CMS)
// Each map uses a different hash function for the same key to minimize collisions
BPF_HASH(hash_func_1, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);
BPF_HASH(hash_func_2, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);
BPF_HASH(hash_func_3, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);
BPF_HASH(hash_func_4, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);
BPF_HASH(hash_func_5, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);

// Map for aggregated results from CMS for userspace access
BPF_HASH(aggr, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);

// Array map to track timestamps between consecutive flows (for IAT calculation)
BPF_ARRAY(last_first_seen, u64, NUM_HASH_FUNCTIONS);

// Counter for packets that passed through XDP
BPF_HASH(passed_packets, u32, struct datarec, 1);

// Map for tracking flow states (Waiting, Ready, Malicious, Benign)
BPF_HASH(sig_map, u32, enum states, XDP_MAX_MAP_ENTRIES);

// Structure to hold hash keys and seeds (moved from stack to avoid stack size limitations)
struct hash_info {
    u32 hashed_keys[NUM_HASH_FUNCTIONS];
    u32 map_seeds[NUM_HASH_FUNCTIONS];
};

// Per-CPU array to store hash state
BPF_PERCPU_ARRAY(hash_info_map, struct hash_info, 1);


/* Updates the packet counter for packets that pass through XDP */
static __always_inline void update_passed_packets(void)
{
    u32 zero = 0;
    struct datarec *rec = {0};
    struct datarec new_rec = {.packets = 1};
    int ret;

    rec = (struct datarec *)passed_packets.lookup(&zero);
    if (!rec)
    {
        // First entry - initialize the counter
        passed_packets.insert(&zero, &new_rec);
        return;
    }

    lock_xadd(&rec->packets, 1);
}


/* Updates a Count-Min Sketch hash map with flow information
 * map_flag: Index of the hash map to update (1-5)
 * key: Hashed flow key
 * info: Flow information to store/update
 * lfs_key: Key for the last_first_seen array
 * aggregated: Pointer to store aggregated min values
 * return 0 on success, -1 on error
 */
static __always_inline int update_map(u8 map_flag, u32 key, struct flow_info info, u32 lfs_key, struct flow_info *aggregated)
{
    struct flow_info *rec;
    int ret;
    u64 *last_first_seen_value;

    // Select the appropriate map based on map_flag
    switch (map_flag) {
        case 1: rec = (struct flow_info *)hash_func_1.lookup(&key); break;
        case 2: rec = (struct flow_info *)hash_func_2.lookup(&key); break;
        case 3: rec = (struct flow_info *)hash_func_3.lookup(&key); break;
        case 4: rec = (struct flow_info *)hash_func_4.lookup(&key); break;
        case 5: rec = (struct flow_info *)hash_func_5.lookup(&key); break;
        default: return -1;
    }
    // rec = (struct flow_info *)map.lookup(&key);

    // If entry doesn't exist yet, initialize it
    if (!rec) {
        // Retrieve the last seen timestamp for IAT calculation
        last_first_seen_value = (u64 *)last_first_seen.lookup(&lfs_key);
        if (!last_first_seen_value)
            return -1;

        // Calculate inter-arrival time (IAT)
        if (*last_first_seen_value == 0)
            info.iat = 0;

        else
            info.iat = info.first_seen - *last_first_seen_value;

        // Update last_first_seen map with current timestamp
        last_first_seen.update(&lfs_key, &(info.first_seen));


        // Insert new entry into the appropriate map
        switch (map_flag) {
            case 1: hash_func_1.update(&key, &info); break;
            case 2: hash_func_2.update(&key, &info); break;
            case 3: hash_func_3.update(&key, &info); break;
            case 4: hash_func_4.update(&key, &info); break;
            case 5: hash_func_5.update(&key, &info); break;
            default: return -1;
        }

        // Copy initial values to aggregated output
        aggregated->packets = info.packets;
        aggregated->bytes = info.bytes;
        aggregated->first_seen = info.first_seen;
        aggregated->last_seen = info.last_seen;
        aggregated->duration = info.duration;
        aggregated->pps = info.pps;
        aggregated->bps = info.bps;
        aggregated->iat = info.iat;

        return 0;
    }

    // Entry exists - update it with new information
    // Acquire lock
    bpf_spin_lock(&rec->lock);

    // Update packet and byte counters, if this packet is newer than what we've seen
    rec->packets += info.packets;
    rec->bytes += info.bytes;

    // Update last_seen and calculate duration
    if (rec->last_seen < info.last_seen) {

        rec->last_seen = info.last_seen;
        rec->duration = rec->last_seen - rec->first_seen;

        // Calculate rates if we have valid duration
        if (rec->duration != 0) {
            // Packets per second with 1 decimal point accuracy (2.3pps -> 23 pps)
            rec->pps = (rec->packets * 10000000000) / rec->duration;
            // Bytes per second with no decimal point accuracy
            rec->bps = (rec->bytes * 1000000000) / rec->duration;
        }
    }

    bpf_spin_unlock(&rec->lock);  // Release lock

    // Update aggregated values using the CMS minimum values
    // The CMS approach takes the minimum value across all hash functions
    // for each metric to get the most accurate estimate
    if (rec->packets < aggregated->packets)
        aggregated->packets = rec->packets;

    if (rec->bytes < aggregated->bytes)
        aggregated->bytes = rec->bytes;

    if (rec->first_seen > aggregated->first_seen)
        aggregated->first_seen = rec->first_seen;

    if (rec->last_seen < aggregated->last_seen)
        aggregated->last_seen = rec->last_seen;

    if (rec->duration < aggregated->duration)
        aggregated->duration = rec->duration;

    if (rec->pps < aggregated->pps)
        aggregated->pps = rec->pps;

    if (rec->bps < aggregated->bps)
        aggregated->bps = rec->bps;

    if (rec->iat > aggregated->iat)
        aggregated->iat = rec->iat;

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
 * 3. Updates the Count-Min Sketch with flow statistics
 * 4. Decides whether to pass or drop the packet
 * 
 * ctx: XDP context containing packet data
 * return XDP action (XDP_PASS, XDP_DROP, XDP_ABORTED)
 */

int packet_handler(struct xdp_md *ctx)
{
    u32 zero = 0;
    struct hash_info empty = {0}; // Initialize with zeros
    struct hash_info *hash_inf = hash_info_map.lookup_or_try_init(&zero, &empty);
    if (!hash_inf)
        return XDP_ABORTED;

    // Initialize hash function seeds
    hash_inf->map_seeds[0] = 12;
    hash_inf->map_seeds[1] = 37;
    hash_inf->map_seeds[2] = 42;
    hash_inf->map_seeds[3] = 68;
    hash_inf->map_seeds[4] = 91;

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
        update_passed_packets();
        printk("EtherType: 0x%x\n", ntohs(eth->h_proto));
        return XDP_PASS;
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

    // Check if this flow has already been classified
    u32 state_key = jhash(&key, sizeof(key), STATE_HASH_SEED);
    enum states *state_ptr = sig_map.lookup(&state_key);

    // Take immediate action based on existing classification
    enum states state = Waiting;
    if (state_ptr) {
        state = *state_ptr;
        if (state == Malicious) {
            return XDP_DROP; // Drop malicious flows
        } else if (state == Benign) {
            update_passed_packets();
            return XDP_PASS; // Pass benign flows
        }
    }

    // Set initial state if not already classified
    sig_map.update(&state_key, &state);

    // Initialize flow info structure with packet details
    info.src_ip = key.src_ip;
    info.dst_ip = key.dst_ip;
    info.src_port = key.src_port;
    info.dst_port = key.dst_port;
    info.protocol = key.protocol;
    info.packets = 1;
    info.bytes = size;
    info.first_seen = bpf_ktime_get_ns();
    info.last_seen = info.first_seen;
    info.duration = 0;
    info.pps = 0;
    info.bps = 0;
    info.iat = 0;

    // Compute key hash values for each map
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++)
    {
        hash_inf->hashed_keys[i] = jhash(&key, sizeof(key), hash_inf->map_seeds[i]);
    }

    // Initialize aggregated flow info structure
    // Set to maximum values so that minimum operations will work correctly
    struct flow_info agg = {0};
    agg.src_ip = key.src_ip;
    agg.dst_ip = key.dst_ip;
    agg.src_port = key.src_port;
    agg.dst_port = key.dst_port;
    agg.protocol = key.protocol;
    agg.packets = UINT32_MAX;
    agg.bytes = UINT64_MAX;
    agg.first_seen = 0;
    agg.last_seen = UINT64_MAX;
    agg.duration = UINT64_MAX;
    agg.pps = UINT32_MAX;
    agg.bps = UINT32_MAX;
    agg.iat = 0;

    // Update each CMS hash map
    update_map(1, hash_inf->hashed_keys[0], info, 0, &agg);
    update_map(2, hash_inf->hashed_keys[1], info, 1, &agg);
    update_map(3, hash_inf->hashed_keys[2], info, 2, &agg);
    update_map(4, hash_inf->hashed_keys[3], info, 3, &agg);
    update_map(5, hash_inf->hashed_keys[4], info, 4, &agg);

    // Add aggregated flow info to aggr map
    u32 aggr_key = jhash(&key, sizeof(key), AGGR_HASH_SEED);
    aggr.update(&aggr_key, &agg);

    bpf_trace_printk("flow packets: %u, PACKETS_SAMPLE: %d\n", agg.packets, PACKETS_SAMPLE);

    // Check if we've collected enough samples to make a decision (flow timeout?)
    if (agg.packets >= PACKETS_SAMPLE) // || ((current_time - agg.last_seen) > FLOW_TIMEOUT))
    {
        // Change the state in sig_map to Ready
        state = Ready;
        sig_map.update(&state_key, &state);

    }

    // Increment the counter value for passed packets
    update_passed_packets();
    return XDP_PASS;
}
