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
BPF_HASH(passed_packets, u32, struct datarec, 1);

// Map for tracking flow states (Waiting, Ready, Malicious, Benign)
BPF_TABLE("lru_hash", struct flow_key, enum states, sig_map, 400000);

/* Updates the packet counter for packets that pass through XDP */
static __always_inline void update_passed_packets(void)
{
    u32 zero = 0;
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

/* Updates a Count-Min Sketch hash map with flow information
 * map_flag: Index of the hash map to update (1-5)
 * key: Hashed flow key
 * info: Flow information to store/update
 * aggregated: Pointer to store aggregated min values
 * return 0 on success, -1 on error
 */
static __always_inline int update_map(struct flow_key key, struct flow_info info)
{
    struct flow_info *rec;
    int ret;
    u32 packets_old;
    u64 last_seen_old;
    u64 iat_mean_old;

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

    // Update packet and byte counters, if this packet is newer than what we've seen
    rec->packets += info.packets;
    rec->bytes += info.bytes;

    // Update last_seen and calculate duration
    if (rec->last_seen < info.last_seen) {

        rec->last_seen = info.last_seen;
        rec->duration = rec->last_seen - rec->first_seen;

        // Calculate rates if we have valid duration
        if (rec->duration >= 1000000000) { //if duration >= 1 second
            // Packets per second with 1 decimal point accuracy (2.3pps -> 23 pps)
            rec->pps = (rec->packets * 10000000000) / rec->duration;
            // Bytes per second with no decimal point accuracy
            rec->bps = (rec->bytes * 1000000000) / rec->duration;
        }
        else {
            rec->pps = rec->packets;
            rec->bps = rec->bytes;
        }
    }

    if (rec->packets > 0) {
        rec->iat_mean = ((iat_mean_old * packets_old) + rec->last_seen - last_seen_old) / rec->packets;
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

    // Update flow_map
    update_map(key, info);

    // bpf_trace_printk("flow packets: %u, PACKETS_SAMPLE: %d\n", agg.packets, PACKETS_SAMPLE);

    // Lookup can be avoided if update_map returns packet count
    struct flow_info *updated_flow = flow_map.lookup(&key);
    
    // Check if we've collected enough samples to make a decision (flow timeout?)
    if (updated_flow && updated_flow->packets >= PACKETS_SAMPLE && state == Waiting) // || ((current_time - agg.last_seen) > FLOW_TIMEOUT))
    {
        // Change the state in sig_map to Ready
        state = Ready;
        sig_map.update(&key, &state);
    }

    // Increment the counter value for passed packets
    update_passed_packets();
    return XDP_PASS;
}
