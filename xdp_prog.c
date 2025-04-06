// COUNT MIN SKETCH WITH FLOW FEATURES

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/jhash.h>

// #include "common_kern_user.h" /* defines: structs flow_info, flow_key, datarec; */
#include "flow_headers.h"

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

#define UINT64_MAX (~0ULL) // Maximum value for 64-bit unsigned integer
#define UINT32_MAX (~0U)   // Maximum value for 32-bit unsigned integer

// Hash maps for count min sketch
BPF_HASH(hash_func_1, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);
BPF_HASH(hash_func_2, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);
BPF_HASH(hash_func_3, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);
BPF_HASH(hash_func_4, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);
BPF_HASH(hash_func_5, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);

// Debug map to print aggregated results from cms to user space
BPF_HASH(aggr, u32, struct flow_info, XDP_MAX_MAP_ENTRIES);

// Array map to keep the first_seen attribute of the most recent flow in order to calculate flow IAT (time between two flows)
BPF_ARRAY(last_first_seen, u64, 5);

// Define the passed packet counter map
BPF_HASH(passed_packets, u32, struct datarec, 1);

// Define the sig_map
BPF_HASH(sig_map, u32, enum states, XDP_MAX_MAP_ENTRIES);

// Define a struct to hold the arrays that were on the stack
struct stack_arrays {
    u32 hashed_keys[NUM_MAPS];
    u32 map_seeds[NUM_MAPS];
};

// Create a BPF per-CPU array map to store these arrays
BPF_PERCPU_ARRAY(stack_arrays_map, struct stack_arrays, 1);

// // Function to update the last_first_seen map, used in update_map
// static __always_inline void update_last_first_seen(void *map, u64 first_seen, u32 key)
// {
//     map.update(&key, &first_seen);
// }


// 1: hash_func_1
// 2: hash_func_2
// 3: hash_func_3
// 4: hash_func_4
// 5: hash_func_5
// Function to update the hash maps used for CMS key here is hashed
static __always_inline int update_map(u8 map_flag, u32 key, struct flow_info info, u32 lfs_key, struct flow_info *aggregated)
{
    struct flow_info *rec;
    int ret;
    u64 *last_first_seen_value;

    /* Lookup in kernel BPF-side return pointer to actual data record */
    switch (map_flag) {
        case 1:
            rec = (struct flow_info *)hash_func_1.lookup(&key);
            break;
        case 2:
            rec = (struct flow_info *)hash_func_2.lookup(&key);
            break;
        case 3:
            rec = (struct flow_info *)hash_func_3.lookup(&key);
            break;
        case 4:
            rec = (struct flow_info *)hash_func_4.lookup(&key);
            break;
        case 5:
            rec = (struct flow_info *)hash_func_5.lookup(&key);
            break;
        default:
            return -1;
    }
    // rec = (struct flow_info *)map.lookup(&key);

    // If the entry is not found, initialize it
    if (!rec)
    {
        last_first_seen_value = (u64 *)last_first_seen.lookup(&lfs_key);

        if (!last_first_seen_value)
            return -1;

        else if (*last_first_seen_value == 0)
            info.iat = 0;

        else
            info.iat = info.first_seen - *last_first_seen_value;

        // Update last_first_seen map
        // update_last_first_seen(&last_first_seen, info.first_seen, lfs_key);
        last_first_seen.update(&lfs_key, &(info.first_seen));


        // Update the map
        switch (map_flag) {
            case 1:
                hash_func_1.update(&key, &info);
                break;
            case 2:
                hash_func_2.update(&key, &info);
                break;
            case 3:
                hash_func_3.update(&key, &info);
                break;
            case 4:
                hash_func_4.update(&key, &info);
                break;
            case 5:
                hash_func_5.update(&key, &info);
                break;
            default:
                return -1;
        }
        // map.update(&key, &info);

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

    // Acquire lock
    bpf_spin_lock(&rec->lock);

    // Update packets, bytes
    rec->packets += info.packets;
    rec->bytes += info.bytes;

    // Update last_seen and calculate duration
    if (rec->last_seen < info.last_seen)
    {
        rec->last_seen = info.last_seen;
        rec->duration = rec->last_seen - rec->first_seen;
        if (rec->duration != 0)
        {
            // Packets per second with 1 decimal point accuracy (2.3pps -> 23 pps)
            rec->pps = (rec->packets * 10000000000) / rec->duration;
            // Bytes per second with no decimal point acccuracy
            rec->bps = (rec->bytes * 1000000000) / rec->duration;
        }
    }

    // Release lock
    bpf_spin_unlock(&rec->lock);

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

// 0: hash_func_1
// 1: hash_func_2
// 2: hash_func_3
// 3: hash_func_4
// 4: hash_func_5
// 5: aggr
static __always_inline int delete_from_map(u8 map_flag, struct flow_key key, u32 seed)
{
    u32 hashed_key = jhash(&key, sizeof(key), seed);
    switch (map_flag) {
        case 0:
            aggr.delete(&hashed_key);
            break;
        case 1:
            hash_func_1.delete(&hashed_key);
            break;
        case 2:
            hash_func_2.delete(&hashed_key);
            break;
        case 3:
            hash_func_3.delete(&hashed_key);
            break;
        case 4:
            hash_func_4.delete(&hashed_key);
            break;
        case 5:
            hash_func_5.delete(&hashed_key);
            break;
        default:
            return -1;
    }
    // map.delete(&hashed_key);
    return 0;
}

int packet_handler(struct xdp_md *ctx)
{
    u32 zero = 0;
    struct stack_arrays empty = {0}; // Initialize with zeros
    struct stack_arrays *arrays = stack_arrays_map.lookup_or_try_init(&zero, &empty);
    if (!arrays)
        return XDP_ABORTED;

    // Initialize the map_seeds in the array
    arrays->map_seeds[0] = 12;
    arrays->map_seeds[1] = 37;
    arrays->map_seeds[2] = 42;
    arrays->map_seeds[3] = 68;
    arrays->map_seeds[4] = 91;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    u64 size = data_end - data;
    struct flow_key key = {0};
    struct flow_info info = {0};
    int ret;

    if ((void *)eth + sizeof(*eth) > data_end)
    {
        // Increment the counter value for passed packets
        update_passed_packets();
        return XDP_PASS;
    }

    if (ntohs(eth->h_proto) != ETH_P_IP)
    {
        return XDP_DROP;
        update_passed_packets();
        printk("EtherType: 0x%x\n", ntohs(eth->h_proto));
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
    {
        update_passed_packets();
        return XDP_PASS;
    }

    key.dst_ip = ip->daddr;
    key.src_ip = ip->saddr;
    key.protocol = ip->protocol;

    // Check if the protocol is TCP or UDP to extract ports
    if (key.protocol == IPPROTO_TCP) // TCP Protocol
    {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end)
        {
            update_passed_packets();
            return XDP_PASS;
        }

        key.src_port = tcp->source; // Extract TCP source port
        key.dst_port = tcp->dest;   // Extract TCP destination port
    }
    else if (key.protocol == IPPROTO_UDP) // UDP Protocol
    {
        // return XDP_DROP;
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end)
        {
            update_passed_packets();
            return XDP_PASS;
        }

        key.src_port = udp->source; // Extract UDP source port
        key.dst_port = udp->dest;   // Extract UDP destination port
    }
    else
    {
        // If it's not TCP or UDP, we won't have ports
        key.src_port = 0;
        key.dst_port = 0;
    }

    // Check if the signature already exists in the sig_map and the decision is already taken
    u32 state_key = jhash(&key, sizeof(key), STATE_HASH_SEED);
    enum states *state_ptr = sig_map.lookup(&state_key);

    enum states state = Waiting;
    if (state_ptr) {
        state = *state_ptr;
        if (state == Malicious) {
            return XDP_DROP;
        } else if (state == Benign) {
            update_passed_packets();
            return XDP_PASS;
        }
    }

    sig_map.update(&state_key, &state);

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

    for (int i = 0; i < NUM_MAPS; i++)
    {
        arrays->hashed_keys[i] = jhash(&key, sizeof(key), arrays->map_seeds[i]);
    }

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

    // Update cms hash_func1 map
    update_map(1, arrays->hashed_keys[0], info, 0, &agg);

    // Update cms hash_func2 map
    update_map(2, arrays->hashed_keys[1], info, 1, &agg);

    // Update cms hash_func3 map
    update_map(3, arrays->hashed_keys[2], info, 2, &agg);

    // Update cms hash_func4 map
    update_map(4, arrays->hashed_keys[3], info, 3, &agg);

    // Update cms hash_func5 map
    update_map(5, arrays->hashed_keys[4], info, 4, &agg);

    // Add agg to aggr map
    u32 aggr_key = jhash(&key, sizeof(key), AGGR_HASH_SEED);
    aggr.update(&aggr_key, &agg);

    // u64 current_time = bpf_ktime_get_ns();
    // u64 time_since_last_seen = current_time - agg.last_seen;
    // bpf_printk("Current time - Last Seen = %llu\n", time_since_last_seen);
    // Check number of packets and flow timeout

    bpf_trace_printk("flow packets: %u, PACKETS_SAMPLE: %d\n", agg.packets, PACKETS_SAMPLE);
    if (agg.packets >= PACKETS_SAMPLE) // || ((current_time - agg.last_seen) > FLOW_TIMEOUT))
    {
        // Change the state in sig_map to Ready
        state = Ready;
        sig_map.update(&state_key, &state);

        // Delete from debug map 
        delete_from_map(0, key, AGGR_HASH_SEED);

        // Delete from hash_func maps
        delete_from_map(1, key, arrays->map_seeds[0]);
        delete_from_map(2, key, arrays->map_seeds[1]);
        delete_from_map(3, key, arrays->map_seeds[2]);
        delete_from_map(4, key, arrays->map_seeds[3]);
        delete_from_map(5, key, arrays->map_seeds[4]);
    }

    // Increment the counter value for passed packets
    update_passed_packets();
    return XDP_PASS;
}
