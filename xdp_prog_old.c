// COUNT MIN SKETCH WITH FLOW FEATURES

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <linux/jhash.h>

// #include "common_kern_user.h" /* defines: structs flow_info, flow_key, datarec; */
#include "flow_headers.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

#define UINT64_MAX (~0ULL) // Maximum value for 64-bit unsigned integer
#define UINT32_MAX (~0U)   // Maximum value for 32-bit unsigned integer

// Hash map definition for count min sketch
struct hash_func
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct flow_info);
    __uint(max_entries, XDP_MAX_MAP_ENTRIES);
};

struct hash_func hash_func_1 SEC(".maps");
struct hash_func hash_func_2 SEC(".maps");
struct hash_func hash_func_3 SEC(".maps");
struct hash_func hash_func_4 SEC(".maps");
struct hash_func hash_func_5 SEC(".maps");

// Debug map to print aggregated results from cms to user space
struct hash_func dbg SEC(".maps");

// Array map to keep the first_seen attribute of the most recent flow in order to calculate flow IAT (time between two flows)
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 5);
} last_first_seen SEC(".maps");

// Define the passed packet counter map
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, 1);
} passed_packets SEC(".maps");

// Define the sig_map
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, enum states);
    __uint(max_entries, XDP_MAX_MAP_ENTRIES);
} sig_map SEC(".maps");

// Function to update the last_first_seen map, used in update_map
static __always_inline int update_last_first_seen(void *map, __u64 first_seen, __u32 key)
{
    int ret = bpf_map_update_elem(map, &key, &first_seen, BPF_ANY);
    if (ret < 0)
        return ret; // Return error code if update fails

    return 0;
}

// Function to update the hash maps used for CMS key here is hashed
static __always_inline int update_map(void *map, __u32 key, struct flow_info info, __u32 lfs_key, struct flow_info *aggregated)
{
    struct flow_info *rec;
    int ret;
    __u64 *last_first_seen_value;

    /* Lookup in kernel BPF-side return pointer to actual data record */
    rec = (struct flow_info *)bpf_map_lookup_elem(map, &key);

    // If the entry is not found, initialize it
    if (!rec)
    {
        last_first_seen_value = (__u64 *)bpf_map_lookup_elem(&last_first_seen, &lfs_key);

        if (!last_first_seen_value)
            return -1;

        else if (*last_first_seen_value == 0)
            info.iat = 0;

        else
            info.iat = info.first_seen - *last_first_seen_value;

        // Update last_first_seen map
        ret = update_last_first_seen(&last_first_seen, info.first_seen, lfs_key);
        if (ret < 0)
            return ret;

        ret = bpf_map_update_elem(map, &key, &info, BPF_ANY);
        if (ret < 0)
            return ret;

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

static __always_inline int update_passed_packets(void *map)
{
    __u32 zero = 0;
    struct datarec *rec = {0};
    struct datarec new_rec = {.packets = 1};
    int ret;

    rec = (struct datarec *)bpf_map_lookup_elem(map, &zero);
    if (!rec)
    {
        // First entry - initialize the counter
        ret = bpf_map_update_elem(map, &zero, &new_rec, BPF_ANY);
        if (ret < 0)
            return ret;

        return 0;
    }

    lock_xadd(&rec->packets, 1);
    return 0;
}

static __always_inline int delete_from_map(void *map, struct flow_key key, __u32 seed)
{
    __u32 hashed_key = jhash(&key, sizeof(key), seed);
    int ret;

    ret = bpf_map_delete_elem(map, &hashed_key);
    if (ret < 0)
        return ret;

    return 0;
}

SEC("xdp")
int packet_handler(struct xdp_md *ctx)
{
    const __u32 map_seeds[] = {12, 37, 42, 68, 91};

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u64 size = data_end - data;
    struct flow_key key = {0};
    struct flow_info info = {0};
    int ret;

    if ((void *)eth + sizeof(*eth) > data_end)
    {
        // Increment the counter value for passed packets
        ret = update_passed_packets(&passed_packets);
        if (ret < 0)
            return XDP_ABORTED;
        return XDP_PASS;
    }

    if (ntohs(eth->h_proto) != ETH_P_IP)
    {
        return XDP_DROP;
        ret = update_passed_packets(&passed_packets);
        if (ret < 0)
            return XDP_ABORTED;
        bpf_printk("EtherType: 0x%x\n", ntohs(eth->h_proto));
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
    {
        ret = update_passed_packets(&passed_packets);
        if (ret < 0)
            return XDP_ABORTED;
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
            ret = update_passed_packets(&passed_packets);
            if (ret < 0)
                return XDP_ABORTED;
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
            ret = update_passed_packets(&passed_packets);
            if (ret < 0)
                return XDP_ABORTED;
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
    __u32 state_key = jhash(&key, sizeof(key), STATE_HASH_SEED);
    enum states *state_ptr;
    enum states state;
    state_ptr = bpf_map_lookup_elem(&sig_map, &state_key);
    if (!state_ptr)
    {
        // If the entry doesn't exist, create it
        state = Waiting;
    }
    else
    {
        state = *state_ptr;
        switch (state)
        {
        case Malicious:
            bpf_printk("Dropped a 'Malicious' packet");
            return XDP_DROP;
        case Benign:
            ret = update_passed_packets(&passed_packets);
            if (ret < 0)
                return XDP_ABORTED;
            return XDP_PASS;
        default:
            break;
        }
    }
    ret = bpf_map_update_elem(&sig_map, &state_key, &state, BPF_ANY);
    if (ret < 0)
    {
        bpf_printk("Couldn't create the sig_map entry\n");
        return ret;
    }

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

    __u32 hashed_keys[NUM_MAPS];
    for (int i = 0; i < NUM_MAPS; i++)
    {
        hashed_keys[i] = jhash(&key, sizeof(key), map_seeds[i]);
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
    ret = update_map(&hash_func_1, hashed_keys[0], info, 0, &agg);
    if (ret < 0)
        return XDP_ABORTED;

    // Update cms hash_func2 map
    ret = update_map(&hash_func_2, hashed_keys[1], info, 1, &agg);
    if (ret < 0)
    {
        delete_from_map(&hash_func_1, key, map_seeds[0]);
        return XDP_ABORTED;
    }

    // Update cms hash_func3 map
    ret = update_map(&hash_func_3, hashed_keys[2], info, 2, &agg);
    if (ret < 0)
    {
        delete_from_map(&hash_func_1, key, map_seeds[0]);
        delete_from_map(&hash_func_2, key, map_seeds[1]);
        return XDP_ABORTED;
    }

    // Update cms hash_func4 map
    ret = update_map(&hash_func_4, hashed_keys[3], info, 3, &agg);
    if (ret < 0)
    {
        delete_from_map(&hash_func_1, key, map_seeds[0]);
        delete_from_map(&hash_func_2, key, map_seeds[1]);
        delete_from_map(&hash_func_3, key, map_seeds[2]);
        return XDP_ABORTED;
    }

    // Update cms hash_func5 map
    ret = update_map(&hash_func_5, hashed_keys[4], info, 4, &agg);
    if (ret < 0)
    {
        delete_from_map(&hash_func_1, key, map_seeds[0]);
        delete_from_map(&hash_func_2, key, map_seeds[1]);
        delete_from_map(&hash_func_3, key, map_seeds[2]);
        delete_from_map(&hash_func_4, key, map_seeds[3]);
        return XDP_ABORTED;
    }

    // Add agg to dbg map
    __u32 dbg_key = jhash(&key, sizeof(key), DBG_HASH_SEED);
    ret = bpf_map_update_elem(&dbg, &dbg_key, &agg, BPF_ANY);
    if (ret < 0)
    {
        // bpf_printk("Could not update debug map\n");
        return XDP_ABORTED;
    }

    // __u64 current_time = bpf_ktime_get_ns();
    // __u64 time_since_last_seen = current_time - agg.last_seen;
    // bpf_printk("Current time - Last Seen = %llu\n", time_since_last_seen);
    // Check number of packets and flow timeout
    if (agg.packets > PACKETS_SAMPLE) // || ((current_time - agg.last_seen) > FLOW_TIMEOUT))
    {
        // Change the state in sig_map to Ready
        state = Ready;
        ret = bpf_map_update_elem(&sig_map, &state_key, &state, BPF_ANY);
        if (ret < 0)
        {
            bpf_printk("Couldn't update the sig_map entry\n");
            return ret;
        }

        // Delete from maps
        delete_from_map(&hash_func_1, key, map_seeds[0]);
        delete_from_map(&hash_func_2, key, map_seeds[1]);
        delete_from_map(&hash_func_3, key, map_seeds[2]);
        delete_from_map(&hash_func_4, key, map_seeds[3]);
        delete_from_map(&hash_func_5, key, map_seeds[4]);
        delete_from_map(&dbg, key, DBG_HASH_SEED);
    }

    // Increment the counter value for passed packets
    ret = update_passed_packets(&passed_packets);
    if (ret < 0)
    {
        return XDP_ABORTED;
    }
    return XDP_PASS;
}
