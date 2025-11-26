#define PACKETS_SAMPLE 10

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef XDP_MAX_MAP_ENTRIES
#define XDP_MAX_MAP_ENTRIES 1024000
#endif

/* This is the data record stored in the map */
struct datarec
{
    __u64 packets;
};

struct flow_key
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u32 protocol;
};

struct flow_info
{
    volatile __u32 packets;
    volatile __u64 bytes;
    __u64 first_seen;
    volatile __u64 last_seen;
    volatile __u64 duration;
    volatile __u32 pps;
    volatile __u32 bps;
    volatile __u64 iat_mean; // mean inter arrival time between packets of a flow
    volatile __u64 iat_total;
    volatile __u64 iat_min;
    volatile __u64 iat_max;
    struct bpf_spin_lock lock;
};

enum states
{
    Waiting = 0,
    Ready = 1,
    Malicious = 2,
    Benign = 3
};
