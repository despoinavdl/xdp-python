#define PACKETS_SAMPLE 10
#define MAX_DEPTH 10
#define TREE_1_NODES 257
#define TREE_2_NODES 259
#define TREE_3_NODES 287

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
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
    __u64 duration;
    __u64 pps;
    __u64 bps;
    __u64 iat_mean;
    __u64 iat_total;
    __u64 iat_min;
    __u64 iat_max;
    struct bpf_spin_lock lock;
};

enum states
{
    Waiting = 0,
    Ready = 1,
    Malicious = 2,
    Benign = 3
};
