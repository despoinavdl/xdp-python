/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#define NUM_MAPS 5
// #define FLOW_TIMEOUT 3000000000 // 3 seconds timeout in nanoseconds
#define FLOW_TIMEOUT 5000000000 // 5 seconds timeout in nanoseconds
// #define FLOW_TIMEOUT 100000000000 // 100 seconds timeout in nanoseconds for testing
#define PACKETS_SAMPLE 12
#define DBG_HASH_SEED 88
#define STATE_HASH_SEED 66

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
    __u8 protocol;
};

struct flow_info
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    volatile __u32 packets;
    volatile __u64 bytes;
    __u64 first_seen;
    volatile __u64 last_seen;
    volatile __u64 duration;
    volatile __u32 pps;
    volatile __u32 bps;
    volatile __u64 iat; // inter arrival time
    struct bpf_spin_lock lock;
};

enum states
{
    Waiting = 0,
    Ready = 1,
    Malicious = 2,
    Benign = 3
};

struct model_input
{
    __u8 protocol;
    volatile __u64 duration;
    volatile __u32 pps;
    volatile __u32 bps;
    volatile __u64 iat; // inter arrival time
};

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#ifndef XDP_MAX_MAP_ENTRIES
#define XDP_MAX_MAP_ENTRIES 1024
#endif

#endif /* __COMMON_KERN_USER_H */
