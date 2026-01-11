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

#include <cstdlib>

/* This is the data record stored in the map */
struct datarec
{
    uint64_t packets;
};

struct flow_key
{
    // __be32 src_ip;
    // __be32 dst_ip;
    // __be16 src_port;
    // __be16 dst_port;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t protocol;

    // Add equality operator for unordered_map
    bool operator==(const flow_key& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

// Hash function for flow_key
namespace std {
    template<>
    struct hash<flow_key> {
        size_t operator()(const flow_key& k) const {
            return ((hash<uint32_t>()(k.src_ip) ^ 
                    (hash<uint32_t>()(k.dst_ip) << 1)) >> 1) ^
                    (hash<uint16_t>()(k.src_port) << 1) ^
                    (hash<uint16_t>()(k.dst_port) >> 1) ^
                    (hash<uint8_t>()(k.protocol) << 1);
        }
    };
}

struct flow_info
{
    volatile uint64_t packets;
    volatile uint64_t bytes;
    uint64_t first_seen;
    volatile uint64_t last_seen;
    volatile uint64_t duration;
    volatile uint64_t pps;
    volatile uint32_t bps;
    volatile uint64_t iat_mean; // mean inter arrival time between packets of a flow
    volatile uint64_t iat_total;
    volatile uint64_t iat_min;
    volatile uint64_t iat_max;
};

enum states
{
    Waiting = 0,
    Ready = 1,
    Malicious = 2,
    Benign = 3
};

