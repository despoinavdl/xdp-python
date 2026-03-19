#ifndef FLOW_TYPES_H
#define FLOW_TYPES_H

#include <cstdint>
#include <functional>

#define PACKETS_SAMPLE 10
#define MAX_DEPTH 10

#ifndef XDP_MAX_MAP_ENTRIES
#define XDP_MAX_MAP_ENTRIES 1024000
#endif

struct datarec
{
    uint64_t packets;
};

struct flow_key
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t protocol;

    bool operator==(const flow_key& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

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
    uint64_t packets;
    uint64_t bytes;
    uint64_t first_seen;
    uint64_t last_seen;
    uint64_t duration;
    uint64_t pps;
    uint32_t bps;
    uint64_t iat_mean;
    uint64_t iat_total;
    uint64_t iat_min;
    uint64_t iat_max;
};

enum states
{
    Waiting = 0,
    Ready = 1,
    Malicious = 2,
    Benign = 3
};

#endif
