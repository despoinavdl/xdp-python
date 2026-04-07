#include "flow_tracker.h"

#include <climits>

bool FlowTracker::update(const flow_key& key, const flow_info& info) {
    passed_packets_++;

    // New flow: insert and return
    if (flow_map_.count(key) == 0) {
        flow_map_.emplace(key, info);
        return true;
    }

    // Existing flow: update statistics
    auto& flow = flow_map_[key];

    uint64_t last_seen_old = flow.last_seen;

    if (last_seen_old < info.last_seen) {
        flow.last_seen = info.last_seen;
        flow.duration = flow.last_seen - flow.first_seen;

        // IAT calculation (ns → microseconds to match dataset units)
        if (flow.packets > 0) {
            uint64_t iat = (flow.last_seen - last_seen_old) / 1000;
            flow.iat_total += iat;
            flow.iat_mean = flow.iat_total / flow.packets;
            if (flow.iat_min > iat) flow.iat_min = iat;
            if (flow.iat_max < iat) flow.iat_max = iat;
        }
    }

    flow.packets += info.packets;
    flow.bytes += info.bytes;

    // Calculate rates
    if (flow.duration >= 1000000000) { // duration >= 1 second
        // Scaled by 100,000 to match threshold map values
        flow.pps = (flow.packets * 1000000000ULL * 100000) / flow.duration;
        flow.bps = (flow.bytes * 1000000000ULL * 100000) / flow.duration;
    } else {
        flow.pps = flow.packets * 100000;
        flow.bps = flow.bytes;
    }

    return false;
}

flow_info* FlowTracker::get(const flow_key& key) {
    auto it = flow_map_.find(key);
    return (it != flow_map_.end()) ? &it->second : nullptr;
}

const flow_info* FlowTracker::get(const flow_key& key) const {
    auto it = flow_map_.find(key);
    return (it != flow_map_.end()) ? &it->second : nullptr;
}

states FlowTracker::get_state(const flow_key& key) const {
    auto it = sig_map_.find(key);
    return (it != sig_map_.end()) ? it->second : Waiting;
}

void FlowTracker::set_state(const flow_key& key, states s) {
    sig_map_[key] = s;
}
