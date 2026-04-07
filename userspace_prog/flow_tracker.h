#ifndef FLOW_TRACKER_H
#define FLOW_TRACKER_H

#include <unordered_map>

#include "flow_types.h"

class FlowTracker {
public:
    // Update flow statistics. Returns true if this was a new flow.
    bool update(const flow_key& key, const flow_info& info);

    flow_info* get(const flow_key& key);
    const flow_info* get(const flow_key& key) const;

    states get_state(const flow_key& key) const;
    void set_state(const flow_key& key, states s);

    uint64_t passed_packets() const { return passed_packets_; }

private:
    std::unordered_map<flow_key, flow_info> flow_map_;
    std::unordered_map<flow_key, states> sig_map_;
    uint64_t passed_packets_ = 0;
};

#endif
