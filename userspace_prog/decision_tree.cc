#include "decision_tree.h"

#include <fstream>
#include <iostream>
#include <string>

static bool load_array(const std::string& filename, std::vector<int64_t>& target) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        try {
            target.push_back(std::stoll(line));
        } catch (const std::exception& e) {
            std::cerr << "Warning: Could not parse line: " << line
                      << " in " << filename << std::endl;
        }
    }
    return true;
}

bool DecisionTree::load(const std::string& directory) {
    if (!load_array(directory + "/children_left", children_left)) return false;
    if (!load_array(directory + "/children_right", children_right)) return false;
    if (!load_array(directory + "/features", features)) return false;
    if (!load_array(directory + "/thresholds", thresholds)) return false;
    if (!load_array(directory + "/values", values)) return false;
    return true;
}

int DecisionTree::traverse(const flow_info& flow) const {
    int current_node = 0;

    for (int i = 0; i < MAX_DEPTH; i++) {
        int64_t left_child = children_left[current_node];
        int64_t right_child = children_right[current_node];
        int64_t feature_idx = features[current_node];
        int64_t threshold = thresholds[current_node];

        // Leaf node: both children are negative
        if (left_child < 0)
            break;

        // Select flow feature by index:
        // 0: Total Length of Fwd Packets  1: Total Fwd Packets
        // 2: Fwd Packets/s               3: Fwd IAT Mean
        // 4: Fwd IAT Min                 5: Fwd IAT Max
        // 6: Fwd IAT Total
        uint64_t flow_feature = 0;
        switch (feature_idx) {
            case 0: flow_feature = flow.bytes;     break;
            case 1: flow_feature = flow.packets;   break;
            case 2: flow_feature = flow.pps;       break;
            case 3: flow_feature = flow.iat_mean;  break;
            case 4: flow_feature = flow.iat_min;   break;
            case 5: flow_feature = flow.iat_max;   break;
            case 6: flow_feature = flow.iat_total; break;
        }

        if (flow_feature <= static_cast<uint64_t>(threshold))
            current_node = left_child;
        else
            current_node = right_child;
    }

    // Return classification at leaf: 0 = benign, 1 = malicious
    return static_cast<int>(values[current_node]);
}

int classify_flow(const std::vector<DecisionTree>& trees, const flow_info& flow) {
    int malicious_votes = 0;
    for (const auto& tree : trees) {
        malicious_votes += tree.traverse(flow);
    }
    // Majority voting
    return (malicious_votes > static_cast<int>(trees.size()) / 2) ? 1 : 0;
}
