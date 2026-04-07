#ifndef DECISION_TREE_H
#define DECISION_TREE_H

#include <cstdint>
#include <string>
#include <vector>

#include "flow_types.h"

struct DecisionTree {
    std::vector<int64_t> children_left;
    std::vector<int64_t> children_right;
    std::vector<int64_t> features;
    std::vector<int64_t> thresholds;
    std::vector<int64_t> values;

    // Load all tree arrays from a directory containing
    // children_left, children_right, features, thresholds, values files.
    bool load(const std::string& directory);

    // Traverse the tree using flow features and return classification:
    // 0 = benign, 1 = malicious.
    int traverse(const flow_info& flow) const;
};

// Classify a flow using majority voting across multiple trees.
// Returns 1 for malicious, 0 for benign.
int classify_flow(const std::vector<DecisionTree>& trees, const flow_info& flow);

#endif
