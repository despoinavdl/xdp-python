#!/usr/bin/env python3
"""
BCC Python Program for Flow Monitoring

This program loads and manages an eBPF/XDP program for network flow monitoring. 
It periodically checks flows and collects classification statistics from the dataplane.
"""
from bcc import BPF
import argparse
import socket
import time
import ctypes
import signal
import sys

# Constants
XDP_MAX_MAP_ENTRIES = 1024000
FLOW_TIMEOUT = 30_000_000_000  # 30 seconds timeout in nanoseconds
MAX_FLOWS_THRESHOLD = int(XDP_MAX_MAP_ENTRIES * 0.8)  # Clean when 80% full
CLEANUP_BATCH_SIZE = 10000  # Clean up this many flows at once

# Flow state constants (must match eBPF program)
STATE_WAITING = 0
STATE_READY = 1
STATE_MALICIOUS = 2
STATE_BENIGN = 3

# Global statistics
stats = {
    'total': 0,
    'malicious': 0,
    'benign': 0,
    'unclassified': 0
}

# Track which flows we've already counted
counted_flows = set()

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="BCC/XDP Flow Monitor")
    parser.add_argument("--device", type=str, default="veth0", 
                        help="Network device to use")
    parser.add_argument("--source", type=str, default="xdp_prog.c", 
                        help="eBPF program file name")
    parser.add_argument("--func", type=str, default="packet_handler", 
                        help="Function name to attach")
    parser.add_argument("--debug", type=int, default=0,
                        help="Print debugging information")
    
    return parser.parse_args()

def load_decision_trees(b, debug=0):
    """Load all 3 decision trees from their respective folders"""
    import os
    
    # Define the map names for each tree
    map_names = ['children_left', 'children_right', 'features', 'thresholds', 'values']
    tree_folders = ['decision-tree1', 'decision-tree2', 'decision-tree3']
    
    for tree_num, folder in enumerate(tree_folders, 1):
        if debug:
            print(f"\n=== Loading Decision Tree {tree_num} from {folder}/ ===")
        
        # Check if folder exists
        if not os.path.exists(folder):
            print(f"Warning: Folder {folder} not found, skipping tree {tree_num}")
            continue
            
        for map_name in map_names:
            # Construct the BPF map name (e.g., "children_left1")
            bpf_map_name = f"{map_name}{tree_num}"
            file_path = os.path.join(folder, map_name)
            
            try:
                # Get map reference
                bpf_map = b.get_table(bpf_map_name)
                
                # Read values from file
                with open(file_path, 'r') as f:
                    values = [int(line.strip()) for line in f if line.strip()]
                
                # Update map with values from file
                for i, val in enumerate(values):
                    if i < bpf_map.max_entries:
                        bpf_map[ctypes.c_uint(i)] = ctypes.c_int64(val)
                    else:
                        print(f"Warning: More values in {file_path} than map size")
                        break
                
                if debug:
                    print(f"Loaded {len(values)} values into {bpf_map_name} from {file_path}")
                
            except FileNotFoundError:
                print(f"Error: File {file_path} not found")
            except Exception as e:
                print(f"Error loading {bpf_map_name}: {e}")
    
    print(f"Decision Trees loaded successfully")

def get_protocol_name(protocol):
    """Convert protocol number to human-readable name"""
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    return protocols.get(protocol, f"Unknown ({protocol})")

def flow_key_to_tuple(key):
    """Convert flow_key to a hashable tuple for tracking"""
    return (key.src_ip, key.dst_ip, key.src_port, key.dst_port, key.protocol)

def collect_statistics(bpf_tables, debug=0):
    """
    Collect statistics by reading the sig_map and checking flow states
    """
    global stats, counted_flows
    
    sig_map = bpf_tables["sig_map"]
    current_time = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    flow_map = bpf_tables["flow_map"]
    
    current_counted = set()
    
    try:
        # Iterate through all flows in sig_map
        for key, state in sig_map.items():
            flow_tuple = flow_key_to_tuple(key)
            current_counted.add(flow_tuple)
            
            # Only count flows we haven't counted before
            if flow_tuple not in counted_flows:
                if state.value == STATE_MALICIOUS:
                    stats['malicious'] += 1
                    stats['total'] += 1
                    counted_flows.add(flow_tuple)
                    if debug:
                        print(f"New malicious flow detected: {socket.inet_ntoa(key.src_ip.to_bytes(4, 'little'))} -> {socket.inet_ntoa(key.dst_ip.to_bytes(4, 'little'))}")
                
                elif state.value == STATE_BENIGN:
                    stats['benign'] += 1
                    stats['total'] += 1
                    counted_flows.add(flow_tuple)
                    if debug:
                        print(f"New benign flow detected: {socket.inet_ntoa(key.src_ip.to_bytes(4, 'little'))} -> {socket.inet_ntoa(key.dst_ip.to_bytes(4, 'little'))}")
        
        # Check for flows that have been removed (timed out)
        removed_flows = counted_flows - current_counted
        if removed_flows:
            # These flows were classified but have now been removed
            # They're already counted, so we just remove them from our tracking set
            counted_flows = current_counted
            if debug and removed_flows:
                print(f"Removed {len(removed_flows)} old flows from tracking")
                
    except Exception as e:
        if debug:
            print(f"Error collecting statistics: {e}")

def cleanup_old_flows(bpf_tables, debug=0):
    """
    Cleanup old/stale flows from the flow_map to prevent it from getting full
    """
    global stats, counted_flows
    
    current_time = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    flow_map = bpf_tables["flow_map"]
    sig_map = bpf_tables["sig_map"]
    
    flows_cleaned = 0
    
    try:
        # Get all flows
        for key, flow in list(flow_map.items()):
            # Check if flow is too old (hasn't been seen recently)
            if (current_time - flow.last_seen) > FLOW_TIMEOUT:
                flow_tuple = flow_key_to_tuple(key)
                
                # Count as unclassified if being cleaned up without classification
                if key in sig_map:
                    state = sig_map[key]
                    if state.value == STATE_WAITING and flow_tuple not in counted_flows:
                        stats['unclassified'] += 1
                        stats['total'] += 1
                        if debug:
                            print(f"Unclassified flow timed out: {socket.inet_ntoa(key.src_ip.to_bytes(4, 'little'))} -> {socket.inet_ntoa(key.dst_ip.to_bytes(4, 'little'))}")
                
                # Delete from flow_map
                try:
                    del flow_map[key]
                    if debug:
                        print(f"Cleaned up old flow from flow_map")
                except:
                    pass

                # Delete from sig_map
                try:
                    del sig_map[key]
                except:
                    pass
                
                # Remove from counted flows
                if flow_tuple in counted_flows:
                    counted_flows.discard(flow_tuple)
                
                flows_cleaned += 1
                
                # Limit batch size
                if flows_cleaned >= CLEANUP_BATCH_SIZE:
                    break
                
        if debug and flows_cleaned > 0:
            print(f"Cleaned up {flows_cleaned} old flows")
            
    except Exception as e:
        if debug:
            print(f"Error during flow cleanup: {e}")
    
    return flows_cleaned

def print_final_statistics():
    """Print final statistics in the requested format"""
    print("\n=== Final Statistics ===")
    print(f"Total flows processed: {stats['total']}")
    print(f"Malicious flows: {stats['malicious']}")
    print(f"Benign flows: {stats['benign']}")
    print(f"Unclassified flows: {stats['unclassified']}")
    print("========================")

def signal_handler(sig, frame, bpf_obj, device):
    """Handle SIGINT (Ctrl+C) gracefully"""
    print("\nShutting down...")
    print(f"Unloading XDP program from device: {device}")
    bpf_obj.remove_xdp(device, 0)
    print_final_statistics()
    sys.exit(0)

def main():
    """Main function to load and run the eBPF program"""
    # Parse command line arguments
    args = parse_arguments()

    # Load the eBPF program from the source file
    bpf = BPF(src_file=args.source)
    
    # Load and attach the packet handler function
    fn_packet_handler = bpf.load_func(args.func, BPF.XDP)

    # Fill model related maps
    load_decision_trees(bpf, args.debug)
    XDP_FLAGS_DRV_MODE = (1 << 2)
    print(f"XDP program flags: {XDP_FLAGS_DRV_MODE}")
    # Attach to interface
    bpf.attach_xdp(args.device, fn_packet_handler, XDP_FLAGS_DRV_MODE)
    print(f"XDP program attached to device: {args.device}")
    
    # Get all the BPF maps
    bpf_tables = {
        "passed_packets": bpf.get_table("passed_packets"),
        "sig_map": bpf.get_table("sig_map"),
        "flow_map": bpf.get_table("flow_map"),
    }
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, bpf, args.device))
        
    try:
        print("Flow monitor running. Press Ctrl+C to exit.")
        
        # Main processing loop
        while True:
            # Refresh maps
            bpf_tables["flow_map"] = bpf.get_table("flow_map")
            bpf_tables["sig_map"] = bpf.get_table("sig_map")
            
            # Collect statistics from sig_map
            collect_statistics(bpf_tables, args.debug)
            
            # Check flow map usage
            try:
                current_entries = len(list(bpf_tables["flow_map"].items()))
                usage_percent = (current_entries / XDP_MAX_MAP_ENTRIES) * 100
                
                if args.debug:
                    print(f"Flow map usage: {current_entries}/{XDP_MAX_MAP_ENTRIES} ({usage_percent:.1f}%)")
                
                # Cleanup old flows when map is getting full
                if current_entries > MAX_FLOWS_THRESHOLD:
                    cleanup_old_flows(bpf_tables, args.debug)
                    
                    if usage_percent > 90 and args.debug:
                        print(f"WARNING: Flow map is {usage_percent:.1f}% full!")
            except:
                pass
                    
            # Sleep briefly to avoid CPU hogging 
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None, bpf, args.device)

if __name__ == "__main__":
    main()