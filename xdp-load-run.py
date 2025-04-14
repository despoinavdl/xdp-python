#!/usr/bin/env python3
"""
BCC Python Program for Count-Min Sketch Flow Monitoring

This program loads and manages an eBPF/XDP program that implements a Count-Min Sketch
for network flow monitoring. It periodically checks flows and makes decisions about
whether they are malicious or benign.
"""

from bcc import BPF, lib
import argparse
import socket
import time
import ctypes
import os
import struct
from jhash import jhash  # Custom jhash implementation

# Constants
# FLOW_TIMEOUT = 5_000_000_000  # 5 seconds timeout in nanoseconds
FLOW_TIMEOUT = 100_000_000_000  # 100 seconds timeout in nanoseconds for testing
MAP_SEEDS = [12, 37, 42, 68, 91]  # Hash function seeds matching the eBPF program

# Flow state constants
STATE_WAITING = 0
STATE_READY = 1
STATE_MALICIOUS = 2
STATE_BENIGN = 3

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="BCC/XDP Flow Monitor")
    parser.add_argument("--device", type=str, default="lo", 
                        help="Network device to use")
    parser.add_argument("--source", type=str, default="xdp_prog.c", 
                        help="eBPF program file name")
    parser.add_argument("--func", type=str, default="packet_handler", 
                        help="Function name to attach")
    
    return parser.parse_args()

def get_protocol_name(protocol):
    """Convert protocol number to human-readable name"""
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    return protocols.get(protocol, f"Unknown ({protocol})")

def print_flow_info(flow):
    """Display formatted flow information"""
    src_ip_str = socket.inet_ntoa(flow.src_ip.to_bytes(4, 'little'))
    dst_ip_str = socket.inet_ntoa(flow.dst_ip.to_bytes(4, 'little'))
    
    print("-------------------------------")
    print(f"Source IP:       {src_ip_str}")
    print(f"Destination IP:  {dst_ip_str}")
    print(f"Source Port:     {flow.src_port}")
    print(f"Destination Port:{flow.dst_port}")
    print(f"Protocol:        {get_protocol_name(flow.protocol)}")
    print(f"Packets:         {flow.packets}")
    print(f"Bytes:           {flow.bytes}")
    print(f"First Seen:      {flow.first_seen}")
    print(f"Last Seen:       {flow.last_seen}")
    print(f"Duration:        {flow.duration}")
    print(f"PPS:             {flow.pps / 10:.1f}")  # Adjust for decimal point
    print(f"BPS:             {flow.bps}")
    print(f"IAT:             {flow.iat}")
    print("-------------------------------")

def pack_flow_key(flow):
    """Pack flow information into bytes for hashing"""
    return struct.pack(
        "IIHHI",
        flow.src_ip, flow.dst_ip,
        flow.src_port, flow.dst_port,
        flow.protocol
    )

def process_flow(key, flow, bpf_tables):
    """
    Process a flow and make classification decisions
    
    This function:
    1. Checks if the flow is ready for classification or has timed out
    2. Makes a decision (currently marks all flows as malicious for testing)
    3. Updates the state in sig_map
    4. Removes the flow data from all hash tables
    
    Args:
        key: The flow key in the sig_map
        flow: The flow information structure
        bpf_tables: Dictionary containing all BPF map tables
    """
    current_time = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    sig_map = bpf_tables["sig_map"]
    
    # Check if flow exists in sig_map
    if key in sig_map:
        state = sig_map[key]
        
        # Check if flow is ready for classification or has timed out
        if state.value == STATE_READY or (current_time - flow.last_seen > FLOW_TIMEOUT):
            # For testing purposes, classify every flow as malicious
            new_state = STATE_MALICIOUS
            
            # Update the state in sig_map
            sig_map.items_update_batch(
                (ctypes.c_uint32 * 1)(key),
                (ctypes.c_uint32 * 1)(new_state)
            )

            # Delete flow from all hash function maps
            flowkey_bytes = pack_flow_key(flow)
            
            # Clean up all tables
            for i, seed in enumerate(MAP_SEEDS):
                hashed_key = jhash(flowkey_bytes, seed)
                hash_table = bpf_tables[f"hash_func_{i+1}"]
                hash_table.items_delete_batch((ctypes.c_uint32 * 1)(hashed_key))
                if i == 0:  # Only print for the first hash map
                    print(f"Deleting flow from hash tables with key: {hashed_key}")
            
            # Remove from aggregation map
            bpf_tables["aggr"].items_delete_batch((ctypes.c_uint32 * 1)(key))
    else:
        print(f"Flow key {key} not found in sig_map")

def main():
    """Main function to load and run the eBPF program"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Load the eBPF program from the source file
    bpf = BPF(src_file=args.source)
    
    # Load and attach the packet handler function
    fn_packet_handler = bpf.load_func(args.func, BPF.XDP)
    bpf.attach_xdp(args.device, fn_packet_handler, 0)
    print(f"XDP program attached to device: {args.device}")
    
    # Get all the BPF maps
    bpf_tables = {
        "hash_func_1": bpf.get_table("hash_func_1"),
        "hash_func_2": bpf.get_table("hash_func_2"),
        "hash_func_3": bpf.get_table("hash_func_3"),
        "hash_func_4": bpf.get_table("hash_func_4"),
        "hash_func_5": bpf.get_table("hash_func_5"),
        "passed_packets": bpf.get_table("passed_packets"),
        "sig_map": bpf.get_table("sig_map"),
        "aggr": bpf.get_table("aggr"),
    }
        
    try:
        print("Flow monitor running. Press Ctrl+C to exit.")
        
        # Main processing loop
        while True:
            # Refresh the aggregation map (it might have been updated by the eBPF program)
            bpf_tables["aggr"] = bpf.get_table("aggr")
            aggr_items = bpf_tables["aggr"].items()
            
            if aggr_items:
                for key, flow in aggr_items:
                    # Uncomment to debug flow details
                    # print_flow_info(flow)
                    process_flow(key, flow, bpf_tables)
                    
            # Sleep briefly to avoid CPU hogging
            # time.sleep(0.1)
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Clean up
        print(f"Unloading XDP program from device: {args.device}")
        bpf.remove_xdp(args.device, 0)

if __name__ == "__main__":
    main()