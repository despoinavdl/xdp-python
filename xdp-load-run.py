#!/usr/bin/env python3
"""
BCC Python Program for Flow Monitoring

This program loads and manages an eBPF/XDP program for network flow monitoring. 
It periodically checks flows and makes decisions about
whether they are malicious or benign.
"""
import joblib
import torch
import numpy as np

from bcc import BPF, lib
import argparse
import socket
import time
import ctypes
import csv
import os

from MLP import *
from jhash import jhash  # Custom jhash implementation

# Constants
#define XDP_MAX_MAP_ENTRIES 1024000 in flow_headers.h
XDP_MAX_MAP_ENTRIES = 1024000
# XDP_MAX_MAP_ENTRIES = 10
FLOW_TIMEOUT = 30_000_000_000  # 30 seconds timeout in nanoseconds
MAX_FLOWS_THRESHOLD = int(XDP_MAX_MAP_ENTRIES * 0.8)  # Clean when 80% full
CLEANUP_BATCH_SIZE = 10000  # Clean up this many flows at once
# FLOW_TIMEOUT = 100_000_000_000_000  # 100 seconds timeout in nanoseconds for testing
MAP_SEEDS = [17, 53, 97, 193, 389]  # Hash function seeds matching the eBPF program

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
                        help="Function name to attach"),
    parser.add_argument("--debug", type=int, default=0,
                        help="Print debugging information")
    
    return parser.parse_args()

def get_protocol_name(protocol):
    """Convert protocol number to human-readable name"""
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    return protocols.get(protocol, f"Unknown ({protocol})")


def get_flow_map_usage(flow_map_items):
    """Get current usage statistics of the flow map"""
    try:
        current_entries = len(list(flow_map_items))
        usage_percent = (current_entries / XDP_MAX_MAP_ENTRIES) * 100
        return current_entries, usage_percent
    except:
        return 0, 0.0

def cleanup_old_flows(bpf_tables, debug=0):
    """
    Cleanup old/stale flows from the flow_map to prevent it from getting full
    """
    current_time = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    flow_map = bpf_tables["flow_map"]
    sig_map = bpf_tables["sig_map"]
    
    flows_cleaned = 0
    current_entries, usage_percent = get_flow_map_usage(flow_map.items())
    if debug:
        print(f"Flow map usage: {current_entries}/{XDP_MAX_MAP_ENTRIES} ({usage_percent:.1f}%)")
    
    try:
        # Get all flows
        for key, flow in flow_map.items():
            # Check if flow is too old (hasn't been seen recently)
            print(f"Checking current time: {current_time} - flow last seen: {flow.last_seen}")
            if (current_time - flow.last_seen) > FLOW_TIMEOUT:
                
                # Delete from flow_map
                if key in flow_map:
                    try:
                        del flow_map[key]
                        print(f"In cleanup flows, deleting from flow map {key}")
                    except:
                        pass  # Key might have been deleted by another process

                # Also clean from sig_map
                if key in sig_map:
                    try:
                        del sig_map[key]
                        print(f"In cleanup flows, deleting key from sig map: {key.src_ip} \
                              {key.dst_ip} {key.src_port} {key.dst_port} {key.protocol}")
                    except:
                        pass
                
                flows_cleaned += 1
                
                # Limit batch size to avoid holding locks too long
                if flows_cleaned >= CLEANUP_BATCH_SIZE:
                    break
                
        if debug and flows_cleaned > 0:
            print(f"Cleaned up {flows_cleaned} old flows")
            
    except Exception as e:
        print(f"Error during flow cleanup: {e}")
    
    return flows_cleaned


def print_flow_info(key, flow):
    """Display formatted flow information"""
    src_ip_str = socket.inet_ntoa(key.src_ip.to_bytes(4, 'little'))
    dst_ip_str = socket.inet_ntoa(key.dst_ip.to_bytes(4, 'little'))
    
    print("-------------------------------")
    print(f"Source IP:       {src_ip_str}")
    print(f"Destination IP:  {dst_ip_str}")
    print(f"Source Port:     {socket.ntohs(key.src_port)}")
    print(f"Destination Port:{socket.ntohs(key.dst_port)}")
    print(f"Protocol:        {get_protocol_name(key.protocol)}")
    print(f"Packets:         {flow.packets}")
    print(f"Bytes:           {flow.bytes}")
    print(f"First Seen:      {flow.first_seen}")
    print(f"Last Seen:       {flow.last_seen}")
    print(f"Duration:        {flow.duration}")
    print(f"PPS:             {flow.pps / 10:.1f}")  # Adjust for decimal point
    print(f"BPS:             {flow.bps}")
    print(f"IAT MEAN:        {flow.iat_mean}")
    print(f"IAT TOTAL:       {flow.iat_total}")
    print(f"IAT MIN:         {flow.iat_min}")
    print(f"IAT MAX:         {flow.iat_max}")
    print("-------------------------------")

    # # Define output file
    # file_path = "malicious_flows.csv"

    # # Define headers for the CSV file
    # headers = ["Protocol", "SrcIP", "SrcPort", "DstIP", "DstPort"]
    # protocol_name = get_protocol_name(key.protocol)

    # # Prepare current row as a list of strings
    # # print(f"DEBUGGING PORT INT: {key.dst_port}\nPORT STR: {str(key.dst_port)}")
    # # print(f"TEST SRC: {socket.ntohs(key.src_port)}, DST: {socket.ntohs(key.dst_port)}")
    # current_row = [
    #     protocol_name,
    #     src_ip_str,
    #     str(socket.ntohs(key.src_port)),
    #     dst_ip_str,
    #     str(socket.ntohs(key.dst_port))
    # ]

    # # Check line-by-line in file for a matching row
    # already_exists = False
    # if os.path.isfile(file_path):
    #     with open(file_path, mode="r", newline="") as f:
    #         reader = csv.reader(f)
    #         for row in reader:
    #             if row == current_row:
    #                 already_exists = True
    #                 break

    # # Append row only if it doesn't already exist
    # if not already_exists:
    #     file_empty = not os.path.isfile(file_path) or os.path.getsize(file_path) == 0
    #     with open(file_path, mode="a", newline="") as f:
    #         writer = csv.writer(f)
    #         if file_empty:
    #             writer.writerow(headers)
    #         writer.writerow(current_row)

# Function to load the model
def load_model(model_path="best_mlp_model.pt"):
    """
    Load the pre-trained MLP model from state_dict on CPU
    """
    if not os.path.exists(model_path):
        print(f"Error: Model file {model_path} not found")
        return None
    
    # Create model with the same architecture
    input_size = 7  # Number of features
    model = MLP(input_size)
    
    # Load the state_dict on CPU
    state_dict = torch.load(model_path, map_location=torch.device('cpu'))
    
    # Handle the case where the model was saved with DataParallel or similar wrapper
    # This removes the "module." prefix from all keys in the state dictionary
    new_state_dict = {}
    for key, value in state_dict.items():
        if key.startswith('module.'):
            new_key = key[7:]  # Remove 'module.' prefix
            new_state_dict[new_key] = value
        else:
            new_state_dict[key] = value
    
    # Load the modified state dict
    model.load_state_dict(new_state_dict)
    model.eval()  # Set the model to evaluation mode
    return model

# Load the feature scaler
def load_scaler(scaler_path="feature_scaler.joblib"):
    """
    Load the feature scaler used during training
    """
    try:
        scaler = joblib.load(scaler_path)
        print(f"Feature scaler loaded successfully from {scaler_path}")
        return scaler
    except Exception as e:
        print(f"Error loading scaler: {e}")
        return None

# Function to preprocess the flow data
def preprocess_flow(key, flow, scaler=None, debug=0):
    """
    Convert flow information to feature vector for model input
    """
    # Extract features - keep protocol as-is
    categorical_features = [key.protocol]
    
    # Extract numerical features
    numerical_features = np.array([
        flow.duration / 1_000_000_000,  # Flow Duration
        flow.packets,                   # Total Fwd Packets
        flow.bytes,                     # Fwd Packets Length Total
        flow.bps,                       # Flow Bytes/s
        flow.pps / 10,                  # Flow Packets/s (adjusted)
        flow.iat_mean / 1000000000,        # Flow IAT Mean (unit in dataset?)
        flow.iat_total / 1000000000,
        flow.iat_min / 1000000000,
        flow.iat_max / 1000000000
    ], dtype=np.float32)
    

    ##################################
    # DELETE THESE LINES AFTER TESTING
    # features = np.hstack([categorical_features, numerical_features])
    # feature_names = [
    #         'Protocol', 'Flow Duration', 'Total Fwd Packets',
    #         'Fwd Packets Length Total', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean'
    #     ]
    # print("========= INFERENCE INPUT =========")
    # print("BEFORE SCALING:")
    # for name, value in zip(feature_names, features):
    #     print(f"{name}: {value}")
    # print("-" * 23)
    ##################################

    # UNCOMMENT TO APPLY SCALER
    # Apply the same scaling as during training to numerical features only
    # if scaler is not None:
    #     numerical_features = scaler.transform(numerical_features.reshape(1, -1)).flatten()
    
    # Combine categorical and numerical features
    features = np.hstack([categorical_features, numerical_features])
    
    # Print for debugging
    if debug:
        feature_names = [
            'Protocol', 'Flow Duration', 'Total Fwd Packets',
            'Fwd Packets Length Total', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Flow IAT Total', 'Flow IAT Min', 'Flow IAT Max',
            'Label'
        ]
        # print("=== INFERENCE INPUT ===")
        # print("AFTER SCALING:")
        for name, value in zip(feature_names, features):
            print(f"{name}: {value}")

        file_path = "features/features.csv"
        # Does the file already exist?
        file_exists = os.path.isfile(file_path)

        # Open file in append mode
        with open(file_path, mode="a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=feature_names)

            # Write header only once (when file is created)
            if not file_exists:
                writer.writeheader()

            # Write one row of features
            row = dict(zip(feature_names, features))
            row['Label'] = 'Benign'
            writer.writerow(row)

        print("===================================")

   # Convert to PyTorch tensor
    features_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0)
    return features_tensor

benign_flows = 0
malicious_flows = 0
def process_flow(key, flow, bpf_tables, model, scaler=None, debug=0):
    # print("In process flow!")
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
        model: Pre-trained PyTorch model for flow classification
    """
    global benign_flows
    global malicious_flows
    current_time = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    sig_map = bpf_tables["sig_map"]
    
    # Check if flow exists in sig_map
    if key in sig_map:
        state = sig_map[key]
        # print("Key in sigmap\n")
        
        # Check if flow is ready for classification or has timed out
        # if state.value == STATE_READY or (current_time - flow.last_seen > FLOW_TIMEOUT):
        if state.value == STATE_READY:
            # Use model for classification if available
            if model is not None:
                try:
                    # Preprocess flow data
                    input_features = preprocess_flow(key, flow, scaler, debug)
                    
                    # Need to temporarily set the model to evaluation mode but with no tracking
                    with torch.no_grad():
                        # For batch normalization to work with single sample
                        model.eval()
                        output = model(input_features)
                        # Binary classification where 1 = malicious, 0 = benign
                        prediction = output.item() > 0.5  # Adjust threshold as needed
                    
                    # Set state based on model prediction
                    new_state = STATE_MALICIOUS if prediction else STATE_BENIGN
                    if prediction:
                        malicious_flows += 1
                    else: 
                        benign_flows +=1
                    if debug:
                        print(f"Flow classified as {'MALICIOUS' if prediction else 'BENIGN'} (confidence: {output.item():.4f})")
                except Exception as e:
                    print(f"Error during model inference: {e}")
                    new_state = STATE_MALICIOUS  # Default to malicious on error
            else:
                # Fallback to default classification if model not available
                print("Model not available, using default classification")
                new_state = STATE_MALICIOUS
            
            sig_map[key] = ctypes.c_uint32(new_state)
            
            # Clean up table (flow_map)
            flow_map = bpf_tables[f"flow_map"]
            try:
                # flow_map.items_delete_batch([key])
                del flow_map[key]
                if debug:
                    print(f"Deleting flow from hash tables with key: {key}\n\n")
            except Exception:
                print("Could not delete key")
                pass
    else:
        print(f"Flow key {key} not found in sig_map")
        print(f"{key.src_ip} {key.dst_ip} {key.src_port} {key.dst_port} {key.protocol}")

def main():
    """Main function to load and run the eBPF program"""
    # Parse command line arguments
    args = parse_arguments()

    # Load the ML model
    model = load_model()
    if model is None:
        print("Warning: Failed to load model, will use default classification")
    else:
        print("Model loaded successfully")

    # Load the feature scaler
    scaler = load_scaler()
    if scaler is None:
        print("Warning: Failed to load feature scaler, predictions may be inaccurate")
    
    # Load the eBPF program from the source file
    bpf = BPF(src_file=args.source)
    
    # Load and attach the packet handler function
    fn_packet_handler = bpf.load_func(args.func, BPF.XDP)
    bpf.attach_xdp(args.device, fn_packet_handler, 0)
    print(f"XDP program attached to device: {args.device}")
    
    # Get all the BPF maps
    bpf_tables = {
        "passed_packets": bpf.get_table("passed_packets"),
        "sig_map": bpf.get_table("sig_map"),
        "flow_map": bpf.get_table("flow_map"),
    }


        
    try:
        print("Flow monitor running. Press Ctrl+C to exit.")
        
        # Main processing loop
        while True:
            # Refresh the aggregation map (it might have been updated by the eBPF program)
            bpf_tables["flow_map"] = bpf.get_table("flow_map")
            flow_map_items = bpf_tables["flow_map"].items()
            
            current_entries, usage_percent = get_flow_map_usage(flow_map_items)
            
            # Cleanup old flows periodically or when map is getting full
            should_cleanup = current_entries > MAX_FLOWS_THRESHOLD
            
            if should_cleanup:
                flows_cleaned = cleanup_old_flows(bpf_tables, args.debug)
                
                if usage_percent > 90 and args.debug:
                    print(f"WARNING: Flow map is {usage_percent:.1f}% full!")

            if flow_map_items:
                for key, flow in flow_map_items:
                    # Uncomment to debug flow details
                    # if args.debug:
                    #     print_flow_info(key, flow)
                    process_flow(key, flow, bpf_tables, model, scaler, args.debug)
                    
            # Sleep briefly to avoid CPU hogging 
            # time.sleep(0.1)
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Clean up
        print(f"Unloading XDP program from device: {args.device}")
        bpf.remove_xdp(args.device, 0)
        total_flows = benign_flows + malicious_flows
        print(f"Malicious flows: {malicious_flows}/{total_flows}")
        print(f"Benign flows: {benign_flows}/{total_flows}")

if __name__ == "__main__":
    main()
