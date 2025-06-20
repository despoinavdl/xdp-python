#!/usr/bin/env python3
"""
BCC Python Program for Count-Min Sketch Flow Monitoring

This program loads and manages an eBPF/XDP program that implements a Count-Min Sketch
for network flow monitoring. It periodically checks flows and makes decisions about
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
import os
import struct

from MLP import *
from jhash import jhash  # Custom jhash implementation

# Constants
# FLOW_TIMEOUT = 5_000_000_000  # 5 seconds timeout in nanoseconds
# FLOW_TIMEOUT = 50000000000  # 50 seconds timeout in nanoseconds
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
    print(f"IAT:             {flow.iat_mean}")
    print("-------------------------------")

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
        flow.iat_mean / 1000000         # Flow IAT Mean (unit in dataset?)
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


    # Apply the same scaling as during training to numerical features only
    if scaler is not None:
        numerical_features = scaler.transform(numerical_features.reshape(1, -1)).flatten()
    
    # Combine categorical and numerical features
    features = np.hstack([categorical_features, numerical_features])
    
    # Print for debugging
    if debug:
        feature_names = [
            'Protocol', 'Flow Duration', 'Total Fwd Packets',
            'Fwd Packets Length Total', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean'
        ]
        # print("=== INFERENCE INPUT ===")
        print("AFTER SCALING:")
        for name, value in zip(feature_names, features):
            print(f"{name}: {value}")
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
            
            if flow_map_items:
                for key, flow in flow_map_items:
                    # Uncomment to debug flow details
                    # if args.debug:
                    #     print_flow_info(flow)
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