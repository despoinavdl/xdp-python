#!/usr/bin/env python3
import socket
import time
import json
import subprocess
import struct

def get_protocol_name(protocol):
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    return protocols.get(protocol, f"Unknown ({protocol})")

def print_flow_info(flow):
    """Display formatted flow information matching the original function"""
    # Convert IP addresses using little-endian byte order
    src_ip_str = socket.inet_ntoa(struct.pack("<I", flow["src_ip"]))
    dst_ip_str = socket.inet_ntoa(struct.pack("<I", flow["dst_ip"]))
    
    # Convert duration from nanoseconds to seconds
    duration_seconds = flow['duration'] / 1_000_000_000
    
    # Calculate pps and bps properly based on the dataplane code
    # In the dataplane: pps = (packets * 10000000000) / duration
    # So to convert back: pps = pps_stored / 10
    pps = flow['pps'] / 10
    
    # In the dataplane: bps = (bytes * 1000000000) / duration
    # This is bytes per second
    bps = flow['bps']
    
    print("-------------------------------------------")
    print(f"Source IP:       {src_ip_str}")
    print(f"Destination IP:  {dst_ip_str}")
    print(f"Source Port:     {flow['src_port']}")
    print(f"Destination Port:{flow['dst_port']}")
    print(f"Protocol:        {get_protocol_name(flow['protocol'])}")
    print(f"Packets:         {flow['packets']}")
    print(f"Bytes:           {flow['bytes']}")
    print(f"First Seen:      {flow['first_seen'] / 1_000_000_000} s (since epoch)")
    print(f"Last Seen:       {flow['last_seen'] / 1_000_000_000} s (since epoch)")
    print(f"Duration:        {duration_seconds:.3f} sec")
    print(f"PPS:             {pps:.1f} packets/sec")
    print(f"BPS:             {bps} bytes/sec")
    print(f"IAT:             {flow['iat'] / 1_000_000_000} s")
    print("-------------------------------------------")

def get_map_entries():
    """Use bpftool to get map contents"""
    try:
        # Run bpftool to dump the map contents
        result = subprocess.run(
            ["sudo", "bpftool", "map", "dump", "name", "aggr", "-j"],
            capture_output=True, text=True, check=True
        )
        
        # Parse the JSON output
        map_data = json.loads(result.stdout)
        return map_data
    except subprocess.CalledProcessError as e:
        print(f"Error running bpftool: {e}")
        if e.stderr:
            print(f"stderr: {e.stderr}")
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return []

def main():
    print("eBPF Map Monitor - using bpftool")
    print("Press Ctrl+C to exit")
    
    try:
        while True:
            print(f"\nTime: {time.strftime('%H:%M:%S')}")
            
            # Get map entries using bpftool
            entries = get_map_entries()
            
            if not entries:
                print("No flows detected or error retrieving map data.")
            else:
                print(f"Found {len(entries)} flows:")
                for entry in entries:
                    if "formatted" in entry and "value" in entry["formatted"]:
                        # Use the pre-formatted values
                        flow_data = entry["formatted"]["value"]
                        print_flow_info(flow_data)
            
            # Wait before next check
            time.sleep(2)
    
    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    main()