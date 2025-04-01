from bcc import BPF
from bcc.utils import printb
import argparse
import socket
import time
import ctypes
from jhash import *

FLOW_TIMEOUT = 5000000000 # 5 seconds timeout in nanoseconds

parser = argparse.ArgumentParser(description="Process command-line arguments.")
parser.add_argument("--device", type=str, default="lo", help="Network device to use")
parser.add_argument("--source", type=str, default="xdp_prog_1.c", help="eBPF program file name")
parser.add_argument("--func", type=str, default="packet_handler", help="Function name")

args = parser.parse_args()

device = args.device
source = args.source
func = args.func
map_seeds = [12, 37, 42, 68, 91]

def get_protocol_name(protocol):
    protocols = {
        1 : "ICMP",
        6 : "TCP",
        17 : "UDP"
    }
    return protocols.get(protocol, "Unknown")

def print_flow_info(flow):
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
    print(f"PPS:             {flow.pps / 10:.1f}")
    print(f"BPS:             {flow.bps}")
    print(f"IAT:             {flow.iat}")
    print("-------------------------------")


# Waiting: 0,
# Ready: 1,
# Malicious: 2,
# Benign: 3
def check_for_deletion(key, flow):
    current_time = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    sig_map = b.get_table("sig_map")
    if key in sig_map: 
        # Check for timeout and if state = Ready
        # !!!!!!! MAKE THE FLOW DECISION !!!!!!!
        #
        state = sig_map[key]
        # print(f"State : {state}")
        # if state == Ready or timeout
        print(f"Current time: {current_time}")
        print(f"Flow last seen: {flow.last_seen}")
        if state == 1 or (current_time - flow.last_seen > FLOW_TIMEOUT):
            # For testing purposes, decide every flow to be malicious
            state = 2
            c_state = ctypes.c_uint(state)
            sig_map[key] = c_state
            # sig_map.items_update_batch([key], [state])

            # Delete flow from hash func maps with their respective key
            flowkey_bytes = struct.pack(
                "IIHHI",
                flow.src_ip, flow.dst_ip,
                flow.src_port, flow.dst_port,
                flow.protocol
            )
            hash_func_1.items_delete_batch((ctypes.c_uint32 * 1)(jhash(flowkey_bytes, map_seeds[0])))
            hash_func_2.items_delete_batch((ctypes.c_uint32 * 1)(jhash(flowkey_bytes, map_seeds[1])))
            hash_func_3.items_delete_batch((ctypes.c_uint32 * 1)(jhash(flowkey_bytes, map_seeds[2])))
            hash_func_4.items_delete_batch((ctypes.c_uint32 * 1)(jhash(flowkey_bytes, map_seeds[3])))
            hash_func_5.items_delete_batch((ctypes.c_uint32 * 1)(jhash(flowkey_bytes, map_seeds[4])))

            dbg.items_delete_batch((ctypes.c_uint32 * 1)(key))
    else:
        print(f"{key} not found in sig_map")



# Load the eBPF program from the source file
b = BPF(src_file=source)

# Load and attach the packet_handler function
fn_packet_handler = b.load_func(func, BPF.XDP)
b.attach_xdp(device, fn_packet_handler, 0)

hash_func_1 = b.get_table("hash_func_1")
hash_func_2 = b.get_table("hash_func_2")
hash_func_3 = b.get_table("hash_func_3")
hash_func_4 = b.get_table("hash_func_4")
hash_func_5 = b.get_table("hash_func_5")

passed_packets = b.get_table("passed_packets")
dbg = b.get_table("dbg")
sig_map = b.get_table("sig_map")


try:
    # b.trace_print()
    # icmp_dist = b.get_table("counter_icmp")

    while(1):

        dbg = b.get_table("dbg")
        dbg_items = dbg.items()
        if(dbg_items):
            for k, v in dbg_items:
                print_flow_info(v)
                check_for_deletion(k, v)
        time.sleep(2)

except KeyboardInterrupt:
    print("\nUnloading xdp program from device...")

b.remove_xdp(device, 0)