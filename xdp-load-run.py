from bcc import BPF
from bcc.utils import printb
import argparse
import time
from jhash import *

parser = argparse.ArgumentParser(description="Process command-line arguments.")
parser.add_argument("--device", type=str, default="lo", help="Network device to use")
parser.add_argument("--source", type=str, default="xdp_prog.c", help="eBPF program file name")
parser.add_argument("--func", type=str, default="packet_handler", help="Function name")

args = parser.parse_args()

device = args.device
source = args.source
func = args.func
map_seeds = [12, 37, 42, 68, 91]
protocols = {
    1 : "ICMP",
    6 : "TCP",
    17 : "UDP"
}

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
    icmp_dist = b.get_table("counter_icmp")

    while(1):
        items = icmp_dist.items()
        print(f"\n{len(items)} in dict")
        if(items):
            for k, v in items:
                print(f"\n{k.value} : {v.value}")
        else:
            print("-" * 28)
        time.sleep(2)
        

except KeyboardInterrupt:
    print("\nUnloading xdp program from device...")

b.remove_xdp(device, 0)