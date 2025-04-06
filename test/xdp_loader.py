from bcc import BPF
from bcc.utils import printb
import time
from jhash import *

device = "lo"
hash_seed = 0x12345678

# Load the eBPF program from the source file
b = BPF(src_file="xdp_prog_test.c")

# Load and attach the packet_handler function
fn_packet_handler = b.load_func("packet_handler", BPF.XDP)
b.attach_xdp(device, fn_packet_handler, 0)

# Convert the IP address (integer) to 4 bytes in little-endian format
def ip_to_bytes(value):
    return struct.pack("<IB", value.ip, value.ki)  # 4-byte representation

try:
    # b.trace_print()
    icmp_dist = b.get_table("counter_icmp")
    while(1):
        items = icmp_dist.items()
        print(f"\n{len(items)} in dict")
        if(items):
            for k, v in items:
                print(f"\n{k.value} : {v}")
                if(k.value):
                    ip_as_bytes = ip_to_bytes(v)  # Convert IP to 4 bytes
                    python_hash = jhash(ip_as_bytes, hash_seed)  # Hash same way as data plane program
                    print(f"COMPARING: {k.value} - {python_hash}")
                    print(k.value == python_hash)
        else:
            print("-" * 28)
        time.sleep(2)
        


except KeyboardInterrupt:
    # Print the counter histogram
    # dist = b.get_table("counter")
    # for k, v in sorted(dist.items(), key=lambda item: item[0].value):
    #     print("\nDEST_PORT : %10d, COUNT : %10d" % (k.value, v.value))
    
    # Print the source counter histogram
    icmp_dist = b.get_table("counter_icmp")
    for k, v in sorted(icmp_dist.items(), key=lambda item: item[0].value):
        print("\nICMP PACKET PASS COUNT : %10d" % (v.value))

# Remove XDP programs from the device
b.remove_xdp(device, 0)