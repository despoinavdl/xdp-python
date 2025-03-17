from bcc import BPF
from bcc.utils import printb

device = "lo"

# Load the eBPF program from the source file
b = BPF(src_file="xdp_prog.c")

# Load and attach the packet_handler function
fn_packet_handler = b.load_func("packet_handler", BPF.XDP)
b.attach_xdp(device, fn_packet_handler, 0)


try:
    b.trace_print()
except KeyboardInterrupt:
    # Print the counter histogram
    dist = b.get_table("counter")
    for k, v in sorted(dist.items(), key=lambda item: item[0].value):
        print("\nDEST_PORT : %10d, COUNT : %10d" % (k.value, v.value))
    
    # Print the source counter histogram
    icmp_dist = b.get_table("counter_icmp")
    for k, v in sorted(icmp_dist.items(), key=lambda item: item[0].value):
        print("\nICMP PACKET DROP COUNT : %10d" % (v.value))

# Remove XDP programs from the device
b.remove_xdp(device, 0)