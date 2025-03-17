#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/jhash.h>

#define BPF_MAP_TYPE_HASH 3

// Define the BPF hash map for counting packets based on hashed IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // IP hash as the key
    __type(value, u64); // Counter as the value
    __uint(max_entries, 1024); // Set a larger map size if needed
} counter_icmp SEC(".maps");

// Seed for jhash (you can choose a different value)
#define HASH_SEED 0x12345678

// Packet handler function
int packet_handler(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)eth + sizeof(*eth) <= data_end)
    {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end)
        {
            if (ip->protocol == IPPROTO_UDP)
            {
                struct udphdr *udp = (void *)ip + sizeof(*ip);
                if ((void *)udp + sizeof(*udp) <= data_end)
                {
                    // Create a hash from the destination IP address (could also use source IP)
                    u32 key = jhash(&ip->daddr, sizeof(ip->daddr), HASH_SEED);
                    
                    // Fetch current counter value or initialize it to 0
                    u64 *counter_value = bpf_map_lookup_elem(&counter_icmp, &key);
                    if (!counter_value) {
                        u64 init_value = 0;
                        bpf_map_update_elem(&counter_icmp, &key, &init_value, BPF_ANY);
                        counter_value = &init_value;
                    }
                    
                    // Increment the counter value
                    (*counter_value)++;

                    // Return XDP_PASS to let the packet continue
                    return XDP_PASS;
                }
            }
            if (ip->protocol == IPPROTO_ICMP)
            {
                u32 key = 0;
                u64 *counter_value = bpf_map_lookup_elem(&counter_icmp, &key);
                if (!counter_value) {
                    u64 init_value = 0;
                    bpf_map_update_elem(&counter_icmp, &key, &init_value, BPF_ANY);
                    counter_value = &init_value;
                }

                // Increment the ICMP counter
                (*counter_value)++;

                // Drop the packet
                return XDP_DROP;
            }
        }
    }
    return XDP_PASS;
}
