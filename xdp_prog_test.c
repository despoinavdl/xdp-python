#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/jhash.h>

#define BPF_MAP_TYPE_HASH 3

// Define the BPF hash map for counting packets based on hashed IP
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, u32);   // IP hash as the key
//     __type(value, u64); // Counter as the value
//     __uint(max_entries, 1024); // Set a larger map size if needed
// } counter_icmp SEC(".maps");


BPF_HASH(counter_icmp, u32);

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
            if (ip->protocol == IPPROTO_ICMP)
            {
                u32 key = 0;

                // Fetch current counter value or initialize it to 0
                u64 *counter_value = counter_icmp.lookup(&key);
                if (!counter_value) {
                    u64 init_value = 1;
                    counter_icmp.insert(&key, &init_value);
                    counter_value = &init_value;
                }
                
                // Increment the counter value
                (*counter_value)++;
                
                u32 key2 = jhash(&ip->daddr, sizeof(ip->daddr), HASH_SEED);
                // Fetch current counter value or initialize it to 0
                u64 *tmp_value = counter_icmp.lookup(&key2);
                if (!tmp_value) {
                    u64 init_value = ip->daddr;
                    counter_icmp.insert(&key2, &init_value);
                }

                // Return XDP_PASS to let the packet continue
                return XDP_PASS;
            }
        }
    }
    return XDP_PASS;
}
