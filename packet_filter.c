#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/in.h>

#define IP_TO_BLOCK 0xC0A80001  // Replace with the IP you want to block (e.g., 192.168.0.1)

struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};

SEC("xdp")
int xdp_program(struct xdp_md *ctx) {
    u32 key = 0;
    u64 *value;

    // Get packet data
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) {
        return XDP_DROP;
    }

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        return XDP_DROP;
    }

    // Check if the packet is IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Check if the source IP matches the one to block
    if (ip->saddr == __constant_htonl(IP_TO_BLOCK)) {
        // Drop the packet
        return XDP_DROP;
    }

    // Log the packet (increment counter)
    value = bpf_map_lookup_elem(&packet_count, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
