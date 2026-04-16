#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


// Simple rate-limiting XDP program that tracks the number of requests from each IP address
struct ip_stats {
    __u64 count;
    __u64 last_seen;
};

//Map 1: Tracks the number of requests and last seen time for each source IP
struct {
    __uint (type, BPF_MAP_TYPE_LRU_HASH);
    __uint (max_entries, 10000);
    __type (key, __u32);
    __type (value, struct ip_stats);
} request_count SEC(".maps");

//Map 2: Tracks blocked IP addresses and their expiration times
struct {
    __uint (type, BPF_MAP_TYPE_LRU_HASH);
    __uint (max_entries, 10000);
    __type (key, __u32);
    __type (value, __u64);
} block_list SEC(".maps");


SEC("xdp")
int policy_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    // Check if the source IP is currently blocked
    __u64 *blocked_until = bpf_map_lookup_elem(&request_count, &src_ip);
    if (blocked_until && *blocked_until > now) {
        return XDP_DROP;
    }

    // Update request count and last seen time for the source IP
    struct ip_stats *stats = bpf_map_lookup_elem(&request_count, &src_ip);
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
        stats->last_seen = now;
    } else {
        struct ip_stats new_stats = { .count = 1, .last_seen = now };
        bpf_map_update_elem(&request_count, &src_ip, &new_stats, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
