/*
 * policy_filter — XDP program for per-IP DDoS blocking and rate limiting,
 *                 scoped to a configurable set of protected TCP/UDP ports.
 *
 * Packet processing pipeline:
 *   1. Non-IPv4 packets are passed through immediately (no tracking).
 *   2. Non-TCP/UDP packets (ICMP, IGMP, etc.) are passed through immediately
 *      without being recorded in any DDoS statistics.
 *   3. The destination port is extracted from the TCP or UDP header and looked
 *      up in protected_ports. If the port is not listed, the packet is passed
 *      through without any tracking or enforcement.
 *   4. Drops the packet immediately if src_ip is in block_list and the entry
 *      has not yet expired (expiry is a ktime_get_ns timestamp).
 *   5. If the IP has an entry in rate_limit_config_map, applies a per-IP
 *      token-bucket rate limiter using the configured rate (tokens/s) with
 *      burst = 2× rate. Drops the packet when the bucket is empty. If no
 *      entry exists the packet is passed without any rate limiting.
 *   6. Increments the cumulative counter in request_count so the Go agent can
 *      calculate req/s and decide whether to extend/add a block.
 *   7. Records per-packet processing latency in latency_map.
 *
 * Protected ports are managed at runtime via the Go agent helpers
 * AddProtectedPort and RemoveProtectedPort in internal/agent/ebpf/loader.go.
 * By default ports 80, 443, and 8080 are registered on startup.
 *
 * All maps except protected_ports are LRU hash maps capped at 10 000 entries.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
struct ip_stats {
    __u64 count;
    __u64 last_seen;
};

struct rate_limit_state {
    __u64 tokens;
    __u64 last_refill;
};

struct latency_stats {
    __u64 total_latency_ns;
    __u64 packet_count;
    __u64 min_latency_ns;
    __u64 max_latency_ns;
};

// Map 1: per-IP packet counters (for req/s calculation by the Go agent)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct ip_stats);
} request_count SEC(".maps");

// Map 2: DDoS block list — src IP → expiry timestamp (ktime_get_ns)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} block_list SEC(".maps");

// Map 3: token bucket runtime state per IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key,   __u32);
    __type(value, struct rate_limit_state);
} rate_limit_map SEC(".maps");

// Map 4: per-IP latency statistics
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key,   __u32);
    __type(value, struct latency_stats);
} latency_map SEC(".maps");

// Map 5: per-IP rate limit config written by Go agent (value = tokens/sec)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key,   __u32);
    __type(value, __u64);
} rate_limit_config_map SEC(".maps");

// Map 6: set of TCP/UDP destination ports subject to DDoS enforcement.
// Key = port number in host byte order; value = 1 (present = protected).
// Managed at runtime by the Go agent via AddProtectedPort / RemoveProtectedPort.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,   __u16);
    __type(value, __u8);
} protected_ports SEC(".maps");

// Token bucket — returns XDP_PASS or XDP_DROP.
// Returns XDP_PASS immediately if no rate limit is configured for this IP.
static __always_inline int check_rate_limit(__u32 src_ip, __u64 now)
{
    __u64 *rate_ptr = bpf_map_lookup_elem(&rate_limit_config_map, &src_ip);
    if (!rate_ptr)
        return XDP_PASS;

    __u64 rate  = *rate_ptr;
    __u64 burst = rate * 2;

    struct rate_limit_state *state = bpf_map_lookup_elem(&rate_limit_map, &src_ip);

    if (!state) {
        struct rate_limit_state new_state = {
            .tokens      = burst - 1,
            .last_refill = now,
        };
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_state, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed    = now - state->last_refill;
    __u64 new_tokens = (elapsed * rate) / 1000000000ULL;

    if (new_tokens > 0) {
        state->tokens += new_tokens;
        if (state->tokens > burst)
            state->tokens = burst;
        state->last_refill = now;
    }

    if (state->tokens > 0) {
        state->tokens--;
        return XDP_PASS;
    }

    return XDP_DROP;
}

static __always_inline void update_latency(__u32 src_ip, __u64 latency_ns)
{
    struct latency_stats *stats = bpf_map_lookup_elem(&latency_map, &src_ip);

    if (!stats) {
        struct latency_stats new_stats = {
            .total_latency_ns = latency_ns,
            .packet_count     = 1,
            .min_latency_ns   = latency_ns,
            .max_latency_ns   = latency_ns,
        };
        bpf_map_update_elem(&latency_map, &src_ip, &new_stats, BPF_ANY);
        return;
    }

    stats->total_latency_ns += latency_ns;
    stats->packet_count++;

    if (latency_ns < stats->min_latency_ns)
        stats->min_latency_ns = latency_ns;

    if (latency_ns > stats->max_latency_ns)
        stats->max_latency_ns = latency_ns;
}

SEC("xdp")
int policy_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u64 start_time = bpf_ktime_get_ns();

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

    // Only process TCP and UDP — pass all other protocols (ICMP, IGMP, etc.)
    // through immediately without recording them in any DDoS statistics.
    __u8 protocol = ip->protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Extract the destination port from the TCP or UDP header.
    // Uses ip+1 which points past the fixed 20-byte IP header; packets with
    // IP options and a payload smaller than the transport header are dropped
    // safely by the bounds check below.
    __u16 dst_port;
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        dst_port = bpf_ntohs(tcp->dest);
    } else {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dst_port = bpf_ntohs(udp->dest);
    }

    // Only apply DDoS logic to ports listed in protected_ports.
    // All other ports are passed through without any tracking.
    __u8 *is_protected = bpf_map_lookup_elem(&protected_ports, &dst_port);
    if (!is_protected)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 now    = bpf_ktime_get_ns();
    int   action = XDP_PASS;

    // Step 1: check if src IP is currently blocked
    __u64 *blocked_until = bpf_map_lookup_elem(&block_list, &src_ip);
    if (blocked_until && *blocked_until > now) {
        action = XDP_DROP;
        goto update_stats;
    }

    // Step 2: increment request counter so the Go agent can compute req/s
    {
        struct ip_stats *stats = bpf_map_lookup_elem(&request_count, &src_ip);
        if (stats) {
            __sync_fetch_and_add(&stats->count, 1);
            stats->last_seen = now;
        } else {
            struct ip_stats new_stats = { .count = 1, .last_seen = now };
            bpf_map_update_elem(&request_count, &src_ip, &new_stats, BPF_ANY);
        }
    }

    // Step 3: token-bucket rate limit
    if (check_rate_limit(src_ip, now) == XDP_DROP) {
        action = XDP_DROP;
        goto update_stats;
    }

update_stats:
    {
        __u64 latency = bpf_ktime_get_ns() - start_time;
        update_latency(src_ip, latency);
    }

    return action;
}

char _license[] SEC("license") = "GPL";
