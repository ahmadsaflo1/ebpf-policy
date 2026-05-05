/*
 * policy_filter — XDP program for per-IP DDoS blocking and rate limiting.
 *
 * For each incoming IPv4 packet the program:
 *   1. Drops the packet immediately if src_ip is in block_list and the entry
 *      has not yet expired (expiry is a ktime_get_ns timestamp).
 *   2. If the IP has an entry in rate_limit_config_map, applies a per-IP
 *      token-bucket rate limiter using the configured rate (tokens/s) with
 *      burst = 2x rate. Drops the packet when the bucket is empty. If no
 *      entry exists the packet is passed without any rate limiting.
 *   3. Increments the cumulative counter in request_count so the Go agent can
 *      calculate req/s and decide whether to extend/add a block.
 *   4. Records per-packet processing latency in latency_map.
 *
 * Maps are LRU hash maps capped at 10 000 entries each.
 */
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

// Token bucket state per IP
struct rate_limit_state {
    __u64 tokens;       // available tokens
    __u64 last_refill;  // last refill timestamp
};

// Latency statistics per IP
struct latency_stats {
    __u64 total_latency_ns;  // total processing time in nanoseconds
    __u64 packet_count;      // number of packets processed
    __u64 min_latency_ns;    // minimum latency observed
    __u64 max_latency_ns;    // maximum latency observed
};

//Map 1: Tracks the number of requests and last seen time for each source IP
struct {
    __uint (type, BPF_MAP_TYPE_LRU_HASH);
    __uint (max_entries, 10000);
    __type (key, __u32);
    __type (value, struct ip_stats);
} request_count SEC(".maps");

//Map 2: block list — agent writes here for DDoS blocking
struct {
    __uint (type, BPF_MAP_TYPE_LRU_HASH);
    __uint (max_entries, 10000);
    __type (key, __u32);
    __type (value, __u64);
} block_list SEC(".maps");

// Map 3: token bucket state per IP (runtime state — tokens + last_refill)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key,   __u32);
    __type(value, struct rate_limit_state);
} rate_limit_map SEC(".maps");

// Map 4: latency statistics per IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key,   __u32);
    __type(value, struct latency_stats);
} latency_map SEC(".maps");

// Map 5: per-IP rate limit config written by Go agent (value = tokens/sec)
// Absence of an entry means no rate limiting for that IP.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key,   __u32);
    __type(value, __u64);
} rate_limit_config_map SEC(".maps");

// Token bucket — returns XDP_PASS or XDP_DROP.
// Passes immediately if no rate limit is configured for this IP.
static __always_inline int check_rate_limit(__u32 src_ip, __u64 now)
{
    __u64 *rate_ptr = bpf_map_lookup_elem(&rate_limit_config_map, &src_ip);
    if (!rate_ptr)
        return XDP_PASS;

    __u64 rate  = *rate_ptr;
    __u64 burst = rate * 2;

    struct rate_limit_state *state;
    struct rate_limit_state new_state;

    state = bpf_map_lookup_elem(&rate_limit_map, &src_ip);

    if (!state) {
        new_state.tokens      = burst - 1;
        new_state.last_refill = now;
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

// Update latency statistics
static __always_inline void update_latency(__u32 src_ip, __u64 latency_ns)
{
    struct latency_stats *stats;
    struct latency_stats new_stats;

    stats = bpf_map_lookup_elem(&latency_map, &src_ip);

    if (!stats) {
        // First packet — initialize stats
        new_stats.total_latency_ns = latency_ns;
        new_stats.packet_count = 1;
        new_stats.min_latency_ns = latency_ns;
        new_stats.max_latency_ns = latency_ns;
        bpf_map_update_elem(&latency_map, &src_ip, &new_stats, BPF_ANY);
        return;
    }

    // Update existing stats
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
    void *data = (void *)(long)ctx->data;
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

    __u32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    int action = XDP_PASS;

    // Step 1: check if IP is blocked (DDoS block)
    __u64 *blocked_until = bpf_map_lookup_elem(&block_list, &src_ip);
    if (blocked_until && *blocked_until > now) {
        return XDP_DROP;
        goto update_stats;
    }

    // Step 2: update request count for all packets (including those that will
    // be dropped) so the Go agent sees actual traffic, not just passed traffic.
    struct ip_stats *stats = bpf_map_lookup_elem(&request_count, &src_ip);
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
        stats->last_seen = now;
    } else {
        struct ip_stats new_stats = { .count = 1, .last_seen = now };
        bpf_map_update_elem(&request_count, &src_ip, &new_stats, BPF_ANY);
    }

    // Step 3: check rate limit (token bucket)
    if (check_rate_limit(src_ip, now) == XDP_DROP){
        action = XDP_DROP;
        goto update_stats;
    }

update_stats:
    {
        __u64 end_time = bpf_ktime_get_ns();
        __u64 latency = end_time - start_time;
        update_latency(src_ip, latency);
    }

    return action;
}

char _license[] SEC("license") = "GPL";
