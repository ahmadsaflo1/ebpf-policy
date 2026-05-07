// Package ebpf loads the compiled eBPF/XDP policy program onto a network
// interface and exposes helpers for managing the block list, rate-limit state,
// and per-IP request counters maintained by the kernel program.
package ebpf

import (
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "time"
    "os"

    "github.com/cilium/ebpf/link"
)

// PolicyProgram wraps the loaded eBPF objects and the XDP link attached to
// the network interface. Use Load to create one; call Close when done.
type PolicyProgram struct {
	objs PolicyObjects
	xdp  link.Link
}

// RateLimitState mirrors the kernel-space rate_limit_state struct stored in
// the rate_limit_map BPF map.
type RateLimitState struct {
    Tokens     uint64
    LastRefill uint64
}

// LatencyStats mirrors the kernel-space latency_stats struct stored in the
// latency_map BPF map.
type LatencyStats struct {
    TotalLatencyNs uint64
    PacketCount    uint64
    MinLatencyNs   uint64
    MaxLatencyNs   uint64
}

// Load loads the eBPF program and attaches it to the specified network interface.
func Load(iface string) (*PolicyProgram, error) {
    p := &PolicyProgram{}

    if err := LoadPolicyObjects(&p.objs, nil); err != nil {
        return nil, fmt.Errorf("Failed to load eBPF-Objects: %w", err)
    }

    ifaceObj, err := net.InterfaceByName(iface)
    if err != nil {
        return nil, fmt.Errorf("Failed to get interface by name %s: %w", iface, err)
    }

    p.xdp, err = link.AttachXDP(link.XDPOptions{
        Program:   p.objs.PolicyFilter,
        Interface: ifaceObj.Index,
        Flags:     link.XDPGenericMode, // generic mode for broader driver compatibility
    })
    if err != nil {
        return nil, fmt.Errorf("Failed to attach XDP program: %w", err)
    }

    log.Printf("Successfully loaded eBPF program on interface %s (index %d)\n", iface, ifaceObj.Index)
    return p, nil
}

// Close detaches the eBPF program and closes all associated resources.
func (p *PolicyProgram) Close() {
    if p.xdp != nil {
        p.xdp.Close()
    }
    p.objs.Close()
    log.Println("Successfully unloaded eBPF program and closed resources")
}

// BlockIP adds the specified IP address to the block list with a duration for how long it should be blocked.
func (p *PolicyProgram) BlockIP(ip net.IP, duration time.Duration) error {
    key := ipToUint32(ip)
    
    ktimeNs, err := getKtimeNs()
    if err != nil {
        return fmt.Errorf("Failed to get ktime in nanoseconds: %w", err)
    }
    
    blockedUntil := ktimeNs + uint64(duration.Nanoseconds())
    return p.objs.BlockList.Put(key, blockedUntil)
}


// IsBlocked checks if an IP address is currently blocked
func(p *PolicyProgram) IsBlocked(ip net.IP) bool {
    key := ipToUint32(ip)

    var blockedUntil uint64
    err := p.objs.BlockList.Lookup(key, &blockedUntil)
    if err != nil {
        return false
    }

    ktimeNs, err := getKtimeNs()
    if err != nil {
        return false
    }

    return ktimeNs < blockedUntil
}

// UnblockIP removes the specified IP address from the block list.
func (p *PolicyProgram) UnblockIP(ip net.IP) error {
    key := ipToUint32(ip)
    return p.objs.BlockList.Delete(key)
}

// SetRateLimit writes a per-IP token-bucket rate into rate_limit_config_map.
// The eBPF program will enforce ratePerSec tokens/s with burst = 2×ratePerSec
// for this IP. Calling again with a different rate updates it in place.
func (p *PolicyProgram) SetRateLimit(ip net.IP, ratePerSec uint64) error {
    key := ipToUint32(ip)
    return p.objs.RateLimitConfigMap.Put(key, ratePerSec)
}

// RemoveRateLimit removes the rate limit config for an IP and clears its
// token bucket state so it starts fresh if re-added later.
func (p *PolicyProgram) RemoveRateLimit(ip net.IP) error {
    key := ipToUint32(ip)
    // Ignore not-found errors — entry may never have been added.
    _ = p.objs.RateLimitConfigMap.Delete(key)
    _ = p.objs.RateLimitMap.Delete(key)
    return nil
}

// GetAllStats retrieves all IP addresses and their corresponding counts from the request count map.
func (p *PolicyProgram) GetAllStats() (map[string]uint64, error) {
    stats := make(map[string]uint64)

    var key   uint32
    var value PolicyIpStats  
    iter := p.objs.RequestCount.Iterate()

    for iter.Next(&key, &value) {
        ip := uint32ToIP(key)
        stats[ip.String()] = value.Count
    }

    return stats, iter.Err()
}

// GetRateLimitStats returns the current token bucket state for an IP.
func (p *PolicyProgram) GetRateLimitStats(ip net.IP) (*RateLimitState, error) {
    key := ipToUint32(ip)

    var state RateLimitState
    err := p.objs.RateLimitMap.Lookup(key, &state)
    if err != nil {
        // IP not found — not rate limited yet
        return nil, nil
    }

    return &state, nil
}

// IsRateLimited checks if an IP is currently rate limited (no tokens left).
func (p *PolicyProgram) IsRateLimited(ip net.IP) bool {
    state, err := p.GetRateLimitStats(ip)
    if err != nil || state == nil {
        return false
    }
    return state.Tokens == 0
}

// GetLatencyStats returns latency statistics for an IP
func (p *PolicyProgram) GetLatencyStats(ip net.IP) (*LatencyStats, error) {
    key := ipToUint32(ip)

    var stats LatencyStats
    err := p.objs.LatencyMap.Lookup(key, &stats)
    if err != nil {
        // IP not found — no latency data yet
        return nil, nil
    }

    return &stats, nil
}

// GetAllLatencyStats retrieves latency stats for all IPs
func (p *PolicyProgram) GetAllLatencyStats() (map[string]*LatencyStats, error) {
    result := make(map[string]*LatencyStats)

    var key uint32
    var stats LatencyStats
    iter := p.objs.LatencyMap.Iterate()

    for iter.Next(&key, &stats) {
        ip := uint32ToIP(key)
        statsCopy := stats  // Make a copy to avoid pointer issues
        result[ip.String()] = &statsCopy
    }

    return result, iter.Err()
}

// GetAvgLatency calculates average latency for an IP in microseconds
func (stats *LatencyStats) GetAvgLatencyUs() int64 {
    if stats.PacketCount == 0 {
        return 0
    }
    return int64(stats.TotalLatencyNs) / int64(stats.PacketCount) / 1000
}

// GetMinLatencyUs returns minimum latency in microseconds
func (stats *LatencyStats) GetMinLatencyUs() int64 {
    return int64(stats.MinLatencyNs) / 1000
}

// GetMaxLatencyUs returns maximum latency in microseconds
func (stats *LatencyStats) GetMaxLatencyUs() int64 {
    return int64(stats.MaxLatencyNs) / 1000
}

// AddProtectedPort registers a TCP/UDP destination port for DDoS enforcement.
// Packets to ports not in this map are passed through without any tracking.
func (p *PolicyProgram) AddProtectedPort(port uint16) error {
	flag := uint8(1)
	return p.objs.ProtectedPorts.Put(port, flag)
}

// RemoveProtectedPort removes a port from DDoS enforcement.
// After removal, traffic to that port is no longer tracked or blocked.
func (p *PolicyProgram) RemoveProtectedPort(port uint16) error {
	return p.objs.ProtectedPorts.Delete(port)
}

// GetProtectedPorts returns all ports currently registered for DDoS enforcement.
func (p *PolicyProgram) GetProtectedPorts() ([]uint16, error) {
	var ports []uint16
	var key, nextKey uint16
	var flag uint8

	err := p.objs.ProtectedPorts.NextKey(nil, &key)
	for err == nil {
		if lookupErr := p.objs.ProtectedPorts.Lookup(key, &flag); lookupErr == nil {
			ports = append(ports, key)
		}
		err = p.objs.ProtectedPorts.NextKey(key, &nextKey)
		key = nextKey
	}

	return ports, nil
}

// getKtimeNs returns the kernel monotonic time in nanoseconds by reading
// /proc/uptime, matching the bpf_ktime_get_ns() clock used by the XDP program
// to store block-expiry timestamps in block_list.
func getKtimeNs() (uint64, error) {
    data, err := os.ReadFile("/proc/uptime")
    if err != nil {
        return 0, err
    }

    var uptime float64
    fmt.Sscanf(string(data), "%f", &uptime)
    return uint64(uptime * 1e9), nil
}

// ipToUint32 converts a net.IP to a uint32 for use as an eBPF map key.
// The kernel stores src_ip = ip->saddr (network byte order) directly as the
// map key, so on little-endian x86 the bytes must be interpreted as
// little-endian — equivalent to htonl in C.
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.LittleEndian.Uint32(ip)
}

// uint32ToIP converts an eBPF map key back to a net.IP.
// Reverses ipToUint32: uses little-endian so the bytes come out in network
// order — equivalent to ntohl in C.
func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}