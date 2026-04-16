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

type PolicyProgram struct {
    objs PolicyObjects
    xdp  link.Link
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

    // Attach the eBPF program to the specified network interface using XDP with SKB mode for better compatibility across different environments
    p.xdp, err = link.AttachXDP(link.XDPOptions{
        Program:   p.objs.PolicyFilter,
        Interface: ifaceObj.Index,
        Flags:     link.XDPGenericMode, // Use generic mode for compatibility
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

// getKtimeNs retrieves the current kernel time in nanoseconds, which is used for timing the block duration in the eBPF program.
func getKtimeNs() (uint64, error) {
    data, err := os.ReadFile("/proc/uptime")
    if err != nil {
        return 0, err
    }

    var uptime float64
    fmt.Sscanf(string(data), "%f", &uptime)
    return uint64(uptime * 1e9), nil
}

// UnblockIP removes the specified IP address from the block list.
func (p *PolicyProgram) UnblockIP(ip net.IP) error {
    key := ipToUint32(ip)
    return p.objs.BlockList.Delete(key)
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

// Helper functions to convert between net.IP and uint32 for map keys
func ipToUint32(ip net.IP) uint32 {
    ip = ip.To4()
    return binary.BigEndian.Uint32(ip)
}

// Convert uint32 back to net.IP
func uint32ToIP(n uint32) net.IP {
    ip := make(net.IP, 4)
    binary.BigEndian.PutUint32(ip, n)
    return ip
}