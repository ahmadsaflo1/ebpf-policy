// Package system collects and reports system-level performance metrics
// (CPU, memory, disk, network I/O) from the agent host via gopsutil.
package system

import (
	"log"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// Monitor collects system performance metrics
type Monitor struct {
	agentID          string
	interval         time.Duration
	lastNetStats     map[string]net.IOCountersStat
	onMetricsCollect func(models.SystemMetrics)
}

// New creates a new system metrics monitor
func New(agentID string, interval time.Duration, callback func(models.SystemMetrics)) *Monitor {
	return &Monitor{
		agentID:          agentID,
		interval:         interval,
		lastNetStats:     make(map[string]net.IOCountersStat),
		onMetricsCollect: callback,
	}
}

// Start begins periodic collection of system metrics
func (m *Monitor) Start() {
	// Initialize network stats
	m.updateNetStats()

	ticker := time.NewTicker(m.interval)
	go func() {
		for range ticker.C {
			metrics := m.collect()
			if m.onMetricsCollect != nil {
				m.onMetricsCollect(metrics)
			}
		}
	}()
	log.Printf("System monitor started with interval: %s\n", m.interval)
}

// collect gathers all system metrics
func (m *Monitor) collect() models.SystemMetrics {
	metrics := models.SystemMetrics{}

	// CPU usage
	if cpuPercent, err := cpu.Percent(time.Second, false); err == nil && len(cpuPercent) > 0 {
		metrics.CPUPercent = cpuPercent[0]
	}

	// Memory usage
	if memInfo, err := mem.VirtualMemory(); err == nil {
		metrics.MemoryPercent = memInfo.UsedPercent
		metrics.MemoryUsedMB = memInfo.Used / 1024 / 1024
		metrics.MemoryTotalMB = memInfo.Total / 1024 / 1024
	}

	// Disk usage (root partition)
	if diskInfo, err := disk.Usage("/"); err == nil {
		metrics.DiskUsedGB = diskInfo.Used / 1024 / 1024 / 1024
		metrics.DiskTotalGB = diskInfo.Total / 1024 / 1024 / 1024
		metrics.DiskPercent = diskInfo.UsedPercent
	}

	// Network I/O (delta since last check)
	netBytesSent, netBytesRecv := m.getNetworkDelta()
	metrics.NetBytesSent = netBytesSent
	metrics.NetBytesRecv = netBytesRecv

	return metrics
}

// updateNetStats refreshes the baseline network stats
func (m *Monitor) updateNetStats() {
	stats, err := net.IOCounters(true)
	if err != nil {
		return
	}

	for _, stat := range stats {
		m.lastNetStats[stat.Name] = stat
	}
}

// getNetworkDelta calculates bytes sent/received since last check
func (m *Monitor) getNetworkDelta() (uint64, uint64) {
	currentStats, err := net.IOCounters(true)
	if err != nil {
		return 0, 0
	}

	var totalBytesSent, totalBytesRecv uint64

	for _, current := range currentStats {
		if last, exists := m.lastNetStats[current.Name]; exists {
			totalBytesSent += current.BytesSent - last.BytesSent
			totalBytesRecv += current.BytesRecv - last.BytesRecv
		}
		m.lastNetStats[current.Name] = current
	}

	return totalBytesSent, totalBytesRecv
}