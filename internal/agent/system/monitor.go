// Package system collects and reports system-level performance metrics
// (CPU, memory, disk, network I/O) from the agent host to the central server.
package system

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

type cpuStat struct {
	total uint64
	idle  uint64
}

type netStat struct {
	bytesSent uint64
	bytesRecv uint64
}

// Monitor collects system performance metrics
type Monitor struct {
	agentID          string
	interval         time.Duration
	lastNetStats     map[string]netStat
	lastCPUStat      cpuStat
	onMetricsCollect func(models.SystemMetrics)
}

// New creates a new system metrics monitor
func New(agentID string, interval time.Duration, callback func(models.SystemMetrics)) *Monitor {
	return &Monitor{
		agentID:          agentID,
		interval:         interval,
		lastNetStats:     make(map[string]netStat),
		onMetricsCollect: callback,
	}
}

// Start begins periodic collection of system metrics
func (m *Monitor) Start() {
	m.updateNetStats()
	m.lastCPUStat, _ = readCPUStat()

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
	current, err := readCPUStat()
	if err == nil {
		deltaTotal := current.total - m.lastCPUStat.total
		deltaIdle := current.idle - m.lastCPUStat.idle
		if deltaTotal > 0 {
			metrics.CPUPercent = 100.0 * float64(deltaTotal-deltaIdle) / float64(deltaTotal)
		}
		m.lastCPUStat = current
	}	
	// Memory usage
	memTotal, memAvail, err := readMemInfo()
	if err == nil && memTotal > 0 {
		memUsed := memTotal - memAvail
		metrics.MemoryTotalMB = memTotal / 1024 / 1024
		metrics.MemoryUsedMB = memUsed / 1024 / 1024
		metrics.MemoryPercent = 100.0 * float64(memUsed) / float64(memTotal)
	}

	// Disk usage (root partition)
	diskUsed, diskTotal, diskPercent, err := readDiskUsage("/")
	if err == nil {
		metrics.DiskUsedGB = diskUsed
		metrics.DiskTotalGB = diskTotal
		metrics.DiskPercent = diskPercent
	}

	// Network I/O (delta since last check)
	sent, recv := m.getNetworkDelta()
	metrics.NetBytesSent = sent
	metrics.NetBytesRecv = recv

	return metrics
}

// readCPUStat reads the aggregate CPU counters from /proc/stat and returns total and idle times.
func readCPUStat() (cpuStat, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuStat{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			break
		}
		var vals [8]uint64
		for i := 1; i < len(fields) && i <= 8; i++ {
			vals[i-1], _ = strconv.ParseUint(fields[i], 10, 64)
		}
		idle := vals[3] + vals[4] 
		total := vals[0] + vals[1] + vals[2] + vals[3] + vals[4] + vals[5] + vals[6] + vals[7]
		return cpuStat{total: total, idle: idle}, nil
	}
	return cpuStat{}, fmt.Errorf("cpu line not found in /proc/stat")
}

// readMemInfo reads MemTotal and MemAvailable
func readMemInfo() (total, available uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		val, e := strconv.ParseUint(fields[1], 10, 64)
		if e != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = val * 1024
		case "MemAvailable:":
			available = val * 1024
		}
		if total > 0 && available > 0 {
			break
		}
	}
	return total, available, nil
}

// readDiskUsage uses syscall.Statfs to get disk usage for the given path.
func readDiskUsage(path string) (usedGB, totalGB uint64, percent float64, err error) {
	var stat syscall.Statfs_t
	if err = syscall.Statfs(path, &stat); err != nil {
		return
	}
	total := stat.Blocks * uint64(stat.Bsize)
	avail := stat.Bavail * uint64(stat.Bsize)
	used := total - avail
	usedGB = used / 1024 / 1024 / 1024
	totalGB = total / 1024 / 1024 / 1024
	if total > 0 {
		percent = 100.0 * float64(used) / float64(total)
	}
	return
}

func (m *Monitor) updateNetStats() {
	stats, err := readNetDev()
	if err != nil {
		return
	}
	for iface, s := range stats {
		m.lastNetStats[iface] = s
	}
}

// getNetworkDelta calculates bytes sent/received since last check
func (m *Monitor) getNetworkDelta() (uint64, uint64) {
	current, err := readNetDev()
	if err != nil {
		return 0, 0
	}
	var totalSent, totalRecv uint64
	for iface, cur := range current {
		if last, ok := m.lastNetStats[iface]; ok {
			totalSent += cur.bytesSent - last.bytesSent
			totalRecv += cur.bytesRecv - last.bytesRecv
		}
		m.lastNetStats[iface] = cur
	}
	return totalSent, totalRecv
}


func readNetDev() (map[string]netStat, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stats := make(map[string]netStat)
	scanner := bufio.NewScanner(f)
	scanner.Scan() 
	scanner.Scan() 
	for scanner.Scan() {
		line := scanner.Text()
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colonIdx])
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 9 {
			continue
		}
		recv, _ := strconv.ParseUint(fields[0], 10, 64)
		sent, _ := strconv.ParseUint(fields[8], 10, 64)
		stats[iface] = netStat{bytesSent: sent, bytesRecv: recv}
	}
	return stats, nil
}
