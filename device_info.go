package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

type DeviceInfo struct {
	UserID           string   `json:"user_id"`
	OS               string   `json:"os"`
	OSVersion        string   `json:"os_version"`
	Hostname         string   `json:"hostname"`
	CPU              string   `json:"cpu"`
	CPUCores         int      `json:"cpu_cores"`
	MemoryGB         uint64   `json:"memory_gb"`
	MACAddress       string   `json:"mac_address"`
	IsVirtual        bool     `json:"is_virtual"`
	VirtualMachine   string   `json:"vm_type"`
	RunningProcesses []string `json:"running_processes"`
}

func main() {
	info := DeviceInfo{
		UserID: "siswa001",
	}

	// OS info
	info.OS = runtime.GOOS
	if hostStat, err := host.Info(); err == nil {
		info.OSVersion = hostStat.Platform + " " + hostStat.PlatformVersion
		info.Hostname = hostStat.Hostname
	}

	// CPU info
	if cpuInfo, err := cpu.Info(); err == nil && len(cpuInfo) > 0 {
		info.CPU = cpuInfo[0].ModelName
		info.CPUCores = int(cpuInfo[0].Cores)
	}

	// Memory
	if vmStat, err := mem.VirtualMemory(); err == nil {
		info.MemoryGB = vmStat.Total / 1024 / 1024 / 1024
	}

	// MAC address
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			if len(iface.HardwareAddr) > 0 {
				info.MACAddress = iface.HardwareAddr
				break
			}
		}
	}

	// Running processes
	if processes, err := process.Processes(); err == nil {
		for _, p := range processes {
			if name, err := p.Name(); err == nil {
				info.RunningProcesses = append(info.RunningProcesses, name)
			}
		}
	}

	// Detect virtualization
	info.VirtualMachine, info.IsVirtual = detectVirtualization(info.OS)

	// Output
	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		log.Fatal("Failed to marshal JSON:", err)
	}
	fmt.Println(string(jsonData))
}

func detectVirtualization(goos string) (string, bool) {
	switch goos {
	case "windows":
		return detectVirtualizationWindows()
	case "linux":
		return detectVirtualizationLinux()
	case "darwin":
		return detectVirtualizationMac()
	default:
		return "Unknown", false
	}
}

// Detect virtualization on Windows
func detectVirtualizationWindows() (string, bool) {
	cmd := exec.Command("wmic", "computersystem", "get", "model")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown", false
	}
	out := strings.ToLower(string(output))
	switch {
	case strings.Contains(out, "virtualbox"):
		return "VirtualBox", true
	case strings.Contains(out, "vmware"):
		return "VMware", true
	case strings.Contains(out, "hyper-v"):
		return "Hyper-V", true
	case strings.Contains(out, "virtual"):
		return "Generic Virtual", true
	default:
		return "Physical", false
	}
}

// Detect virtualization on Linux
func detectVirtualizationLinux() (string, bool) {
	cmd := exec.Command("systemd-detect-virt")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown", false
	}
	virt := strings.TrimSpace(string(output))
	switch virt {
	case "kvm", "qemu", "vmware", "oracle", "microsoft":
		return virt, true
	case "none":
		return "Physical", false
	default:
		return virt, true
	}
}

// Detect virtualization on macOS
func detectVirtualizationMac() (string, bool) {
	// Use system_profiler to get more reliable hardware information
	cmd := exec.Command("system_profiler", "SPHardwareDataType")
	output, err := cmd.Output()
	if err == nil {
		hardwareInfo := strings.ToLower(string(output))
		
		// Check for Mac hardware models that indicate physical hardware
		if strings.Contains(hardwareInfo, "macbook") || 
		   strings.Contains(hardwareInfo, "imac") || 
		   strings.Contains(hardwareInfo, "mac mini") || 
		   strings.Contains(hardwareInfo, "mac pro") {
			return "Physical", false
		}
		
		// Check for specific VM indicators in hardware info
		if strings.Contains(hardwareInfo, "virtualbox") || 
		   strings.Contains(hardwareInfo, "vmware") ||
		   strings.Contains(hardwareInfo, "parallels") {
			return "VM Detected", true
		}
	}
	
	// Check CPU info as a secondary method
	cpuCmd := exec.Command("sysctl", "-n", "machdep.cpu.brand_string")
	cpuInfo, err := cpuCmd.Output()
	if err == nil {
		cpuStr := strings.ToLower(string(cpuInfo))
		if strings.Contains(cpuStr, "virtualbox") || 
		   strings.Contains(cpuStr, "vmware") || 
		   strings.Contains(cpuStr, "kvm") {
			return "VM Detected", true
		}
	}
	
	// Use ioreg for a more targeted search with specific VM indicators
	ioregCmd := exec.Command("ioreg", "-l")
	ioregOut, err := ioregCmd.Output()
	if err == nil {
		ioregStr := strings.ToLower(string(ioregOut))
		
		// Search for specific VM hardware markers, avoiding partial matches
		if strings.Contains(ioregStr, "virtualbox") {
			return "VirtualBox", true
		}
		if strings.Contains(ioregStr, "vmware") {
			return "VMware", true
		}
		if strings.Contains(ioregStr, "parallels") {
			return "Parallels", true
		}
		if strings.Contains(ioregStr, "hypervisor") && !strings.Contains(ioregStr, "apple") {
			return "Virtual Machine", true
		}
	}

	// If we made it here, it's most likely physical hardware
	return "Physical", false
}