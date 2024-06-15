package main

import (
    "fmt"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
    "github.com/shirou/gopsutil/process"
    "log"
    "bytes"
)

// Function to get PID by process name
func getPidByName(processName string) (int32, error) {
    processes, err := process.Processes()
    if err != nil {
        return 0, err
    }

    for _, proc := range processes {
        name, err := proc.Name()
        if err != nil {
            continue
        }
        if name == processName {
            return proc.Pid, nil
        }
    }
    return 0, fmt.Errorf("process %s not found", processName)
}

// eBPF program in C
const bpfProgram = `
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>

#define ALLOWED_PORT 4040

BPF_HASH(target_pid, u32, u32);

SEC("xdp_prog")
int xdp_filter(struct xdp_md *ctx) {
    u32 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u32 *allowed_pid = target_pid.lookup(&pid);
    if (!allowed_pid) {
        return XDP_PASS;
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)tcp + sizeof(*tcp) > data_end) {
        return XDP_PASS;
    }

    if (tcp->dest == __constant_htons(ALLOWED_PORT)) {
        return XDP_PASS;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
`

func main() {
    // Increase the limit on the number of locked memory pages
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("Failed to remove memory lock limit: %v", err)
    }

    // Get the PID of the target process
    processName := "myprocess"
    targetPid, err := getPidByName(processName)
    if err != nil {
        log.Fatalf("Failed to get PID of process %s: %v", processName, err)
    }

    fmt.Printf("Target PID: %d\n", targetPid)

    // Load the eBPF program
    spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader([]byte(bpfProgram)))
    if err != nil {
        log.Fatalf("Failed to load eBPF program: %v", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("Failed to create eBPF collection: %v", err)
    }
    defer coll.Close()

    prog := coll.Programs["xdp_filter"]
    if prog == nil {
        log.Fatalf("Program xdp_filter not found")
    }

    // Attach the eBPF program to the XDP hook
    link, err := link.AttachXDP(link.XDPOptions{
        Program:   prog,
        Interface: 0, // Change this to your network interface index
    })
    if err != nil {
        log.Fatalf("Failed to attach XDP program: %v", err)
    }
    defer link.Close()

    // Update the eBPF map with the target PID
    targetPidKey := uint32(targetPid)
    targetPidValue := uint32(1)
    err = coll.Maps["target_pid"].Put(targetPidKey, targetPidValue)
    if err != nil {
        log.Fatalf("Failed to update eBPF map: %v", err)
    }

    fmt.Println("eBPF program loaded and attached successfully.")
    fmt.Println("Press Ctrl+C to exit.")
    select {} // Wait indefinitely
}
