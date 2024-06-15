#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>

#define ALLOWED_PORT 4040

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} port_map SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("cgroup_skb/ingress")
int filter_ingress(struct __sk_buff *skb) {
    struct task_struct *task;
    char comm[16];
    __u32 key = 0;
    __u16 *port;

    // Get the current task (process)
    task = (struct task_struct *)bpf_get_current_task();

    // Read the process name (comm)
    bpf_core_read_str(&comm, sizeof(comm), task->comm);

    // Check if the process name matches "myprocess"
    if (bpf_strncmp(comm, "myprocess", sizeof("myprocess")) != 0) {
        return 1; // Allow packet for other processes
    }

    // Parse the packet to get the destination port
    void *data = (void *)(unsigned long long)skb->data;
    void *data_end = (void *)(unsigned long long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 0;
    }

    // Check if the packet is IP
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            return 0;
        }

        // Check if the packet is TCP
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if ((void *)(tcp + 1) > data_end) {
                return 0;
            }

            // Allow only if the destination port is the allowed port
            port = bpf_map_lookup_elem(&port_map, &key);
            if (port && tcp->dest == bpf_htons(*port)) {
                return 1;
            } else {
                return 0; // Drop packet if the port is not allowed
            }
        }
    }

    return 1; // Allow non-IP packets
}

SEC("cgroup_skb/egress")
int filter_egress(struct __sk_buff *skb) {
    return filter_ingress(skb);
}
