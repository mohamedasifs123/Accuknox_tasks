#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u16),
    .max_entries = 1,
};

SEC("xdp")
int drop_tcp_on_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 key = 0;
    __u16 *port;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcp = (void *)ip + sizeof(*ip);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    port = bpf_map_lookup_elem(&port_map, &key);
    if (port && tcp->dest == bpf_htons(*port)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
