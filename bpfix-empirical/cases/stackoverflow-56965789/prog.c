#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

SEC("xdp")
int xdp_parse_ip_direct(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u64 nh_off = sizeof(*eth);

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph2 = (void *)(sizeof(*eth) + nh_off);

		return iph2->protocol;
	}
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
