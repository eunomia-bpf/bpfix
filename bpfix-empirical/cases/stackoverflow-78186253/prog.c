#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define TCP_PORT_HTTP 8000

SEC("xdp")
int xdp_search_http_request(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)eth + sizeof(*eth);
	if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP)
		return XDP_PASS;

	struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
	if ((void *)(tcp + 1) > data_end ||
	    tcp->dest != bpf_htons(TCP_PORT_HTTP))
		return XDP_PASS;

	unsigned char *payload = (unsigned char *)tcp + tcp->doff * 4;
	if ((void *)(payload + 1) > data_end)
		return XDP_PASS;

	if (payload[64] == 'c')
		return XDP_DROP;
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
