#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct ipv6_authhdr {
	struct ipv6_opt_hdr opt;
	__u16 reserved;
	__u32 spi;
	__u32 seq;
};

SEC("xdp")
int prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6_opt_hdr *ext;
	struct ipv6_authhdr *auth;
	__u64 off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

	ext = data + off;
	if ((void *)(ext + 1) > data_end)
		return XDP_ABORTED;

	auth = (struct ipv6_authhdr *)ext;
	auth->spi = bpf_htonl(0x222);
	auth->seq = bpf_htonl(1);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
