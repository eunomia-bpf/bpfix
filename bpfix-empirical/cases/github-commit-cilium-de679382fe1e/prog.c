#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/* L3-only Cilium devices model ETH_HLEN as zero even though ethhdr is 14 bytes. */
#define ETH_HLEN 0

struct ethhdr_like {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	unsigned short h_proto;
};

SEC("classifier")
int l3_device_zero_eth_check(struct __sk_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr_like *eth = data;
	unsigned char first_dest_octet;

	if ((void *)eth + ETH_HLEN > data_end)
		return 0;

	first_dest_octet = eth->h_dest[0];
	return first_dest_octet;
}

char LICENSE[] SEC("license") = "GPL";
