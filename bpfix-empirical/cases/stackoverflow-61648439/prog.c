#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800

SEC("kprobe/ip_forward_finish")
int ip_forward_finish_entry(struct pt_regs *ctx, struct net *net,
			    struct sock *sk, struct sk_buff *skb)
{
	__u16 proto = 0;

	bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
	if (proto != __builtin_bswap16(ETH_P_IP))
		return 0;
	return skb->len;
}

char LICENSE[] SEC("license") = "GPL";
