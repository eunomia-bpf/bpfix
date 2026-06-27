#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
int nat_socket_filter(struct __sk_buff *skb)
{
	bpf_l4_csum_replace(skb, 0, 0, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
