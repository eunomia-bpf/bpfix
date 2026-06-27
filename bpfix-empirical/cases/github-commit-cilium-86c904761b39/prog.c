#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("cgroup/connect6")
int prog(struct bpf_sock_addr *ctx)
{
	__u64 word = *(__u64 *)&ctx->user_ip6[1];

	return word ? 1 : 0;
}

char LICENSE[] SEC("license") = "GPL";
