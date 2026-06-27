#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct sock_info {
	struct sockaddr addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} connections SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept4(int fd, struct sockaddr *upeer_sockaddr,
		      int *upeer_addrlen, int flags)
{
	struct sock_info *iad;

	iad = bpf_ringbuf_reserve(&connections, sizeof(*iad), 0);
	if (!iad)
		return 0;

	bpf_probe_read(&iad->addr, sizeof(struct sockaddr), upeer_sockaddr);
	bpf_ringbuf_submit(iad, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
