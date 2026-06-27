#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2

struct ipv4_data_t {
	__u32 pid;
	__u32 daddr;
};

SEC("kprobe/security_socket_connect")
int security_socket_connect_entry(struct pt_regs *ctx, struct socket *sock,
				  struct sockaddr *address, int addrlen)
{
	struct ipv4_data_t data4 = {};
	__u16 address_family = address->sa_family;

	if (address_family == AF_INET) {
		struct sockaddr_in *addr2 = (struct sockaddr_in *)address;

		bpf_probe_read_kernel(&data4.daddr, sizeof(data4.daddr),
				      (void *)((long)addr2->sin_addr.s_addr));
	}
	return data4.daddr;
}

char LICENSE[] SEC("license") = "GPL";
