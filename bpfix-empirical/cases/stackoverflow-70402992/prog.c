#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct event {
	int pid;
	char cookie[90];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} my_map SEC(".maps");

SEC("kprobe/__x64_sys_recvfrom")
int bpf_prog1(struct pt_regs *ctx, int fd, const char *buf, size_t count)
{
	struct event data = { .pid = 1 };

	data.cookie[0] = buf[0];
	bpf_perf_event_output(ctx, &my_map, BPF_F_CURRENT_CPU, &data,
			      sizeof(data));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
