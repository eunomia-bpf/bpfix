#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct data_args_t {
	int fd;
	const char *buf;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct data_args_t);
	__uint(max_entries, 100);
} active_read_args_map SEC(".maps");

SEC("kprobe/sys_read")
int syscall__probe_entry_read(struct pt_regs *ctx, int fd, char *buf,
			      int count)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 key = id;
	struct data_args_t data = {};

	data.fd = fd;
	data.buf = buf;
	bpf_map_update_elem(&active_read_args_map, &key, &data, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
