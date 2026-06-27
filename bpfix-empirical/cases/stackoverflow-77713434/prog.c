#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_MSG_SIZE 16383
#define TRACE_PARENT_SIZE 70

typedef __u32 u32;
typedef __u64 u64;

struct data_args_t {
	const char *buf;
};

struct char_array_value {
	char data[TRACE_PARENT_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u64);
	__type(value, struct data_args_t);
} active_read_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct char_array_value);
} leftover_buf SEC(".maps");

SEC("kretprobe/sys_read")
int syscall__probe_ret_read(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct data_args_t *read_args;
	struct char_array_value *seventy_bytes_array;
	unsigned int overrided_bytes;
	u32 key = 0;

	read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
	if (!read_args)
		return 0;

	seventy_bytes_array = bpf_map_lookup_elem(&leftover_buf, &key);
	if (!seventy_bytes_array)
		return 0;

	overrided_bytes = bpf_get_prandom_u32() & 0x3fff;
	if (overrided_bytes == 0)
		return 0;

	return bpf_probe_read_user(seventy_bytes_array->data,
				   overrided_bytes,
				   read_args->buf + MAX_MSG_SIZE);
}

char LICENSE[] SEC("license") = "GPL";
