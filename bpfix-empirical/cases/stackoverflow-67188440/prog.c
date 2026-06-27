#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, char[300]);
	__uint(max_entries, 1);
} mymap SEC(".maps");

struct execve_args {
	unsigned long long pad;
	long syscall_nr;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(struct execve_args *ctx)
{
	__u32 index = 0;
	char *value = bpf_map_lookup_elem(&mymap, &index);

	if (value) {
		const char *const first_env_value = ctx->envp[0];

		if (!first_env_value)
			return 0;
		value[0] = first_env_value[0];
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
