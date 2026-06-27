#define __TARGET_ARCH_x86 1
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct data_t {
    char **argv;
};

SEC("tp/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct data_t data = {};
    char *arg = 0;

    bpf_probe_read_user_str(&arg, sizeof(arg), (void *)ctx->args[1]);
    data.argv = (char **)ctx->args[2];
    data.argv[0] = arg;
    return 0;
}

char _license[] SEC("license") = "GPL";
