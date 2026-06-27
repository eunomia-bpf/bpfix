#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u32 u32;

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	unsigned long syscall_id = ctx->args[1];
	struct pt_regs *regs;
	u32 mode;
	char fmt[] = "fchmodat %d\n";

	bpf_printk("syscall_id:%d", syscall_id);
	if (syscall_id != 268)
		return 0;

	regs = (struct pt_regs *)ctx->args[0];
	mode = (u32)PT_REGS_PARM3(regs);
	if (!mode)
		return 0;

	bpf_trace_printk(fmt, sizeof(fmt), mode);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
