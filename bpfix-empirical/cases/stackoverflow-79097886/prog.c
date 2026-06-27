#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat_entry, int dfd, struct filename *name)
{
	const char *filename = BPF_CORE_READ(name, name);

	if (filename != 0 && *filename == 't')
		return 1;
	bpf_printk("Deleting this file:%s", filename);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
