#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("fentry/vfs_unlink")
int BPF_PROG(vfs_unlink_entry, struct mnt_idmap *arg0,
	     struct inode *arg1, struct dentry *arg2,
	     struct inode **arg3)
{
	bpf_printk("arg3: %p", arg3);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
