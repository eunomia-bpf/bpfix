#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_SLOTS 32

typedef __u32 u32;
typedef __u64 u64;

struct hist {
	u32 slots[MAX_SLOTS];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u64);
	__type(value, struct hist);
} scsi_hists SEC(".maps");

SEC("kprobe/blk_account_io_done")
int sync_fetch_and_add_repro(struct pt_regs *ctx)
{
	u64 hkey = 0;
	struct hist *histp;
	u64 offset;
	u32 *slotp;

	histp = bpf_map_lookup_elem(&scsi_hists, &hkey);
	if (!histp)
		return 0;

	offset = bpf_get_prandom_u32();
	offset <<= 2;
	slotp = (u32 *)((char *)histp + offset);
	__sync_fetch_and_add(slotp, 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
