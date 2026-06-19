#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#define RS_PATH_LEN 16
#define RS_MMAP_INDEX_SLOTS 4
#define RS_MMAP_BASE 0x100000ULL

struct rs_mmap_pend {
    __s32 fd;
    __u32 pad;
    __u64 len;
    __u64 prot;
    __u64 flags;
};

struct rs_file_id {
    __u64 ino;
    __u64 dev;
};

struct rs_fd_key {
    __s32 pid;
    __s32 fd;
};

struct rs_fd_ref {
    char path[RS_PATH_LEN];
    struct rs_file_id fid;
};

struct rs_mmap_key {
    __s32 pid;
    __u32 pad;
    __u64 start;
};

struct rs_mmap_ref {
    char path[RS_PATH_LEN];
    __u64 start;
    __u64 end;
    __u64 prot;
    __u64 flags;
    struct rs_file_id fid;
};

struct rs_mmap_index {
    __u64 starts[RS_MMAP_INDEX_SLOTS];
    __u32 next;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u64);
    __type(value, struct rs_mmap_pend);
} ts_mmappend SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, struct rs_fd_key);
    __type(value, struct rs_fd_ref);
} ts_fd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, struct rs_mmap_key);
    __type(value, struct rs_mmap_ref);
} ts_mmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __s32);
    __type(value, struct rs_mmap_index);
} ts_mmap_index SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_mmap_ref);
} ts_mmap_scratch SEC(".maps");

static __always_inline void rs_mmap_key(__s32 pid, __u64 start,
                                        struct rs_mmap_key *out)
{
    out->pid = pid;
    out->pad = 0;
    out->start = start;
}

static __always_inline __u64 rs_range_end(__u64 start, __u64 len)
{
    __u64 end = start + len;

    if (end < start)
        return ~0ULL;
    return end;
}

static __noinline __u64 rs_mmap_index_remember(__s32 pid, __u64 start)
{
    struct rs_mmap_index *idx = bpf_map_lookup_elem(&ts_mmap_index, &pid);
    __u64 overwritten = 0;
    __u32 slot = 0;
    __u32 next_slot = 1;

    if (!start)
        return 0;
    if (!idx) {
        struct rs_mmap_index fresh = {};

        fresh.starts[0] = start;
        fresh.next = 1;
        bpf_map_update_elem(&ts_mmap_index, &pid, &fresh, BPF_ANY);
        return 0;
    }
    for (int i = 0; i < RS_MMAP_INDEX_SLOTS; i++) {
        if (idx->starts[i] == start)
            idx->starts[i] = 0;
    }
    slot = idx->next;
    if (slot >= RS_MMAP_INDEX_SLOTS)
        slot = 0;
    overwritten = idx->starts[slot];
    idx->starts[slot] = start;
    next_slot = slot + 1;
    if (next_slot >= RS_MMAP_INDEX_SLOTS)
        next_slot = 0;
    idx->next = next_slot;
    if (overwritten == start)
        return 0;
    return overwritten;
}

static __always_inline int rs_store_mmap_ref(__s32 pid, __u64 start,
                                             const struct rs_mmap_pend *p,
                                             const struct rs_fd_ref *fdref)
{
    __u32 zero = 0;
    struct rs_mmap_ref *mref = bpf_map_lookup_elem(&ts_mmap_scratch, &zero);
    struct rs_mmap_key key = {};
    __u64 overwritten;

    if (!mref || !p || !fdref || !p->len || !start)
        return 0;
    __builtin_memset(mref, 0, sizeof(*mref));
    overwritten = rs_mmap_index_remember(pid, start);
    if (overwritten) {
        struct rs_mmap_key old_key = {};

        rs_mmap_key(pid, overwritten, &old_key);
        bpf_map_delete_elem(&ts_mmap, &old_key);
    }
    rs_mmap_key(pid, start, &key);
    mref->start = start;
    mref->end = rs_range_end(start, p->len);
    mref->prot = p->prot;
    mref->flags = p->flags;
    mref->fid = fdref->fid;
    __builtin_memcpy(mref->path, fdref->path, sizeof(mref->path));
    bpf_map_update_elem(&ts_mmap, &key, mref, BPF_ANY);
    return 1;
}

SEC("xdp")
int rs_actplane_mmap_pending_merge(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *bytes = data;
    struct rs_mmap_pend *p;
    struct rs_fd_ref *ref;
    struct rs_fd_key fkey = {};
    __u64 tid;
    __u64 start;
    __s32 pid;
    __s32 fd;
    __u8 guarded;

    if ((void *)(bytes + 5) > data_end)
        return XDP_PASS;

    pid = bytes[0];
    tid = bytes[1];
    fd = bytes[2];
    guarded = bytes[3];
    start = RS_MMAP_BASE + ((__u64)bytes[4] << 12);

    p = bpf_map_lookup_elem(&ts_mmappend, &tid);
    if (!p)
        return XDP_PASS;
    if (guarded & 1) {
        // guarded path logic preserved
    }

    fd = p->fd;
    fkey.pid = pid;
    fkey.fd = fd;
    ref = bpf_map_lookup_elem(&ts_fd, &fkey);
    if (ref)
        rs_store_mmap_ref(pid, start, p, ref);
    bpf_map_delete_elem(&ts_mmappend, &tid);

    return ref ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
