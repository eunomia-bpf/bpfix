// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

struct sched_packet {
    __u32 prev_pid;
    __u32 next_pid;
    __u64 now_ns;
    __u32 require_known_ts;
    __u32 emit_event;
};

struct runtime_event {
    __u64 ts;
    __u64 runtime_ns;
    __u32 prev_pid;
    __u32 next_pid;
};

struct run_stats {
    __u64 processed;
    __u64 passed;
    __u64 last_prev_pid;
    __u64 last_next_pid;
    __u64 last_delta;
    __u64 last_runtime;
    __u64 last_event_pid;
    __u64 last_next_ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} time_lookup SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} runtime_lookup SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct run_stats);
} stats SEC(".maps");

static __always_inline void remember_pass(__u32 prev_pid, __u32 next_pid, __u64 now_ns)
{
    __u32 zero = 0;
    struct run_stats *s = bpf_map_lookup_elem(&stats, &zero);

    if (s) {
        s->passed += 1;
        s->last_prev_pid = prev_pid;
        s->last_next_pid = next_pid;
        s->last_delta = 0;
        s->last_runtime = 0;
        s->last_event_pid = 0;
        s->last_next_ts = now_ns;
    }
    bpf_map_update_elem(&time_lookup, &next_pid, &now_ns, BPF_ANY);
}

static __always_inline void remember_runtime(__u32 prev_pid, __u32 next_pid, __u64 now_ns,
                                             __u64 delta, __u64 total)
{
    __u32 zero = 0;
    struct run_stats *s = bpf_map_lookup_elem(&stats, &zero);

    if (s) {
        s->processed += 1;
        s->last_prev_pid = prev_pid;
        s->last_next_pid = next_pid;
        s->last_delta = delta;
        s->last_runtime = total;
        s->last_event_pid = prev_pid;
        s->last_next_ts = now_ns;
    }
}

SEC("xdp")
int rs_eunomia_energy_runtime_merge(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct sched_packet) > data_end)
        return XDP_PASS;

    struct sched_packet *pkt = data;
    __u32 prev_pid = pkt->prev_pid;
    __u32 next_pid = pkt->next_pid;
    __u64 now_ns = pkt->now_ns;
    __u32 require_known_ts = pkt->require_known_ts;
    __u32 emit_event = pkt->emit_event;

    __u64 *old_ts = bpf_map_lookup_elem(&time_lookup, &prev_pid);
    if (require_known_ts & 1) {
        if (!old_ts) {
            remember_pass(prev_pid, next_pid, now_ns);
            return XDP_PASS;
        }
    }

    __u64 old_ns = *old_ts;
    if (now_ns < old_ns) {
        remember_pass(prev_pid, next_pid, now_ns);
        return XDP_PASS;
    }

    __u64 delta = now_ns - old_ns;
    __u64 total = delta;
    __u64 *current = bpf_map_lookup_elem(&runtime_lookup, &prev_pid);

    if (current)
        total += *current;

    bpf_map_update_elem(&runtime_lookup, &prev_pid, &total, BPF_ANY);

    if (emit_event & 1) {
        struct runtime_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

        if (e) {
            e->ts = now_ns;
            e->runtime_ns = delta;
            e->prev_pid = prev_pid;
            e->next_pid = next_pid;
            bpf_ringbuf_submit(e, 0);
        }
    }

    bpf_map_update_elem(&time_lookup, &next_pid, &now_ns, BPF_ANY);
    remember_runtime(prev_pid, next_pid, now_ns, delta, total);

    return XDP_DROP;
}

char _license[] SEC("license") = "Dual BSD/GPL";
