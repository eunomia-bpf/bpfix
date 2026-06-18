// SPDX-License-Identifier: GPL-2.0
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define CONTENTION_NONE 0u
#define CONTENTION_SATURATION 1u
#define CONTENTION_CPUSET_LIMITED 2u
#define SCHED_SWITCH_SATURATION_THRESH_HZ 2000u
#define ALLOWED_CPUS_LIMITED_THRESH 4u
#define RATE_WINDOW_NS 1000000000ULL

struct cpu_switch_slot {
    __u64 window_start_ns;
    __u32 switches_in_window;
    __u32 cpu_seen_mask;
};

struct cpu_contention_state {
    __u64 timestamp_ns;
    __u32 sched_switch_rate;
    __u32 allowed_cpus;
    __u8 contention_type;
    __u8 pad[7];
};

struct cpu_observer_config {
    __u32 target_pid;
    __u32 saturation_thresh_hz;
    __u32 cpuset_limited_thresh_cpus;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cpu_observer_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct cpu_switch_slot);
} percpu_slot_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_MMAPABLE);
    __type(key, __u32);
    __type(value, struct cpu_contention_state);
} state_map SEC(".maps");

static __always_inline __u32 popcount32(__u32 value)
{
    __u32 count = 0;
#pragma unroll
    for (int bit = 0; bit < 32; bit++)
        count += (value >> bit) & 1u;
    return count;
}

SEC("tp/sched/sched_switch")
int rs_nccl_cpu_observer_slot_merge(struct trace_event_raw_sched_switch *ctx)
{
    __u32 zero = 0;
    struct cpu_observer_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return 0;

    __u32 target_pid = cfg->target_pid;
    if (target_pid == 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 cur_tgid = (__u32)(pid_tgid >> 32);
    pid_t prev_pid = ctx->prev_pid;
    pid_t next_pid = ctx->next_pid;
    int relevant = (cur_tgid == target_pid) ||
                   ((__u32)prev_pid == target_pid) ||
                   ((__u32)next_pid == target_pid);
    if (!relevant)
        return 0;

    __u64 now_ns = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 cpu_bit = cpu < 32u ? (1u << cpu) : 0u;
    __u32 slot_key = target_pid;
    struct cpu_switch_slot *slot = bpf_map_lookup_elem(&percpu_slot_map, &slot_key);

    if (prev_pid < 0) {
        if (!slot)
            return 0;
        slot->cpu_seen_mask |= cpu_bit;
    }

    __u64 elapsed = now_ns - slot->window_start_ns;
    if (elapsed >= RATE_WINDOW_NS) {
        __u64 duration_ns = elapsed ?: 1;
        __u64 rate64 = ((__u64)slot->switches_in_window * RATE_WINDOW_NS) / duration_ns;
        __u32 rate = rate64 > 0xffffffffULL ? 0xffffffffU : (__u32)rate64;
        __u32 allowed = popcount32(slot->cpu_seen_mask);
        __u32 sat_thresh = cfg->saturation_thresh_hz ?: SCHED_SWITCH_SATURATION_THRESH_HZ;
        __u32 cpuset_thresh = cfg->cpuset_limited_thresh_cpus ?: ALLOWED_CPUS_LIMITED_THRESH;
        __u8 ctype = CONTENTION_NONE;

        if (allowed <= cpuset_thresh)
            ctype = CONTENTION_CPUSET_LIMITED;
        else if (rate >= sat_thresh)
            ctype = CONTENTION_SATURATION;

        struct cpu_contention_state state = {
            .timestamp_ns = now_ns,
            .sched_switch_rate = rate,
            .allowed_cpus = allowed,
            .contention_type = ctype,
        };
        bpf_map_update_elem(&state_map, &zero, &state, BPF_ANY);

        slot->window_start_ns = now_ns;
        slot->switches_in_window = 1;
        slot->cpu_seen_mask = cpu_bit;
    } else {
        slot->switches_in_window += 1;
        slot->cpu_seen_mask |= cpu_bit;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
