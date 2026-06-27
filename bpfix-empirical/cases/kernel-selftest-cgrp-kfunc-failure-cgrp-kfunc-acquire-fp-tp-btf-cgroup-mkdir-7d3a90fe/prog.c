// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "bpf_misc.h"
#include "cgrp_kfunc_common.h"

char _license[] SEC("license") = "GPL";

SEC("tp_btf/cgroup_mkdir")
__failure __msg("arg#0 pointer type STRUCT cgroup must point")
int BPF_PROG(cgrp_kfunc_acquire_fp, struct cgroup *cgrp, const char *path)
{
	struct cgroup *acquired, *stack_cgrp = (struct cgroup *)&path;

	/* Can't invoke bpf_cgroup_acquire() on a random frame pointer. */
	acquired = bpf_cgroup_acquire((struct cgroup *)&stack_cgrp);
	if (acquired)
		bpf_cgroup_release(acquired);

	return 0;
}
