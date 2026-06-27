// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "bpf_misc.h"
#include "cgrp_kfunc_common.h"

char _license[] SEC("license") = "GPL";

/* Prototype for all of the program trace events below:
 *
 * TRACE_EVENT(cgroup_mkdir,
 *         TP_PROTO(struct cgroup *cgrp, const char *path),
 *         TP_ARGS(cgrp, path)
 */

static struct __cgrps_kfunc_map_value *insert_lookup_cgrp(struct cgroup *cgrp)
{
	int status;

	status = cgrps_kfunc_map_insert(cgrp);
	if (status)
		return NULL;

	return cgrps_kfunc_map_value_lookup(cgrp);
}

SEC("tp_btf/cgroup_mkdir")
__failure __msg("Unreleased reference")
int BPF_PROG(cgrp_kfunc_xchg_unreleased, struct cgroup *cgrp, const char *path)
{
	struct cgroup *kptr;
	struct __cgrps_kfunc_map_value *v;

	v = insert_lookup_cgrp(cgrp);
	if (!v)
		return 0;

	kptr = bpf_kptr_xchg(&v->cgrp, NULL);
	if (!kptr)
		return 0;

	/* Kptr retrieved from map is never released. */

	return 0;
}
