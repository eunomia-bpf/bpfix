#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

typedef __u32 u32;
typedef __u64 u64;

enum Route__RouteAction__HashPolicy__PolicySpecifierCase {
	ROUTE__ROUTE_ACTION__HASH_POLICY__POLICY_SPECIFIER_HEADER = 1,
};

struct ProtobufCMessage {
	u64 descriptor;
	u64 n_unknown_fields;
	u64 unknown_fields;
};

struct Route__RouteAction__HashPolicy {
	struct ProtobufCMessage base;
	enum Route__RouteAction__HashPolicy__PolicySpecifierCase policy_specifier_case;
};

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int scalar_policy_repro(void *ctx)
{
	u64 raw = bpf_get_prandom_u32();
	struct Route__RouteAction__HashPolicy *hash_policy;

	if (!raw)
		return 0;

	hash_policy = (void *)raw;
	if (hash_policy->policy_specifier_case ==
	    ROUTE__ROUTE_ACTION__HASH_POLICY__POLICY_SPECIFIER_HEADER)
		return 1;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
