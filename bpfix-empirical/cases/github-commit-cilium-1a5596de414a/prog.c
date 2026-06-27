#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define XDP_PASS 2
#define LB_MAGLEV_LUT_SIZE 16381

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, LB_MAGLEV_LUT_SIZE);
	__type(key, __u32);
	__type(value, __u16);
} backend_ids SEC(".maps");

static __always_inline __u16 map_array_get_16(const __u16 *array, __u32 index,
					      const __u32 limit)
{
	__u16 datum = 0;

	asm volatile("%[index] <<= 1\n\t"
		     "if %[index] >= %[limit] goto +1\n\t"
		     "%[array] += %[index]\n\t"
		     "%[datum] = *(u16 *)(%[array] + 0)\n\t"
		     : [datum]"=r"(datum)
		     : [limit]"i"(limit), [array]"r"(array), [index]"r"(index)
		     :);

	return datum;
}

SEC("xdp")
int prog(struct xdp_md *ctx)
{
	__u32 index = ctx->rx_queue_index % LB_MAGLEV_LUT_SIZE;
	__u32 zero = 0;
	__u16 *ids;

	ids = bpf_map_lookup_elem(&backend_ids, &zero);
	if (!ids)
		return XDP_PASS;

	return map_array_get_16(ids, index, LB_MAGLEV_LUT_SIZE);
}

char LICENSE[] SEC("license") = "GPL";
