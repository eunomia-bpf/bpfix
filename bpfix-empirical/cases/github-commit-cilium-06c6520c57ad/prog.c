#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define ETH_HLEN 14
#define TC_ACT_OK 0

static __always_inline int skb_pull_data(struct __sk_buff *skb, __u32 len)
{
	return bpf_skb_pull_data(skb, len);
}

SEC("tc")
int prog(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	void *l3;
	__u32 l3_len = skb->mark & 15;

	if (data + ETH_HLEN + l3_len > data_end) {
		int err = skb_pull_data(skb, ETH_HLEN + l3_len);

		if (err)
			return TC_ACT_OK;
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;
		if (data + ETH_HLEN + l3_len > data_end)
			return TC_ACT_OK;
	}

	l3 = data + ETH_HLEN;
	return *(__u8 *)l3;
}

char LICENSE[] SEC("license") = "GPL";
