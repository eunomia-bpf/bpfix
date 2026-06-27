#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct custom_data {
	__u32 val1;
	__u32 val2;
	__u32 val3;
	__u32 val4;
};

SEC("tp/net/netif_receive_skb")
int net_netif_receive_skb(struct trace_event_raw_net_dev_template *args)
{
	struct sk_buff *skb = (struct sk_buff *)BPF_CORE_READ(args, skbaddr);
	unsigned char *data = BPF_CORE_READ(skb, data);
	__u32 len = BPF_CORE_READ(skb, len);
	unsigned char *data_end = data + len;
	struct custom_data *telemetry_data = (struct custom_data *)data;

	if ((unsigned char *)(telemetry_data + 1) > data_end)
		return -1;

	__u32 val1 = telemetry_data->val1;
	bpf_printk("val1: %u", val1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
