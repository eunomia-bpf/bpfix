#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct download_event {
	__u32 len;
	__u8 data[1518];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} rb SEC(".maps");

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
	struct download_event *event;
	__u32 payload_len = skb->len;

	if (payload_len == 0)
		return 0;

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event)
		return 0;

	event->len = payload_len;
	bpf_skb_load_bytes(skb, 0, event->data, payload_len);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
