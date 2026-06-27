#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define ETH_FRAME_LEN 1514

typedef __u32 u32;
typedef __u8 u8;

struct packet {
	u32 len;
	u8 data[1516];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} packets SEC(".maps");

SEC("tc")
int skb_load_bytes_len_repro(struct __sk_buff *skb)
{
	struct packet *valp;
	u32 dns_packet_len;

	valp = bpf_ringbuf_reserve(&packets, sizeof(*valp), 0);
	if (!valp)
		return 0;

	dns_packet_len = skb->len;
	if (dns_packet_len > 0 && dns_packet_len < ETH_FRAME_LEN) {
		valp->len = dns_packet_len;
		bpf_skb_load_bytes(skb, 0, valp->data, dns_packet_len);
	}

	bpf_ringbuf_discard(valp, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
