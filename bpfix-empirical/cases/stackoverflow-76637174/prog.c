/* === WRAPPER: compilation boilerplate === */
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef __SO_GH_VERIFIED_STDINT_TYPES
#define __SO_GH_VERIFIED_STDINT_TYPES 1
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;
typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef __s8 int8_t;
typedef __s16 int16_t;
typedef __s32 int32_t;
typedef __s64 int64_t;
#endif

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

#ifndef __section
#define __section(name) SEC(name)
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

#ifndef memcpy
#define memcpy __builtin_memcpy
#endif

#ifndef memset
#define memset __builtin_memset
#endif

#ifndef memmove
#define memmove __builtin_memmove
#endif

#ifndef __constant_ntohs
#define __constant_ntohs(x) ((__u16)__builtin_bswap16((__u16)(x)))
#endif

#ifndef __constant_htons
#define __constant_htons(x) ((__u16)__builtin_bswap16((__u16)(x)))
#endif

#ifndef ___constant_swab16
#define ___constant_swab16(x) ((__u16)__builtin_bswap16((__u16)(x)))
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC (-1)
#endif

#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#endif

#ifndef XDP_DROP
#define XDP_DROP 1
#endif

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#ifndef XDP_TX
#define XDP_TX 3
#endif

#ifndef XDP_REDIRECT
#define XDP_REDIRECT 4
#endif

#ifndef PIN_GLOBAL_NS
#define PIN_GLOBAL_NS 2
#endif

#ifndef csum_diff
#define csum_diff bpf_csum_diff
#endif

#ifndef skb_store_bytes
#define skb_store_bytes bpf_skb_store_bytes
#endif

#ifndef l3_csum_replace
#define l3_csum_replace bpf_l3_csum_replace
#endif

#ifndef l4_csum_replace
#define l4_csum_replace bpf_l4_csum_replace
#endif

#ifndef redirect
#define redirect bpf_redirect
#endif

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

#ifndef size_key
#define size_key key_size
#endif

#ifndef size_value
#define size_value value_size
#endif

#ifndef max_elem
#define max_elem max_entries
#endif

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 map_flags;
    __u32 pinning;
};

#ifndef bpf_printk
#define bpf_printk(fmt, ...)                                                       ({                                                                                 char ____fmt[] = fmt;                                                          bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 })
#endif

/* === END WRAPPER BOILERPLATE === */

/* === ORIGINAL CODE from SO/GH post === */

#define KBUILD_MODNAME "xdp_nvme_drop"
static inline int parse_ipv4(void *data, uint64_t nh_off, void *data_end) {
struct iphdr *iph = data + nh_off;
if (data + nh_off + sizeof(struct iphdr) > data_end)
return 0;
return iph->protocol;
}
static inline int parse_ipv6(void *data, uint64_t nh_off, void *data_end) {
struct ipv6hdr *ip6h = data + nh_off;
if (data + nh_off + sizeof(struct ipv6hdr) > data_end)
return 0;
return ip6h->nexthdr;
}
//static uint64_t zeroes[1024];
SEC("xdp")
int nvme_drop(struct xdp_md *ctx) {
void* data_end = (void*)(long)ctx->data_end;
void* data = (void*)(long)ctx->data;
uint64_t total = data_end-data;
struct ethhdr *eth = data;
uint16_t h_proto;
uint32_t cur = 0;
struct tcphdr *tcph;
uint32_t i;
int nbzeros = 0;
bool found = 0;
cur = sizeof(*eth);
if (data + cur > data_end)
return XDP_PASS;
h_proto = eth->h_proto;
if (h_proto == bpf_htons(ETH_P_IP)) {
h_proto = parse_ipv4(data, cur, data_end);
cur += sizeof(struct iphdr);
} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
h_proto = parse_ipv6(data, cur, data_end);
cur += sizeof(struct ipv6hdr);
} else {
return XDP_PASS;
}
if (cur > 100)
return XDP_PASS;
if (h_proto != IPPROTO_TCP)
return XDP_PASS;
if (data + cur + sizeof(*tcph) > data_end)
return XDP_PASS;
tcph = data + cur;
if (tcph->doff > 10)
return XDP_PASS;
if (data + cur + tcph->doff * 4 > data_end)
return XDP_PASS;
cur += tcph->doff * 4;
if (tcph->dest != 4420)
return XDP_PASS;
if (cur > total || cur > 100)
return XDP_PASS;
nbzeros = 0;
for (i = cur; data+i < data_end; i++) {
if (*((uint8_t*)(data+i)) == 0 && !found) {
nbzeros++;
} else {
found = true;
break;
}
}
if (found && nbzeros > 50) {
bpf_printk("found nvme pdu tail seq=%u\n", bpf_ntohs(tcph->seq));
}
return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

/* === END ORIGINAL CODE === */
