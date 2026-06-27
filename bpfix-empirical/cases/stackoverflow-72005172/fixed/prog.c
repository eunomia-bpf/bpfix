/* === WRAPPER: compilation boilerplate === */
/* no extra boilerplate required */

/* === ORIGINAL CODE from SO/GH post === */

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

//#include <bpf/bpf_helpers.h>


#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bpf_htons(x) __builtin_bswap16(x)
#define __bpf_constant_htons(x) ___constant_swab16(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __bpf_htons(x) (x)
#define __bpf_constant_htons(x) (x)
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_htons(x) \
  (__builtin_constant_p(x) ? __bpf_constant_htons(x) : __bpf_htons(x))


#define trace_printk(fmt, ...)                                       \
    do {                                                         \
        char _fmt[] = fmt;                                   \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
    } while (0)

static inline int is_http(struct __sk_buff *skb, __u64 nh_off);
unsigned long long load_byte(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.byte");

SEC("classifier")
int classification(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    __u16 h_proto;
    __u64 nh_off = 0;
    nh_off = sizeof(*eth);

    if (data + nh_off > data_end) {
        return TC_ACT_OK;
    }

    h_proto = eth->h_proto;

    if (h_proto == bpf_htons(ETH_P_IP)) {
        if (is_http(skb, nh_off) == 1) {
            trace_printk("Yes! It is HTTP!\n"); // (ERROR)
        }
    }

    return TC_ACT_OK;
}

static inline int is_http(struct __sk_buff *skb, __u64 nh_off) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct iphdr *iph = data + nh_off;

    if ((void*)(iph + 1) > data_end) {
        return 0;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return 0;
    }
    __u32 tcp_hlen = 0;
    __u32 ip_hlen = 0;
    __u32 poffset = 0;
    __u32 plength = 0;
    __u32 ip_total_length = iph->tot_len;

    ip_hlen = iph->ihl << 2;

    if (ip_hlen < sizeof(*iph)) {
        return 0;
    }

    struct tcphdr *tcph = data + nh_off + sizeof(*iph);

    if ((void*)(tcph + 1) > data_end) {
        return 0;
    }

    tcp_hlen = tcph->doff << 2;

    poffset = ETH_HLEN + ip_hlen + tcp_hlen;
    plength = ip_total_length - ip_hlen - tcp_hlen;
    if (plength >= 7) {
        unsigned long p[7];
        int i = 0;
        for (i = 0; i < 7; i++) {

            p[i] = load_byte(skb, poffset + i);
        }
        if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
            return 1;
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

/* === END ORIGINAL CODE === */

/* === END ORIGINAL CODE === */
