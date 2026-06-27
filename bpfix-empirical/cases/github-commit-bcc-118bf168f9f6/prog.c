#define SEC(NAME) __attribute__((section(NAME), used))

typedef unsigned short __u16;

struct __sk_buff {
    unsigned int len;
};

const volatile int filter_ports_len = 32;
const volatile __u16 filter_ports[16] = {};

static __attribute__((always_inline)) inline int filter_port(__u16 port)
{
    int i;

    if (filter_ports_len == 0)
        return 0;

    for (i = 0; i < filter_ports_len; i++) {
        if (port == filter_ports[i])
            return 0;
    }

    return 1;
}

SEC("socket")
int prog(struct __sk_buff *skb)
{
    return filter_port(80);
}

char _license[] SEC("license") = "GPL";
