#if defined(BPF_LICENSE)
#error BPF_LICENSE cannot be specified through cflags
#endif
#if !defined(CONFIG_CC_STACKPROTECTOR)
#if defined(CONFIG_CC_STACKPROTECTOR_AUTO) || defined(CONFIG_CC_STACKPROTECTOR_REGULAR) || defined(CONFIG_CC_STACKPROTECTOR_STRONG)
#define CONFIG_CC_STACKPROTECTOR
#endif
#endif

#define KBUILD_MODNAME "bcc"
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14
BPF_PERF_OUTPUT(skb_events);
BPF_HASH(packet_cnt, u64, long, 256);

__attribute__((section(".bpf.fn.packet_monitor"))) int packet_monitor(struct __sk_buff *skb)
{

    u8 *cursor = 0;
    u32 saddr, daddr;
    long *count = 0;
    long one = 1;
    u64 pass_value = 0;

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    if (bpf_dext_pkt(skb, (u64)ip + 9, 0, 8) != IP_TCP)
    {
        if (bpf_dext_pkt(skb, (u64)ip + 9, 0, 8) != IP_UDP)
        {
            if (bpf_dext_pkt(skb, (u64)ip + 9, 0, 8) != IP_ICMP)
                return 0;
        }
    }

    saddr = bpf_dext_pkt(skb, (u64)ip + 12, 0, 32);
    daddr = bpf_dext_pkt(skb, (u64)ip + 16, 0, 32);

    pass_value = saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + daddr;

    count = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -2), &pass_value);
    if (count) // check if this map exists
        *count += 1;
    else // if the map for the key doesn't exist, create one
    {
        bpf_map_update_elem((void *)bpf_pseudo_fd(1, -2), &pass_value, &one, BPF_ANY);
    }
    return -1;
}

#include <bcc/footer.h>