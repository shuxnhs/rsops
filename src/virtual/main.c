#if defined(BPF_LICENSE)
#error BPF_LICENSE cannot be specified through cflags
#endif
#if !defined(CONFIG_CC_STACKPROTECTOR)
#if defined(CONFIG_CC_STACKPROTECTOR_AUTO) \
    || defined(CONFIG_CC_STACKPROTECTOR_REGULAR) \
    || defined(CONFIG_CC_STACKPROTECTOR_STRONG)
#define CONFIG_CC_STACKPROTECTOR
#endif
#endif

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>

BPF_CPUMAP(cpumap, __MAX_CPU__);
BPF_ARRAY(dest, uint32_t, 1);
BPF_PERCPU_ARRAY(rxcnt, long, 1);

__attribute__((section(".bpf.fn.xdp_redirect_cpu")))
int xdp_redirect_cpu(struct xdp_md *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    uint32_t key = 0;
    long *value;
    uint32_t *cpu;
    uint64_t nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off  > data_end)
        return XDP_DROP;

    cpu = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -2), &key);
    if (!cpu)
        return XDP_PASS;

    value = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -3), &key);
    if (value)
        *value += 1;

    return bpf_redirect_map((void *)bpf_pseudo_fd(1, -1), *cpu, 0);
}

__attribute__((section(".bpf.fn.xdp_dummy")))
int xdp_dummy(struct xdp_md *ctx) {

    return XDP_PASS;
}

#include <bcc/footer.h>
