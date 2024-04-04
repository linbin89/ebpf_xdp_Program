from bcc import BPF

# 定义 eBPF 程序
ebpf_program = """
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
int xdp_parser(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto == htons(ETH_P_IPV6)) {
        bpf_trace_printk("IPv6 packet detected\\n");
    }

    return XDP_PASS;
}
"""

# 加载 eBPF 程序
b = BPF(text=ebpf_program)

# 将 eBPF 程序附加到网络接口的 XDP 钩子上
b.attach_xdp("ens33", b.load_func("xdp_parser", BPF.XDP))

print("Capturing packets, hit Ctrl-C to stop")

# 读取并打印 trace_printk 的输出
while True:
    try:
       (task, pid, cpu, flags, ts, msg) = b.trace_fields()
       print(msg.decode('utf-8'))
    except KeyboardInterrupt:
        print("Stopped capturing packets")
        break

# 从网络接口分离 eBPF 程序
b.remove_xdp("ens33")
