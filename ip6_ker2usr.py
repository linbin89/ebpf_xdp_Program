from bcc import BPF
from scapy.all import *
import socket
import ctypes

# 定义 eBPF 程序
bpf_text = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>

struct pkt_info {
    __u32 pkt_size;
};

BPF_PERF_OUTPUT(pkt_events);

int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 检查数据包长度是否足够
    if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end) {
        return XDP_PASS;
    }

    // 获取以太网头部
    struct ethhdr *eth = data;

    // 检查是否为IPv6数据包
    if (eth->h_proto != htons(ETH_P_IPV6)) {
        return XDP_PASS;
    }

    // 获取IPv6头部
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);

    // 将数据包信息发送到用户空间
    struct pkt_info info = {
        .pkt_size = (__u32)(data_end - data)
    };
    pkt_events.perf_submit(ctx, &info, sizeof(info));

    return XDP_PASS;
}
"""

# 定义 pkt_info 结构体
class PktInfo(ctypes.Structure):
    _fields_ = [("pkt_size", ctypes.c_uint32)]

# 加载 eBPF 程序
b = BPF(text=bpf_text)
fn = b.load_func("xdp_prog", BPF.XDP)

# 将 eBPF 程序附加到网络接口上
device = "ens33"  # 替换为实际的网络接口名称
b.attach_xdp(device, fn, 0)

# 定义数据包处理函数
def process_packet(cpu, data, size):
    pkt_info = ctypes.cast(data, ctypes.POINTER(PktInfo)).contents
   # pkt_data = sock.recv(pkt_info.pkt_size)
    #pkt = Ether(pkt_data)
    print(data)

# 打开 perf 事件缓冲区
b["pkt_events"].open_perf_buffer(process_packet)

# 主循环
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break

# 卸载 eBPF 程序并关闭套接字
b.remove_xdp(device, 0)
