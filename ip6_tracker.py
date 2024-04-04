from bcc import BPF
import socket
import struct
import signal
import ctypes
import time

# 定义 BPF 程序
bpf_text = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>


struct pair {
    unsigned __int128 src_ip;
    unsigned __int128 dest_ip;
};

struct stats {
    u64 tx_cnt;
    u64 rx_cnt;
    u64 tx_bytes;
    u64 rx_bytes;
};

BPF_HASH(tracker_map, struct pair, struct stats);

static __always_inline bool parse_and_track(bool is_rx, void *data_begin, void *data_end, struct pair *pair)
{
    struct ethhdr *eth = data_begin;
    if ((void *)(eth + 1) > data_end)
        return false;

    if (eth->h_proto == htons(ETH_P_IPV6))
    {
        struct ipv6hdr *iph = (struct ipv6hdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return false;

        __builtin_memcpy(&pair->src_ip, &iph->saddr, sizeof(pair->src_ip));
        __builtin_memcpy(&pair->dest_ip, &iph->daddr, sizeof(pair->dest_ip));

        struct stats *stats, newstats = {0, 0, 0, 0};
        long long bytes = data_end - data_begin;
        stats = tracker_map.lookup(pair);
        if (stats)
        {
            if (is_rx)
            {
                stats->rx_cnt++;
                stats->rx_bytes += bytes;
            }
            else
            {
                stats->tx_cnt++;
                stats->tx_bytes += bytes;
            }
        }
        else
        {
            if (is_rx)
            {
                newstats.rx_cnt = 1;
                newstats.rx_bytes = bytes;
            }
            else
            {
                newstats.tx_cnt = 1;
                newstats.tx_bytes = bytes;
            }
            tracker_map.insert(pair, &newstats);
        }
        return true;
    }
    return false;
}

int xdp_ip_tracker(struct xdp_md *ctx) {
    struct pair pair;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (!parse_and_track(true, data, data_end, &pair))
        return XDP_PASS;

    return XDP_DROP;
}
"""

# 编译 BPF 程序
b = BPF(text=bpf_text)

# 加载 XDP 程序
fn = b.load_func("xdp_ip_tracker", BPF.XDP)

# 附加到网络接口
ifindex = "ens33"  # 目标网络接口的名称
b.attach_xdp(ifindex, fn, 0)

# 定义 Ctrl-C 处理程序以正常退出
def signal_handler(signal, frame):
    print("stopping")
    b.remove_xdp(ifindex, 0)
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

# 打印统计信息
print("Printing stats, hit CTRL+C to stop")
while True:
    try:
        time.sleep(0.01)
        for k, v in b["tracker_map"].items():
            src_ip = socket.inet_ntop(socket.AF_INET6, bytes(k.src_ip))
            dest_ip = socket.inet_ntop(socket.AF_INET6, bytes(k.dest_ip))
            print(f"Local IP: {src_ip}, Remote IP: {dest_ip}, TX Count: {v.tx_cnt}, TX Bytes: {v.tx_bytes}, RX Count: {v.rx_cnt}, RX Bytes: {v.rx_bytes}")
        print("\n")
    except KeyboardInterrupt:
        print("Removing filter from device")
        break
b.remove_xdp(ifindex, 0)
