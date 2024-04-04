import socket
import struct
from scapy.all import *

# 定义要绑定的网络接口
INTERFACE = "ens33"

# 创建原始套接字
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

# 绑定网络接口
sock.bind((INTERFACE, 0))

while True:
    # 接收数据包
    data, addr = sock.recvfrom(65565)

    # 解析数据包
    packet = Ether(data)

    # 检查数据包是否为IPv6
    if packet.type == 0x86dd:
        ipv6_pkt = IPv6(bytes(packet[IPv6]))

        # 使用scapy的summary函数总结数据包信息
        print(ipv6_pkt.summary())
