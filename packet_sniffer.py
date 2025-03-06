import sys

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sniff


def packet_handler(packet):
    # 简单过滤：只处理IP层和ICMP包（如ping）
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        print(f"捕获到数据包: {src_ip} -> {dst_ip} 协议类型: {proto}")

        # 如果是ICMP包（如ping），提取更多信息
        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"  ICMP类型: {icmp_type}, 代码: {icmp_code}\n")


# 抓包逻辑
try:
    print("开始抓包，按Ctrl+C停止...")
    sniff(filter="icmp", prn=packet_handler, store=0)  # 只抓ICMP包，不存储
except KeyboardInterrupt:
    print("\n抓包已停止")
    sys.exit(0)
