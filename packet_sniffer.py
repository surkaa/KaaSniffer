import sys

from logging_utils import setup_logging

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sniff

logger = setup_logging()


def packet_handler(packet):
    # 简单过滤：只处理IP层和ICMP包（如ping）
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        logger.info(f"捕获到数据包: {src_ip} -> {dst_ip} 协议类型: {proto}")

        # 如果是ICMP包（如ping），提取更多信息
        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            logger.info(f"ICMP类型: {icmp_type}, 代码: {icmp_code}")


# 抓包逻辑
try:
    # print("开始抓包，按Ctrl+C停止...")
    logger.info("开始抓包，按Ctrl+C停止...")
    sniff(filter="icmp", prn=packet_handler, store=0)  # 只抓ICMP包，不存储
except KeyboardInterrupt:
    logger.info("抓包结束，退出程序...")
    sys.exit(0)
