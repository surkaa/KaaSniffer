import sys

from scapy.layers.inet import IP, ICMP, TCP
from scapy.sendrecv import sniff

from logging_utils import setup_logging

logger = setup_logging()


def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        logger.info(f"捕获到数据包: {src_ip} -> {dst_ip} 协议类型: {proto}")

        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            logger.info(f"ICMP类型: {icmp_type}, 代码: {icmp_code}")
        elif packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            logger.info(f"TCP端口: {src_port} -> {dst_port}")


# 抓包逻辑
try:
    logger.info("开始抓包，按Ctrl+C停止...")
    sniff(filter="tcp", prn=packet_handler, store=0)
except KeyboardInterrupt:
    logger.info("抓包结束，退出程序...")
    sys.exit(0)
