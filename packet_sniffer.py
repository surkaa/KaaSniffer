import sys

from scapy.layers.inet import IP, ICMP, TCP
from scapy.sendrecv import sniff

from logging_utils import setup_logging

logger = setup_logging()


def packet_handler(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if packet.haslayer(ICMP):
        icmp_type = packet[ICMP].type
        logger.info(f"{src_ip} -> {dst_ip} ICMP: {icmp_type}")
    elif packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        logger.info(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} TCP")


# 抓包逻辑
try:
    logger.info("开始抓包，按Ctrl+C停止...")
    sniff(prn=packet_handler, store=0)
except KeyboardInterrupt:
    logger.info("抓包结束，退出程序...")
    sys.exit(0)
