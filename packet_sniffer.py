import sys

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff

from logging_utils import setup_logging

logger = setup_logging()


def packet_handler(packet):
    if not packet.haslayer(IP):
        # 检查非IP协议（如ARP）
        if packet.haslayer(ARP):
            arp_op = packet[ARP].op
            logger.info(f"ARP操作: {arp_op} | 发送方MAC: {packet[ARP].hwsrc} -> 目标IP: {packet[ARP].pdst}")
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # ICMP
    if packet.haslayer(ICMP):
        icmp_type = packet[ICMP].type
        logger.info(f"{src_ip} -> {dst_ip} ICMP: {icmp_type}")

    # TCP
    elif packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        logger.info(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} TCP")

    # UDP
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        logger.info(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} UDP")

        # DNS请求/响应
        if packet.haslayer(DNS):
            dns_qname = packet[DNS].qd.qname.decode() if packet[DNS].qd else "N/A"
            logger.info(f"  DNS查询: {dns_qname}")


# 抓包逻辑
try:
    logger.info("开始抓包，按Ctrl+C停止...")
    sniff(prn=packet_handler, store=0)
except KeyboardInterrupt:
    logger.info("抓包结束，退出程序...")
    sys.exit(0)
