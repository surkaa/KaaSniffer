from scapy.layers.dns import DNS
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import sniff

from logging_utils import setup_logging

logger = setup_logging()

# 定义协议处理映射（可扩展）
PROTOCOL_HANDLERS = {
    ICMP: lambda p: f"ICMP类型: {p[ICMP].type}",
    TCP: lambda p: f"TCP端口: {p[TCP].sport}->{p[TCP].dport}",
    UDP: lambda p: f"UDP端口: {p[UDP].sport}->{p[UDP].dport}",
    DNS: lambda p: f"DNS查询: {p[DNS].qd.qname}" if p[DNS].qd else None
}


def packet_handler(packet):
    log_lines = []

    if not packet.haslayer(IP):
        return
    # 基础信息
    log_lines.append(f"{packet[IP].src:>15} -> {packet[IP].dst:<15}")

    # 协议处理
    for proto, handler in PROTOCOL_HANDLERS.items():
        if packet.haslayer(proto):
            result = handler(packet)
            if result:
                log_lines.append(result)

    if log_lines:
        logger.info(" | ".join(log_lines))


# 抓包逻辑
sniff(prn=packet_handler, store=0)
