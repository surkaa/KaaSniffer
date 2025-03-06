import binascii
import json

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.tls.record import TLS
from scapy.packet import Raw
from scapy.sendrecv import sniff

from logging_utils import setup_logging

logger = setup_logging()


class SnifferThread(QThread):
    """
    网络抓包线程
    """
    new_packet = pyqtSignal(dict)  # 定义数据包信号

    def __init__(self, filter=""):
        """
        :param filter: BPF过滤器
        """
        super().__init__()
        self.filter = filter
        self.running = False

    def run(self):
        """
        开始抓包
        """
        self.running = True
        sniff(prn=self.process_packet, store=0, stop_filter=lambda _: not self.running, filter=self.filter)

    def process_packet(self, packet):
        """
        处理抓到的数据包 抓到后发送信号
        :param packet: 抓到的数据包
        """
        if not self.running:
            return
        try:
            packet_info = self.parse_packet(packet)
        except:
            # logger.error(f"解析数据包失败: {packet.summary()}")
            return
        if packet_info:
            self.new_packet.emit(packet_info)

    def parse_packet(self, packet):
        """
        解析数据包
        :param packet: 数据包
        :return: 数据包信息
        """
        if not packet.haslayer(IP):
            return {}

        info = {'layers': {}, 'len': 0, 'src': '', 'dst': '', 'last_type': ''}

        # 物理层/数据链路层（Ethernet）
        if packet.haslayer(Ether):
            eth = packet[Ether]
            info['layers']['eth'] = {
                'srcmac': eth.src,
                'dstmac': eth.dst,
                'type': eth.type
            }

        # 网络层（IP/IPv6/ARP等）
        if packet.haslayer(IP):
            ip = packet[IP]
            info['layers']['ip'] = {
                'src': ip.src,
                'dst': ip.dst,
                'proto': ip.proto,
                'ttl': ip.ttl,
                'len': ip.len
            }
            info['src'] = ip.src
            info['dst'] = ip.dst
            info['len'] = ip.len
        elif packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            info['layers']['ipv6'] = {
                'src': ipv6.src,
                'dst': ipv6.dst,
                'nh': ipv6.nh
            }
            info['src'] = ipv6.src
            info['dst'] = ipv6.dst
            info['len'] = ipv6.plen
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            info['layers']['arp'] = {
                'op': arp.op,
                'hwsrc': arp.hwsrc,
                'psrc': arp.psrc,
                'hwdst': arp.hwdst,
                'pdst': arp.pdst
            }
            info['src'] = arp.psrc
            info['dst'] = arp.pdst
            info['len'] = 0
            return info  # ARP包没有更高层协议

        # 传输层（TCP/UDP/ICMP等）
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info['layers']['tcp'] = {
                'sport': tcp.sport,
                'dport': tcp.dport,
                'flags': tcp.flags,
                'seq': tcp.seq,
                'ack': tcp.ack
            }
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info['layers']['udp'] = {
                'sport': udp.sport,
                'dport': udp.dport,
                'len': udp.len
            }
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            info['layers']['icmp'] = {
                'type': icmp.type,
                'code': icmp.code,
                'id': icmp.id,
                'seq': icmp.seq
            }

        # 应用层协议解析
        if packet.haslayer(DNS):
            dns = packet[DNS]
            info['layers']['dns'] = {
                'qd': str(dns.qd.qname) if dns.qd else None,
                'an': [str(rr.rdata) for rr in dns.an] if dns.an else None
            }

        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            info['layers']['http'] = {
                'method': http.Method.decode(),
                'host': http.Host.decode(),
                'path': http.Path.decode()
            }
        elif packet.haslayer(HTTPResponse):
            http = packet[HTTPResponse]
            info['layers']['http'] = {
                'status': http.Status_Code.decode(),
                'reason': http.Reason_Phrase.decode()
            }

        # TLS/SSL握手信息（HTTPS）
        if packet.haslayer(TLS):
            tls = packet[TLS]
            info['layers']['tls'] = {
                'version': tls.version,
                # 'handshake_type': tls.handshake_type if tls.handshake else None
            }

        # 原始负载（Payload）
        if packet.haslayer(Raw):
            raw = packet[Raw].load
            try:
                # 转为规范的十六进制字符串（每字节两位，空格分隔）
                hex_str = binascii.hexlify(raw).decode('utf-8')
                # 按每2字符（1字节）添加空格分隔，更易读
                formatted_hex = ' '.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))
                info['layers']['payload'] = formatted_hex
            except:
                logger.error(f"无法解码负载数据: {raw}")
                info['layers']['payload'] = '无法解析的数据'

        # 生成简化版协议类型
        layers = list(info['layers'].keys())
        if len(layers) == 0:
            return {}
        last_layer = layers[-1]
        if last_layer == 'payload':
            last_layer = layers[-2]
        info['layers_link'] = '/'.join(info['layers'].keys())
        info['last_type'] = last_layer.upper()
        # 设置info['detail']为info['layers']的json字符串
        try:
            info["detail"] = json.dumps(info['layers'])
        except:
            info["detail"] = str(info['layers'])
        return info

    def stop(self):
        """
        停止抓包
        """
        self.running = False
