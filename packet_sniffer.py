import json
import sys
from collections import defaultdict

from PyQt5.QtChart import QChart, QChartView, QPieSeries
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QPainter
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QTableWidget, QTableWidgetItem, QLabel, QLineEdit,
                             QHeaderView, QSplitter)
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
            logger.error(f"解析数据包失败: {packet.summary()}")
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

        info = {'layers': {}}

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
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            info['layers']['arp'] = {
                'op': arp.op,
                'hwsrc': arp.hwsrc,
                'psrc': arp.psrc,
                'hwdst': arp.hwdst,
                'pdst': arp.pdst
            }
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
                info['layers']['payload'] = raw.decode('utf-8', errors='ignore')
            except:
                logger.error(f"无法解码负载数据: {raw}")
                info['layers']['payload'] = str(raw)

        # 生成简化版协议类型
        info['protocol_type'] = '/'.join(info['layers'].keys())
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


class MainWindow(QMainWindow):
    """
    主窗口
    """

    def __init__(self):
        """
        初始化
        """
        super().__init__()
        self.sniffer = None
        self.packet_count = 0
        self.draw_count = self.packet_count
        self.protocol_stats = defaultdict(int)
        self.init_ui()
        self.setup_chart()
        self.setup_timer()

    def init_ui(self):
        """
        初始化UI
        """
        # 主窗口设置
        self.setWindowTitle("Scapy 网络抓包分析器")
        self.setGeometry(300, 300, 1200, 800)

        # 主分割器
        splitter = QSplitter(Qt.Vertical)

        # 上半部分：控制面板和表格
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)

        # 数据表格
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["源地址", "目标地址", "协议类型", "长度", "详细信息"])
        self.table.horizontalHeader().setStretchLastSection(QHeaderView.Stretch)
        self.table.horizontalHeader().resizeSections(QHeaderView.ResizeToContents)
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 200)
        self.table.setColumnWidth(2, 200)
        self.table.setColumnWidth(3, 100)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("输入BPF过滤器 (例如 tcp port 80)")

        self.start_btn = QPushButton("开始抓包")
        self.stop_btn = QPushButton("停止抓包")
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("清空数据")
        self.clear_btn.setEnabled(False)
        self.status_label = QLabel("就绪")

        # 布局 控制面板
        control_layout = QHBoxLayout()
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addWidget(self.filter_input)

        top_layout.addLayout(control_layout)
        top_layout.addWidget(self.table)

        # 下半部分：统计图表
        self.chart_view = QChartView()
        self.chart_view.setRenderHint(QPainter.Antialiasing)

        splitter.addWidget(top_widget)
        splitter.addWidget(self.chart_view)
        splitter.setSizes([500, 300])

        self.setCentralWidget(splitter)
        self.status_label = QLabel("就绪")
        self.statusBar().addWidget(self.status_label)

        # 信号连接
        self.start_btn.clicked.connect(self.start_sniffing)
        self.stop_btn.clicked.connect(self.stop_sniffing)
        self.clear_btn.clicked.connect(self.clear_data)

    def setup_chart(self):
        """
        设置图表
        """
        self.chart = QChart()
        self.chart.setTitle("协议分布统计")
        self.chart.setAnimationOptions(QChart.SeriesAnimations)
        self.chart_view.setChart(self.chart)

    def setup_timer(self):
        """
        设置定时器
        """
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_chart)
        self.update_timer.start(5000)

    def update_chart(self):
        """
        更新图表
        """
        if self.draw_count == self.packet_count:
            return
        self.draw_count = self.packet_count  # 更新绘制计数
        series = QPieSeries()
        total = sum(self.protocol_stats.values())

        for protocol, count in self.protocol_stats.items():
            if count > 0:
                percentage = count / total * 100
                series.append(f"{protocol} ({count} | {percentage:.1f}%)", count).setLabelVisible(True)

        self.chart.removeAllSeries()
        self.chart.addSeries(series)

    def start_sniffing(self):
        """
        开始抓包
        """
        if not self.sniffer or not self.sniffer.isRunning():
            self.sniffer = SnifferThread(filter=self.filter_input.text())
            self.sniffer.new_packet.connect(self.update_interface)
            self.sniffer.start()
            self.status_label.setText("抓包运行中...")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)

    def update_interface(self, packet_info):
        self.update_table(packet_info)
        protocol_type = packet_info.get('protocol_type', 'Other')
        self.protocol_stats[protocol_type] += 1

    def update_table(self, packet_info):
        """
        更新数据包表格
        :param packet_info: 数据包信息
        """
        self.packet_count += 1
        row = self.table.rowCount()
        self.table.insertRow(row)

        self.table.setItem(row, 0, QTableWidgetItem(packet_info.get('src', '')))
        self.table.setItem(row, 1, QTableWidgetItem(packet_info.get('dst', '')))
        self.table.setItem(row, 2, QTableWidgetItem(packet_info.get('type', '')))
        self.table.setItem(row, 3, QTableWidgetItem(packet_info.get('len', '')))
        self.table.setItem(row, 4, QTableWidgetItem(packet_info.get('detail', '')))

        # 自动滚动到最后一行
        self.table.scrollToBottom()
        if self.packet_count == 1:
            self.clear_btn.setEnabled(True)

    def stop_sniffing(self):
        if self.sniffer and self.sniffer.isRunning():
            self.sniffer.stop()
            self.sniffer.quit()
            self.status_label.setText("已停止")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def clear_data(self):
        self.table.setRowCount(0)
        self.packet_count = 0
        self.protocol_stats.clear()
        self.clear_btn.setEnabled(False)
        self.update_chart()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    window.start_sniffing()  # 开始抓包
    sys.exit(app.exec_())
