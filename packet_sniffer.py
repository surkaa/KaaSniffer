import sys

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QTableWidget, QTableWidgetItem, QLabel, QLineEdit, QHeaderView)
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import sniff


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
        sniff(prn=self.process_packet, store=0, stop_filter=lambda _: not self.running)

    def process_packet(self, packet):
        """
        处理抓到的数据包 抓到后发送信号
        :param packet: 抓到的数据包
        """
        if not self.running:
            return
        packet_info = self.parse_packet(packet)
        if packet_info:
            self.new_packet.emit(packet_info)

    def parse_packet(self, packet):
        """
        解析数据包
        :param packet: 数据包
        :return: 数据包信息
        """
        info = {}
        if packet.haslayer(IP):
            info['src'] = packet[IP].src
            info['dst'] = packet[IP].dst
            info['protocol'] = packet[IP].proto

            if packet.haslayer(ICMP):
                info['type'] = f"ICMP({packet[ICMP].type})"
            elif packet.haslayer(TCP):
                info['type'] = f"TCP({packet[TCP].sport}->{packet[TCP].dport})"
            elif packet.haslayer(UDP):
                info['type'] = f"UDP({packet[UDP].sport}->{packet[UDP].dport})"
                if packet.haslayer(DNS) and packet[DNS].qd:
                    info['detail'] = str(packet[DNS].qd.qname)
            else:
                info['type'] = "Other"
            return info
        return None

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
        self.init_ui()

    def init_ui(self):
        """
        初始化UI
        """
        # 主窗口设置
        self.setWindowTitle("Scapy 网络抓包分析器")
        self.setGeometry(300, 300, 1200, 800)

        # 控件
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["源地址", "目标地址", "协议类型", "详细信息"])
        self.table.horizontalHeader().setStretchLastSection(QHeaderView.Stretch)
        self.table.horizontalHeader().resizeSections(QHeaderView.ResizeToContents)
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 200)
        self.table.setColumnWidth(2, 200)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("输入BPF过滤器 (例如 tcp port 80)")

        self.start_btn = QPushButton("开始抓包")
        self.stop_btn = QPushButton("停止抓包")
        self.clear_btn = QPushButton("清空数据")
        self.status_label = QLabel("就绪")

        # 布局
        control_layout = QHBoxLayout()
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addWidget(self.filter_input)

        main_layout = QVBoxLayout()
        main_layout.addLayout(control_layout)
        main_layout.addWidget(self.table)
        main_layout.addWidget(self.status_label)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # 信号连接
        self.start_btn.clicked.connect(self.start_sniffing)
        self.stop_btn.clicked.connect(self.stop_sniffing)
        self.clear_btn.clicked.connect(self.clear_data)

    def start_sniffing(self):
        """
        开始抓包
        """
        if not self.sniffer or not self.sniffer.isRunning():
            self.sniffer = SnifferThread(filter=self.filter_input.text())
            self.sniffer.new_packet.connect(self.update_table)
            self.sniffer.start()
            self.status_label.setText("抓包运行中...")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)

    def stop_sniffing(self):
        """
        停止抓包
        """
        if self.sniffer and self.sniffer.isRunning():
            self.sniffer.stop()
            self.sniffer.quit()
            self.status_label.setText("已停止")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def clear_data(self):
        """
        清空数据
        """
        self.table.setRowCount(0)
        self.packet_count = 0

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
        self.table.setItem(row, 3, QTableWidgetItem(packet_info.get('detail', '')))

        # 自动滚动到最后一行
        self.table.scrollToBottom()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
