import os
from collections import defaultdict

from PyQt5.QtChart import QChart, QChartView, QPieSeries
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPainter, QIcon
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QTableWidget, QTableWidgetItem, QLabel, QLineEdit,
                             QHeaderView, QSplitter, QMessageBox)

from parse import SnifferThread


class MainWindow(QMainWindow):
    """
    主窗口
    """

    def __init__(self):
        """
        初始化
        """
        super().__init__()
        base_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(base_dir, 'app.ico')
        self.setWindowIcon(QIcon(icon_path))
        self.sniffer = None
        self.packet_count = 0
        self.draw_count = self.packet_count
        self.protocol_stats = defaultdict(int)
        self.init_ui()
        self.setup_chart()
        self.setup_timer()
        # 连接双击信号到处理函数
        self.table.itemDoubleClicked.connect(self.on_table_double_clicked)

    def init_ui(self):
        """
        初始化UI
        """
        # 主窗口设置
        self.setWindowTitle("Scapy 网络抓包分析器")
        self.setGeometry(100, 100, 1600, 1200)

        # 主分割器
        splitter = QSplitter(Qt.Vertical)

        # 上半部分：控制面板和表格
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)

        # 数据表格
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["源地址", "目标地址", "协议类型", "长度", "协议链路", "详细信息"])
        self.table.horizontalHeader().setStretchLastSection(QHeaderView.Stretch)
        self.table.horizontalHeader().resizeSections(QHeaderView.ResizeToContents)
        self.table.setColumnWidth(0, 125)
        self.table.setColumnWidth(1, 125)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(3, 60)
        self.table.setColumnWidth(4, 200)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("输入BPF过滤器 (例如 tcp port 80)")
        # filter_input 回车事件
        self.filter_input.returnPressed.connect(self.start_sniffing)

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
        last_type = packet_info.get('last_type', 'Other')
        self.protocol_stats[last_type] += 1

    def update_table(self, packet_info):
        """
        更新数据包表格
        :param packet_info: 数据包信息
        """
        self.packet_count += 1
        row = self.table.rowCount()
        self.table.insertRow(row)

        # 创建单元格并设置不可编辑
        def create_non_editable_item(text):
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)  # 移除可编辑标志
            return item

        self.table.setItem(row, 0, create_non_editable_item(packet_info.get('src', '')))
        self.table.setItem(row, 1, create_non_editable_item(packet_info.get('dst', '')))
        self.table.setItem(row, 2, create_non_editable_item(packet_info.get('last_type', '')))
        self.table.setItem(row, 3, create_non_editable_item(str(packet_info.get('len', ''))))
        self.table.setItem(row, 4, create_non_editable_item(packet_info.get('layers_link', '')))
        self.table.setItem(row, 5, create_non_editable_item(packet_info.get('detail', '')))

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

    def on_table_double_clicked(self, item):
        """ 处理表格双击事件 """
        row = item.row()
        # 获取各列数据（可选）
        src = self.table.item(row, 0).text()
        dst = self.table.item(row, 1).text()
        protocol = self.table.item(row, 2).text()
        length = self.table.item(row, 3).text()
        layers = self.table.item(row, 4).text()
        detail = self.table.item(row, 5).text()

        # 构建详细信息文本（可根据需要调整格式）
        full_detail = (
            f"源地址: {src}\n"
            f"目标地址: {dst}\n"
            f"协议类型: {protocol}\n"
            f"长度: {length}\n"
            f"协议链路: {layers}\n"
            f"\n详细信息:\n{detail}"
        )

        # 弹窗显示
        QMessageBox.information(self, "数据包详细信息", full_detail)

