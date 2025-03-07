import sqlite3


class SnifferDB:
    def __init__(self):
        """
        初始化数据库
        """
        self.conn = sqlite3.connect('db/sniffer_db.db')
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packet (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                packet_protocol TEXT NOT NULL,
                len INTEGER NOT NULL,
                layers_link TEXT NOT NULL,
                detail TEXT NOT NULL,
                raw TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()

    def insert_packet(self, packet_info):
        """
        插入数据包信息
        :param packet_info: 数据包信息
        """
        self.cursor.execute(
            "INSERT INTO packet (src, dst, packet_protocol, len, layers_link, detail, raw) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (packet_info['src'], packet_info['dst'], packet_info['packet_protocol'], packet_info['len'],
             packet_info['layers_link'], packet_info['detail'], packet_info['raw'])
        )
        self.conn.commit()

    def get_packets(self, protocol: str = None):
        """
        获取数据包信息
        :param protocol: 协议类型
        :return:  数据包信息
        """
        if protocol is None:
            self.cursor.execute("SELECT * FROM packet")
            return self.cursor.fetchall()

        self.cursor.execute("SELECT * FROM packet WHERE packet_protocol=?", (protocol.upper()))
        return self.cursor.fetchall()

    def get_protocols(self):
        """
        获取所有协议类型
        """
        self.cursor.execute("SELECT DISTINCT packet_protocol FROM packet")
        return [row[0] for row in self.cursor.fetchall()]

    def close(self):
        """
        关闭数据库连接
        :return:
        """
        self.conn.close()
