import logging
import os
import sys
import time

import colorlog


def setup_logging():
    log_folder = 'logs'
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)
    timestamp = time.strftime('%Y_%m_%d_%H_%M_%S')
    log_file = os.path.join(log_folder, f'log_{timestamp}.txt')

    # 设置彩色日志格式
    log_format = '%(log_color)s%(asctime)s [%(levelname)s] %(message)s'
    formatter = colorlog.ColoredFormatter(log_format)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # 创建文件处理器并设置格式
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))

    # 创建控制台处理器并设置彩色格式
    console_handler = colorlog.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # 清空之前的处理器，添加新的处理器
    logger.handlers = []
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
