# logger.py
import logging
import os

LOG_FILE = os.path.join(os.path.dirname(__file__), "firewall.log")
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def info(msg: str):
    logging.info(msg)

def warn(msg: str):
    logging.warning(msg)

def error(msg: str):
    logging.error(msg)
