import logging
from .config import LOG_FILE

# Configure logger
logger = logging.getLogger("FirewallLogger")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

def log_info(msg):
    logger.info(msg)

def log_warn(msg):
    logger.warning(msg)

def log_error(msg):
    logger.error(msg)
