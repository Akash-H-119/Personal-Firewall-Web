import platform
import subprocess
from .logger import log_info, log_warn

IS_LINUX = platform.system() == "Linux"

def apply_rule(rule):
    if not IS_LINUX:
        log_info(f"Simulated APPLY rule: {rule}")
        return
    try:
        # Example: block source IP
        if rule["action"] == "BLOCK" and rule["src_ip"]:
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", rule["src_ip"], "-j", "DROP"]
            subprocess.run(cmd, check=True)
            log_info(f"Applied iptables block for {rule['src_ip']}")
    except Exception as e:
        log_warn(f"Failed to apply iptables rule: {e}")

def flush_rules():
    if not IS_LINUX:
        log_info("Simulated FLUSH rules")
        return
    try:
        subprocess.run(["sudo", "iptables", "-F"], check=True)
        log_info("Flushed all iptables rules")
    except Exception as e:
        log_warn(f"Failed to flush iptables rules: {e}")
