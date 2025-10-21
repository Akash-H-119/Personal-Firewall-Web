# iptables_helper.py (Linux only)
import subprocess
from logger import info, error

def apply_block(ip: str, port: int = None, protocol: str = "tcp"):
    cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-p", protocol, "-j", "DROP"]
    if port:
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-p", protocol, "--dport", str(port), "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True)
        info(f"Applied iptables rule: {' '.join(cmd)}")
        return True
    except subprocess.CalledProcessError as e:
        error(f"Failed to apply iptables rule: {e}")
        return False

def remove_block(ip: str, port: int = None, protocol: str = "tcp"):
    cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-p", protocol, "-j", "DROP"]
    if port:
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-p", protocol, "--dport", str(port), "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True)
        info(f"Removed iptables rule: {' '.join(cmd)}")
        return True
    except subprocess.CalledProcessError as e:
        error(f"Failed to remove iptables rule: {e}")
        return False
