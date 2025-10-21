# netsh_helper.py (Windows)
import subprocess
from logger import info, error

def apply_block(ip: str, port: int = None):
    name = f"Block-{ip}-{port or 'any'}"
    if port:
        cmd = f'netsh advfirewall firewall add rule name="{name}" dir=in action=block remoteip={ip} protocol=TCP localport={port}'
    else:
        cmd = f'netsh advfirewall firewall add rule name="{name}" dir=in action=block remoteip={ip}'
    try:
        subprocess.run(cmd, shell=True, check=True)
        info(f"Applied netsh rule: {cmd}")
        return True
    except subprocess.CalledProcessError as e:
        error(f"Failed to apply netsh rule: {e}")
        return False

def remove_block(ip: str, port: int = None):
    name = f"Block-{ip}-{port or 'any'}"
    cmd = f'netsh advfirewall firewall delete rule name="{name}"'
    try:
        subprocess.run(cmd, shell=True, check=True)
        info(f"Removed netsh rule: {cmd}")
        return True
    except subprocess.CalledProcessError as e:
        error(f"Failed to remove netsh rule: {e}")
        return False
