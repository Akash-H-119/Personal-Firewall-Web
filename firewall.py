# firewall.py
import argparse
import platform
import threading
import time
from scapy.all import sniff, IP, TCP, UDP
from rules_manager import match_action, load_rules, add_rule, remove_rule, save_rules
from logger import info, warn
import json
import os

# optional system helpers
IS_WINDOWS = platform.system().lower().startswith("win")
try:
    if IS_WINDOWS:
        from netsh_helper import apply_block as sys_apply_block, remove_block as sys_remove_block
    else:
        from iptables_helper import apply_block as sys_apply_block, remove_block as sys_remove_block
    SYSTEM_BLOCKING_AVAILABLE = True
except Exception:
    SYSTEM_BLOCKING_AVAILABLE = False

_emit_callbacks = []

def on_packet_emit(fn):
    _emit_callbacks.append(fn)

def emit_packet(pkt_info):
    for fn in _emit_callbacks:
        try:
            fn(pkt_info)
        except Exception:
            pass

def packet_to_info(pkt):
    try:
        if IP not in pkt:
            return None
        info_pkt = {}
        info_pkt["src"] = pkt[IP].src
        info_pkt["dst"] = pkt[IP].dst
        if TCP in pkt:
            info_pkt["proto"] = "TCP"
            info_pkt["sport"] = getattr(pkt[TCP], "sport", None)
            info_pkt["dport"] = getattr(pkt[TCP], "dport", None)
        elif UDP in pkt:
            info_pkt["proto"] = "UDP"
            info_pkt["sport"] = getattr(pkt[UDP], "sport", None)
            info_pkt["dport"] = getattr(pkt[UDP], "dport", None)
        else:
            info_pkt["proto"] = pkt.lastlayer().name if pkt.lastlayer() else "OTHER"
            info_pkt["sport"] = None
            info_pkt["dport"] = None
        info_pkt["summary"] = pkt.summary()
        info_pkt["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return info_pkt
    except Exception:
        return None

def process_packet(pkt):
    pkt_info = packet_to_info(pkt)
    if not pkt_info:
        return
    action = match_action(pkt_info)
    if action == "block":
        warn(f"Blocked packet: {pkt_info.get('summary')}")
        pkt_info["action"] = "blocked"
        # optional system blocking (one-shot)
        if SYSTEM_BLOCKING_AVAILABLE:
            # apply a system-level iptables/netsh block for the src IP and port
            try:
                ip = pkt_info.get("src")
                port = pkt_info.get("sport") or pkt_info.get("dport")
                if ip:
                    sys_apply_block(ip, port, protocol=(pkt_info.get("proto") or "tcp").lower())
            except Exception:
                pass
    elif action == "allow":
        info(f"Allowed packet: {pkt_info.get('summary')}")
        pkt_info["action"] = "allowed"
    else:
        info(f"Suspicious packet: {pkt_info.get('summary')}")
        pkt_info["action"] = "suspicious"

    emit_packet(pkt_info)

def start_sniff(interface=None, filter_exp=None):
    t = threading.Thread(target=lambda: sniff(prn=process_packet, store=0, iface=interface, filter=filter_exp), daemon=True)
    t.start()
    return t

# CLI helpers for rule mgmt
def list_rules():
    rules = load_rules()
    print(json.dumps(rules, indent=2))

def add_rule_cli(action, ip, port, protocol, desc):
    r = {"action": action, "ip": ip or None, "port": port or None, "protocol": protocol or None, "description": desc or None}
    add_rule(r)
    print("Rule added.")

def remove_rule_cli(rule_id):
    ok = remove_rule(rule_id)
    print("Removed." if ok else "Rule not found.")

def run_cli(args):
    print("Starting Personal Firewall (sniffing)...")
    start_sniff(interface=args.interface, filter_exp=args.filter)
    # if in CLI interactive, keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Personal Firewall")
    parser.add_argument("--interface", "-i", help="Interface to sniff (default: all)", default=None)
    parser.add_argument("--filter", "-f", help="BPF filter (optional)", default=None)
    parser.add_argument("--list", action="store_true", help="List rules")
    parser.add_argument("--add", nargs=4, metavar=("ACTION","IP","PORT","PROTO"), help='Add rule: ACTION IP PORT PROTO. ACTION=allow|block. Use "-" or "None" for missing values.')
    parser.add_argument("--remove", metavar="RULE_ID", help="Remove rule by id")
    parser.add_argument("--gui", action="store_true", help="Start Tkinter GUI")
    args = parser.parse_args()

    if args.list:
        list_rules()
        raise SystemExit(0)

    if args.add:
        action, ip, port, proto = args.add
        add_rule_cli(action, None if ip in ("-", "None") else ip, None if port in ("-", "None") else port, None if proto in ("-", "None") else proto, "")
        raise SystemExit(0)

    if args.remove:
        remove_rule_cli(args.remove)
        raise SystemExit(0)

    # optionally start GUI
    if args.gui:
        # import GUI here to avoid tkinter import overhead when not used
        from gui import start_gui
        # GUI will call start_sniff internally and register emit callback
        start_gui(interface=args.interface, filter_exp=args.filter)
    else:
        run_cli(args)
