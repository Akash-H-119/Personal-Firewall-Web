# rules_manager.py
import json
import os
import uuid
import ipaddress
from typing import List, Dict, Optional

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules.json")

def load_rules() -> List[Dict]:
    try:
        with open(RULES_FILE, "r") as f:
            data = json.load(f)
            return data.get("rules", [])
    except FileNotFoundError:
        return []

def save_rules(rules: List[Dict]):
    with open(RULES_FILE, "w") as f:
        json.dump({"rules": rules}, f, indent=2)

def add_rule(rule: Dict) -> Dict:
    rules = load_rules()
    rule_id = rule.get("id") or str(uuid.uuid4())
    rule["id"] = rule_id
    rules.append(rule)
    save_rules(rules)
    return rule

def remove_rule(rule_id: str) -> bool:
    rules = load_rules()
    new = [r for r in rules if r.get("id") != rule_id]
    if len(new) == len(rules):
        return False
    save_rules(new)
    return True

def ip_match(rule_ip: Optional[str], ip: str) -> bool:
    if not rule_ip:
        return True
    try:
        if "/" in rule_ip:
            net = ipaddress.ip_network(rule_ip, strict=False)
            return ipaddress.ip_address(ip) in net
        else:
            return ip == rule_ip
    except Exception:
        return False

def port_match(rule_port: Optional[str], sport: Optional[int], dport: Optional[int]) -> bool:
    if not rule_port:
        return True
    # allow ranges like "20-25" or single "80"
    try:
        parts = str(rule_port).split("-")
        if len(parts) == 2:
            low = int(parts[0])
            high = int(parts[1])
            return (sport is not None and low <= sport <= high) or (dport is not None and low <= dport <= high)
        else:
            rp = int(parts[0])
            return (sport is not None and rp == sport) or (dport is not None and rp == dport)
    except Exception:
        return False

def proto_match(rule_proto: Optional[str], proto: Optional[str]) -> bool:
    if not rule_proto:
        return True
    return (rule_proto or "").upper() == (proto or "").upper()

def match_action(packet_info: Dict) -> Optional[str]:
    """
    Returns "block" if any block rule matches,
    "allow" if any allow rule matches,
    None otherwise.
    Priority: block rules first.
    """
    rules = load_rules()
    # check block rules first
    for r in rules:
        if (r.get("action") or "").lower() != "block":
            continue
        if ip_match(r.get("ip"), packet_info.get("src")) and ip_match(r.get("ip"), packet_info.get("dst")) and \
           proto_match(r.get("protocol"), packet_info.get("proto")) and \
           port_match(r.get("port"), packet_info.get("sport"), packet_info.get("dport")):
            return "block"

    # then allow rules
    for r in rules:
        if (r.get("action") or "").lower() != "allow":
            continue
        if ip_match(r.get("ip"), packet_info.get("src")) and ip_match(r.get("ip"), packet_info.get("dst")) and \
           proto_match(r.get("protocol"), packet_info.get("proto")) and \
           port_match(r.get("port"), packet_info.get("sport"), packet_info.get("dport")):
            return "allow"
    return None
