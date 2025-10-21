import platform

# In-memory rules list
rules = []  # each rule: dict {id, src_ip, dst_ip, protocol, src_port, dst_port, action, enabled, hits}
rule_counter = 1

def add_rule(src_ip="", dst_ip="", protocol="", src_port="", dst_port="", action="ALLOW"):
    global rule_counter
    rule = {
        "id": rule_counter,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "action": action,
        "enabled": True,
        "hits": 0
    }
    rules.append(rule)
    rule_counter += 1
    return rule

def remove_rule(rule_id):
    global rules
    rules = [r for r in rules if r["id"] != rule_id]

def list_rules():
    return rules

def match_packet(pkt):
    # Simple match: returns first matching rule or None
    for r in rules:
        if not r["enabled"]:
            continue
        # IP filter
        ip_match = True
        try:
            from scapy.all import IP, TCP, UDP
            if IP in pkt:
                ip = pkt[IP]
                if r["src_ip"] and r["src_ip"] != ip.src:
                    ip_match = False
                if r["dst_ip"] and r["dst_ip"] != ip.dst:
                    ip_match = False
            # Protocol filter
            proto_match = True
            proto = r["protocol"].lower()
            if proto == "tcp" and not pkt.haslayer(TCP):
                proto_match = False
            if proto == "udp" and not pkt.haslayer(UDP):
                proto_match = False
            # Port filter
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                sport = pkt.sport
                dport = pkt.dport
                if r["src_port"] and str(r["src_port"]) != str(sport):
                    proto_match = False
                if r["dst_port"] and str(r["dst_port"]) != str(dport):
                    proto_match = False
            if ip_match and proto_match:
                r["hits"] += 1
                return r
        except Exception:
            continue
    return None
