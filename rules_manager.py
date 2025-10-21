rules = [
    # Example rule
    {"ip": "192.168.1.10", "port": 80, "protocol": "TCP", "action": "block"},
]

def match_block(packet_info):
    for r in rules:
        ip_ok = (r.get("ip") == packet_info.get("src") or r.get("ip") == packet_info.get("dst")) if r.get("ip") else True
        port_ok = (r.get("port") in [packet_info.get("sport"), packet_info.get("dport")]) if r.get("port") else True
        proto_ok = (r.get("protocol") == packet_info.get("protocol")) if r.get("protocol") else True

        if ip_ok and port_ok and proto_ok:
            return r.get("action") == "block"
    return False
