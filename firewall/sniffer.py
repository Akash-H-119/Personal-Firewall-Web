import threading
from scapy.all import sniff, IP, TCP, UDP
from .rules import match_packet
from .logger import log_info, log_warn

class PacketSniffer:
    def __init__(self):
        self.total_packets = 0
        self.allowed = 0
        self.blocked = 0
        self.suspicious = 0
        self.recent_packets = []  # last 50 packets

    def _packet_callback(self, pkt):
        self.total_packets += 1
        rule = match_packet(pkt)
        if rule:
            if rule["action"] == "BLOCK":
                self.blocked += 1
                log_warn(f"Blocked packet: {pkt.summary()}")
            else:
                self.allowed += 1
                log_info(f"Allowed packet: {pkt.summary()}")
        else:
            self.suspicious += 1
            log_warn(f"Suspicious packet: {pkt.summary()}")
        # Keep last 50
        self.recent_packets.append(pkt)
        if len(self.recent_packets) > 50:
            self.recent_packets.pop(0)

    def start_sniffing(self):
        sniff(prn=self._packet_callback, store=False)
