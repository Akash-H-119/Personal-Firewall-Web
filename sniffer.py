from scapy.all import sniff
import threading
from rules_manager import match_block

def packet_callback(packet, socketio=None):
    info = {
        "src": packet[0][1].src if packet.haslayer("IP") else None,
        "dst": packet[0][1].dst if packet.haslayer("IP") else None,
        "sport": getattr(packet, 'sport', None),
        "dport": getattr(packet, 'dport', None),
        "protocol": packet.proto if hasattr(packet, 'proto') else None
    }

    blocked = match_block(info)

    # Emit to dashboard
    if socketio:
        socketio.emit('new_packet', {"info": info, "blocked": blocked})

    # Log blocked packets
    if blocked:
        with open('logs/firewall.log', 'a') as f:
            f.write(f"{info}\n")

def sniff_thread(socketio):
    sniff(prn=lambda pkt: packet_callback(pkt, socketio), store=0)

def start_sniffer(socketio):
    t = threading.Thread(target=sniff_thread, args=(socketio,))
    t.daemon = True
    t.start()
