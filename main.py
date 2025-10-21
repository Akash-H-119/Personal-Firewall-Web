import os
import sys
import threading
from tkinter import Tk
from gui.dashboard import FirewallDashboard
from firewall.sniffer import PacketSniffer

# Ensure logs folder exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Start packet sniffer
sniffer = PacketSniffer()
sniffer_thread = threading.Thread(target=sniffer.start_sniffing, daemon=True)
sniffer_thread.start()

# Start GUI
root = Tk()
app = FirewallDashboard(root, sniffer)
root.mainloop()
