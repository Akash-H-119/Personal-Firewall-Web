from tkinter import ttk, Frame, Label, Text, Button, StringVar, Entry
from ttkbootstrap import Style
from scapy.all import IP
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from time import time
from .widgets import create_card
from .styles import BG_COLOR, ACCENT_COLOR, FONT_MEDIUM


class FirewallDashboard:
    def __init__(self, root, sniffer):
        self.root = root
        self.sniffer = sniffer
        self.root.title("Personal Firewall")
        self.root.geometry("1000x600")
        self.root.configure(bg=BG_COLOR)
        Style(theme="darkly")
        self.selected_tab = None
        self._build_ui()
        self.update_ui()

    def _build_ui(self):
        # Sidebar
        self.sidebar = Frame(self.root, width=180, bg="#111111")
        self.sidebar.pack(side="left", fill="y")
        self.buttons = {}
        for name, cmd in [("Dashboard", self.show_dashboard),
                          ("Rules", self.show_rules),
                          ("Monitor", self.show_monitor),
                          ("Logs", self.show_logs),
                          ("CLI", self.show_cli)]:
            b = Button(self.sidebar, text=name, command=cmd, bg="#222222", fg="white")
            b.pack(fill="x", pady=5)
            self.buttons[name] = b

        # Main content
        self.content = Frame(self.root, bg=BG_COLOR)
        self.content.pack(side="right", fill="both", expand=True)

        # Show dashboard by default
        self.show_dashboard()

    def clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    # ------------------- Dashboard Tab -------------------
    def show_dashboard(self):
        self.clear_content()

        # Initialize chart series
        self.time_series = []
        self.allowed_series = []
        self.blocked_series = []
        self.suspicious_series = []

        # Cards
        self.cards_frame = Frame(self.content, bg=BG_COLOR)
        self.cards_frame.pack(pady=20)
        self.card_blocks = {}
        for i, (title, value) in enumerate([("Total Packets", self.sniffer.total_packets),
                                            ("Blocked", self.sniffer.blocked),
                                            ("Allowed", self.sniffer.allowed),
                                            ("Suspicious", self.sniffer.suspicious)]):
            card, val_label = create_card(self.cards_frame, title, value)
            card.grid(row=0, column=i, padx=10)
            self.card_blocks[title] = val_label

        # Chart
        self.fig = Figure(figsize=(6, 3), facecolor="#222222")
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor("#222222")
        self.ax.set_title("Traffic Over Time", color="white")
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.content)
        self.canvas.get_tk_widget().pack(pady=20)

    # ------------------- Rules Tab -------------------
    def show_rules(self):
        self.clear_content()
        Label(self.content, text="Rules Management", bg=BG_COLOR, fg="white", font=FONT_MEDIUM).pack(pady=10)

        # Treeview table for rules
        columns = ("ID", "Src IP", "Dst IP", "Protocol", "Src Port", "Dst Port", "Action", "Hits")
        style = ttk.Style()
        style.configure("Rules.Treeview", background="#222222", foreground="white",
                        fieldbackground="#222222", rowheight=25)
        style.map('Rules.Treeview', background=[('selected', ACCENT_COLOR)])
        self.rules_tree = ttk.Treeview(self.content, columns=columns, show="headings", style="Rules.Treeview")
        for col in columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=90, anchor="center")
        self.rules_tree.pack(fill="both", expand=True, pady=10)
        self.rules_tree.tag_configure('oddrow', background="#222222")
        self.rules_tree.tag_configure('evenrow', background="#333333")

        # Load rules
        self.refresh_rules()

        # Entry fields to add new rule
        frm = Frame(self.content, bg=BG_COLOR)
        frm.pack(pady=5)
        self.src_ip_var = StringVar()
        self.dst_ip_var = StringVar()
        self.protocol_var = StringVar()
        self.src_port_var = StringVar()
        self.dst_port_var = StringVar()
        self.action_var = StringVar(value="ALLOW")

        Entry(frm, textvariable=self.src_ip_var, width=12).grid(row=0, column=0, padx=2)
        Entry(frm, textvariable=self.dst_ip_var, width=12).grid(row=0, column=1, padx=2)
        Entry(frm, textvariable=self.protocol_var, width=6).grid(row=0, column=2, padx=2)
        Entry(frm, textvariable=self.src_port_var, width=6).grid(row=0, column=3, padx=2)
        Entry(frm, textvariable=self.dst_port_var, width=6).grid(row=0, column=4, padx=2)
        Entry(frm, textvariable=self.action_var, width=6).grid(row=0, column=5, padx=2)
        Button(frm, text="Add Rule", command=self.add_rule_gui, bg=ACCENT_COLOR).grid(row=0, column=6, padx=5)
        Button(frm, text="Delete Selected", command=self.delete_rule_gui, bg=ACCENT_COLOR).grid(row=0, column=7, padx=5)

    def refresh_rules(self):
        from firewall.rules import list_rules
        for i in self.rules_tree.get_children():
            self.rules_tree.delete(i)
        rules = list_rules()
        for idx, r in enumerate(rules):
            tag = 'evenrow' if idx % 2 == 0 else 'oddrow'
            self.rules_tree.insert("", "end", values=(
                r["id"], r["src_ip"], r["dst_ip"], r["protocol"],
                r["src_port"], r["dst_port"], r["action"], r["hits"]
            ), tags=(tag,))

    def add_rule_gui(self):
        from firewall.rules import add_rule
        add_rule(
            src_ip=self.src_ip_var.get(),
            dst_ip=self.dst_ip_var.get(),
            protocol=self.protocol_var.get(),
            src_port=self.src_port_var.get(),
            dst_port=self.dst_port_var.get(),
            action=self.action_var.get()
        )
        self.refresh_rules()

    def delete_rule_gui(self):
        from firewall.rules import remove_rule
        selected = self.rules_tree.selection()
        for sel in selected:
            rule_id = self.rules_tree.item(sel)["values"][0]
            remove_rule(rule_id)
        self.refresh_rules()

    # ------------------- Monitor Tab -------------------
    def show_monitor(self):
        self.clear_content()
        Label(self.content, text="Live Packet Monitor", bg=BG_COLOR, fg="white", font=FONT_MEDIUM).pack(pady=10)

        columns = ("Time", "Src IP", "Dst IP", "Protocol")
        style = ttk.Style()
        style.configure("Monitor.Treeview", background="#222222", foreground="white",
                        fieldbackground="#222222", rowheight=25)
        style.map('Monitor.Treeview', background=[('selected', ACCENT_COLOR)])
        self.monitor_tree = ttk.Treeview(self.content, columns=columns, show="headings", style="Monitor.Treeview")
        for col in columns:
            self.monitor_tree.heading(col, text=col)
            self.monitor_tree.column(col, width=130, anchor="center")
        self.monitor_tree.pack(fill="both", expand=True, pady=10)
        self.monitor_tree.tag_configure('oddrow', background="#222222")
        self.monitor_tree.tag_configure('evenrow', background="#333333")

        self.update_monitor()

    def update_monitor(self):
        from datetime import datetime
        self.monitor_tree.delete(*self.monitor_tree.get_children())
        for idx, pkt in enumerate(self.sniffer.recent_packets[-50:]):
            try:
                src = pkt[IP].src if IP in pkt else "-"
                dst = pkt[IP].dst if IP in pkt else "-"
                proto = pkt.proto if IP in pkt else pkt.summary()
                tag = 'evenrow' if idx % 2 == 0 else 'oddrow'
                self.monitor_tree.insert("", "end", values=(datetime.now().strftime("%H:%M:%S"), src, dst, proto), tags=(tag,))
            except Exception:
                continue
        self.root.after(1000, self.update_monitor)

    # ------------------- Logs Tab -------------------
    def show_logs(self):
        self.clear_content()
        Label(self.content, text="Logs", bg=BG_COLOR, fg="white", font=FONT_MEDIUM).pack(pady=10)
        self.log_text = Text(self.content, bg="#222222", fg="white")
        self.log_text.pack(fill="both", expand=True)

    # ------------------- CLI / Control Tab -------------------
    def show_cli(self):
        self.clear_content()
        Label(self.content, text="Control", bg=BG_COLOR, fg="white", font=FONT_MEDIUM).pack(pady=10)
        Button(self.content, text="Start Firewall", bg=ACCENT_COLOR, command=self.start_firewall).pack(pady=5)
        Button(self.content, text="Stop Firewall", bg=ACCENT_COLOR, command=self.stop_firewall).pack(pady=5)
        Button(self.content, text="Restart Sniffer", bg=ACCENT_COLOR, command=self.restart_sniffer).pack(pady=5)
        Button(self.content, text="Clear Logs", bg=ACCENT_COLOR, command=self.clear_logs).pack(pady=5)

    def start_firewall(self):
        print("Start Firewall clicked")

    def stop_firewall(self):
        print("Stop Firewall clicked")

    def restart_sniffer(self):
        print("Restart Sniffer clicked")

    def clear_logs(self):
        print("Clear Logs clicked")

    # ------------------- UI Updater -------------------
    def update_ui(self):
        # Update cards
        try:
            self.card_blocks["Total Packets"].config(text=str(self.sniffer.total_packets))
            self.card_blocks["Blocked"].config(text=str(self.sniffer.blocked))
            self.card_blocks["Allowed"].config(text=str(self.sniffer.allowed))
            self.card_blocks["Suspicious"].config(text=str(self.sniffer.suspicious))
        except Exception:
            pass

        # Update chart data
        now = time()
        self.time_series.append(now)
        self.allowed_series.append(self.sniffer.allowed)
        self.blocked_series.append(self.sniffer.blocked)
        self.suspicious_series.append(self.sniffer.suspicious)

        # Keep last 20 points
        if len(self.time_series) > 20:
            self.time_series.pop(0)
            self.allowed_series.pop(0)
            self.blocked_series.pop(0)
            self.suspicious_series.pop(0)

       
