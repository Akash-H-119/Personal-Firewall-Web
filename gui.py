# gui.py
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from firewall import start_sniff, on_packet_emit
from rules_manager import load_rules, add_rule, remove_rule, save_rules
import time
import queue

_packet_q = queue.Queue()

def _enqueue_packet(info):
    _packet_q.put(info)

def _periodic_gui_update(tree, logbox):
    try:
        while True:
            info = _packet_q.get_nowait()
            # insert into treeview
            tree.insert("", 0, values=(info.get("time"), info.get("src"), info.get("dst"), info.get("proto"), info.get("summary"), info.get("action")))
            # append to log box
            logbox.insert("end", f"{info.get('time')} {info.get('src')}->{info.get('dst')} {info.get('proto')} {info.get('action')}\n")
            if logbox.size() > 5000:
                logbox.delete(0)
    except Exception:
        pass
    # schedule next
    tree.after(500, _periodic_gui_update, tree, logbox)

def _refresh_rules_list(listbox):
    listbox.delete(0, "end")
    rules = load_rules()
    for r in rules:
        listbox.insert("end", f"{r.get('id')[:8]} | {r.get('action')} | {r.get('ip') or 'any'} | {r.get('port') or 'any'} | {r.get('protocol') or 'any'} | {r.get('description') or ''}")

def start_gui(interface=None, filter_exp=None):
    # register emit callback
    on_packet_emit(_enqueue_packet)
    # start sniffing background
    start_sniff(interface=interface, filter_exp=filter_exp)

    root = tk.Tk()
    root.title("Personal Firewall - Monitor")
    root.geometry("1100x700")

    top = tk.Frame(root)
    top.pack(fill="x", padx=6, pady=6)

    add_frame = tk.Frame(top)
    add_frame.pack(side="left", padx=6)

    action_var = tk.StringVar(value="block")
    tk.OptionMenu(add_frame, action_var, "block", "allow").pack(side="left")

    ip_e = tk.Entry(add_frame, width=18)
    ip_e.pack(side="left", padx=4)
    ip_e.insert(0, "IP or CIDR")

    port_e = tk.Entry(add_frame, width=8)
    port_e.pack(side="left", padx=4)
    port_e.insert(0, "port or 80-90")

    proto_e = tk.Entry(add_frame, width=8)
    proto_e.pack(side="left", padx=4)
    proto_e.insert(0, "TCP")

    desc_e = tk.Entry(add_frame, width=30)
    desc_e.pack(side="left", padx=4)
    desc_e.insert(0, "Description")

    def on_add():
        action = action_var.get()
        ip = ip_e.get().strip()
        port = port_e.get().strip()
        proto = proto_e.get().strip()
        desc = desc_e.get().strip()
        r = {"action": action, "ip": None if ip in ("", "IP or CIDR") else ip, "port": None if port in ("", "port or 80-90") else port, "protocol": None if proto in ("", "TCP") else proto, "description": desc}
        add_rule(r)
        _refresh_rules_list(rules_listbox)

    add_btn = tk.Button(add_frame, text="Add Rule", command=on_add)
    add_btn.pack(side="left", padx=4)

    rules_frame = tk.Frame(top)
    rules_frame.pack(side="right", padx=6)
    tk.Label(rules_frame, text="Rules").pack()
    rules_listbox = tk.Listbox(rules_frame, width=80, height=6)
    rules_listbox.pack()

    def del_selected():
        sel = rules_listbox.curselection()
        if not sel:
            messagebox.showinfo("Delete", "Select a rule first")
            return
        idx = sel[0]
        rules = load_rules()
        rid = rules[idx].get("id")
        remove_rule(rid)
        _refresh_rules_list(rules_listbox)

    del_btn = tk.Button(rules_frame, text="Delete Selected", command=del_selected)
    del_btn.pack(pady=4)

    # main table for packets
    cols = ("Time", "Src", "Dst", "Proto", "Summary", "Action")
    tree = ttk.Treeview(root, columns=cols, show="headings", height=20)
    for c in cols:
        tree.heading(c, text=c)
        tree.column(c, width=150 if c != "Summary" else 400)
    tree.pack(fill="both", expand=True, padx=6, pady=6)

    # log box
    logbox = tk.Listbox(root, height=8)
    logbox.pack(fill="x", padx=6, pady=6)

    _refresh_rules_list(rules_listbox)
    # start periodic updates
    root.after(500, _periodic_gui_update, tree, logbox)
    root.mainloop()
