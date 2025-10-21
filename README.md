# Personal Firewall - Web Dashboard

## Overview
**Personal Firewall** is a lightweight Python-based firewall application with a **web dashboard** for real-time monitoring and rule management. It filters network traffic based on customizable rules, logs suspicious packets, and provides a professional interface for live monitoring.

This project uses:
- **Python** for backend logic
- **Scapy** for packet sniffing
- **Flask + Flask-SocketIO** for the web dashboard
- **HTML/CSS/JavaScript** for frontend interface
- **Eventlet** for async socket communication

---

## Features
1. **Packet Sniffing**
   - Monitors incoming/outgoing traffic in real-time.
2. **Rule Management**
   - Block or allow traffic based on IP, port, or protocol.
3. **Logging**
   - Logs all blocked or suspicious packets for audit.
4. **Dashboard**
   - Modern interface to view traffic in real-time.
   - Add or remove firewall rules directly from the dashboard.
5. **Optional System-Level Enforcement**
   - Can integrate with `iptables` on Linux for system-level blocking.

---

