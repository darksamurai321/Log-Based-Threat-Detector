import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import ttkbootstrap as tb
from ttkbootstrap.scrolled import ScrolledText
import threading
import smtplib
from email.message import EmailMessage
import datetime
import concurrent.futures
import os

# Import modules
from parsers import parse_log_line
from normalization import normalize_payload
from detection import detect_threats, THREAT_PATTERNS
from reporter import generate_pdf_report
from dashboard import create_dashboard_chart

class LogThreatApp(tb.Window):
    def __init__(self):
        super().__init__(themename="cyborg")
        self.title("SENTINYL: Threat Detector")
        self.geometry("1400x900")
        
        # Load Icon (Window Title)
        icon_path = os.path.join(os.getcwd(), 'icon.png')
        if os.path.exists(icon_path):
            img = tk.PhotoImage(file=icon_path)
            self.iconphoto(False, img)
        
        # State Variables
        self.alerts_data = []
        self.parsed_logs = []
        self.blocked_ips = set()
        self.email_config = {"enabled": False, "sender": "", "receiver": "", "password": ""}
        self.active_rules = THREAT_PATTERNS
        
        # Rate Limiting
        self.last_email_time = None
        self.email_cooldown = 60 

        self._load_blocked_ips()
        self.create_widgets()

    def _load_blocked_ips(self):
        """Loads blocked IPs from file to prevent duplicate entries across sessions."""
        if os.path.exists("blocked_ips_firewall.txt"):
            try:
                with open("blocked_ips_firewall.txt", "r") as f:
                    for line in f:
                        if line.startswith("DENY FROM "):
                            ip = line.replace("DENY FROM ", "").strip()
                            if ip:
                                self.blocked_ips.add(ip)
            except Exception as e:
                print(f"[-] Error loading blocked IPs: {e}")

    def create_widgets(self):
        # Header
        header_frame = tb.Frame(self, bootstyle="dark")
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        tb.Label(header_frame, text="🛡️ SENTINYL", font=("Impact", 24), bootstyle="danger").pack(side=tk.LEFT, padx=10)
        tb.Label(header_frame, text="| Enterprise Log Security", font=("Helvetica", 12), bootstyle="secondary").pack(side=tk.LEFT, pady=12)
        tb.Button(header_frame, text="⚙️ Config", bootstyle="outline-light", command=self.configure_email).pack(side=tk.RIGHT, padx=10)

        # Tabs
        self.notebook = tb.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

        self.tab_detection = tb.Frame(self.notebook)
        self.notebook.add(self.tab_detection, text="🔍 Detection & Rules")

        self.tab_dashboard = tb.Frame(self.notebook)
        self.notebook.add(self.tab_dashboard, text="📊 Visual Dashboard")
        self.dashboard_frame = tb.Frame(self.tab_dashboard)
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.tab_blocked = tb.Frame(self.notebook)
        self.notebook.add(self.tab_blocked, text="🚫 Blocked IPs")
        self.blocked_display = ScrolledText(self.tab_blocked, width=100, font=("Consolas", 10))
        self.blocked_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Toolbar
        control_frame = tb.Frame(self.tab_detection, padding=10, bootstyle="secondary")
        control_frame.pack(fill=tk.X)

        self.btn_upload = tb.Button(control_frame, text="📂 1. Upload Log", bootstyle="primary", command=self.upload_and_parse)
        self.btn_upload.pack(side=tk.LEFT, padx=5)
        
        self.use_threading = tk.BooleanVar(value=True)
        tb.Checkbutton(control_frame, text="⚡ Multi-Core", variable=self.use_threading, bootstyle="round-toggle").pack(side=tk.LEFT, padx=10)

        self.btn_detect = tb.Button(control_frame, text="▶ 2. Run Detection", bootstyle="danger", command=self.start_detection_thread, state="disabled")
        self.btn_detect.pack(side=tk.LEFT, padx=5)

        tb.Separator(control_frame, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=15)
        tb.Button(control_frame, text="✚ Add Rule", bootstyle="success-outline", command=self.add_rule).pack(side=tk.LEFT, padx=2)
        tb.Button(control_frame, text="🗑️ Remove Rule", bootstyle="warning-outline", command=self.remove_rule).pack(side=tk.LEFT, padx=2)
        tb.Button(control_frame, text="📋 Show Rules", bootstyle="info-outline", command=self.show_rules).pack(side=tk.LEFT, padx=2)
        self.btn_export = tb.Button(control_frame, text="📄 Export PDF", bootstyle="success", command=self.export_report, state="disabled")
        self.btn_export.pack(side=tk.RIGHT, padx=5)

        # Split Panels (Treeviews)
        paned = tb.Panedwindow(self.tab_detection, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left Tree
        left_frame = tb.Frame(paned)
        paned.add(left_frame, weight=1)
        tb.Label(left_frame, text="Parsed Logs Input", font=("Arial", 10, "bold")).pack(anchor="w")
        
        cols_left = ("time", "ip", "status", "request")
        self.log_tree = ttk.Treeview(left_frame, columns=cols_left, show='headings', height=20)
        self.log_tree.heading("time", text="Time"); self.log_tree.column("time", width=140)
        self.log_tree.heading("ip", text="IP Address"); self.log_tree.column("ip", width=120)
        self.log_tree.heading("status", text="Stat"); self.log_tree.column("status", width=60)
        self.log_tree.heading("request", text="Request"); self.log_tree.column("request", width=350)
        
        v_sl = tb.Scrollbar(left_frame, orient="vertical", command=self.log_tree.yview)
        h_sl = tb.Scrollbar(left_frame, orient="horizontal", command=self.log_tree.xview)
        self.log_tree.configure(yscrollcommand=v_sl.set, xscrollcommand=h_sl.set)
        v_sl.pack(side=tk.RIGHT, fill=tk.Y); h_sl.pack(side=tk.BOTTOM, fill=tk.X); self.log_tree.pack(fill=tk.BOTH, expand=True)

        # Right Tree
        right_frame = tb.Frame(paned)
        paned.add(right_frame, weight=1)
        tb.Label(right_frame, text="Alert Panel (Threats)", font=("Arial", 10, "bold"), bootstyle="danger").pack(anchor="w")
        
        cols_right = ("rule", "time", "ip", "snippet")
        self.alert_tree = ttk.Treeview(right_frame, columns=cols_right, show='headings', height=20)
        self.alert_tree.heading("rule", text="Rule Detected"); self.alert_tree.column("rule", width=150)
        self.alert_tree.heading("time", text="Time"); self.alert_tree.column("time", width=140)
        self.alert_tree.heading("ip", text="Attacker IP"); self.alert_tree.column("ip", width=120)
        self.alert_tree.heading("snippet", text="Payload Snippet"); self.alert_tree.column("snippet", width=250)
        
        v_sr = tb.Scrollbar(right_frame, orient="vertical", command=self.alert_tree.yview)
        h_sr = tb.Scrollbar(right_frame, orient="horizontal", command=self.alert_tree.xview)
        self.alert_tree.configure(yscrollcommand=v_sr.set, xscrollcommand=h_sr.set)
        v_sr.pack(side=tk.RIGHT, fill=tk.Y); h_sr.pack(side=tk.BOTTOM, fill=tk.X); self.alert_tree.pack(fill=tk.BOTH, expand=True)

    def upload_and_parse(self):
        file_path = filedialog.askopenfilename()
        if not file_path: return
        for i in self.log_tree.get_children(): self.log_tree.delete(i)
        for i in self.alert_tree.get_children(): self.alert_tree.delete(i)
        self.parsed_logs = []; self.alerts_data = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for line in lines:
                    parsed = parse_log_line(line)
                    if parsed:
                        self.parsed_logs.append(parsed)
                        self.log_tree.insert("", "end", values=(parsed.get('time','-'), parsed.get('ip','-'), parsed.get('status','-'), parsed.get('request','-')))
            messagebox.showinfo("Success", f"Loaded {len(self.parsed_logs)} logs.")
            self.btn_detect.config(state="normal")
        except Exception as e: messagebox.showerror("Error", f"Failed: {e}")

    # --- UPDATED BUTTON LOCKING LOGIC ---
    def start_detection_thread(self):
        self.btn_detect.config(state="disabled", text="⏳ Scanning...")
        self.btn_upload.config(state="disabled")
        threading.Thread(target=self.run_detection, daemon=True).start()

    def run_detection(self):
        if not self.parsed_logs: 
            self.reset_buttons()
            return
        threat_count = 0
        try:
            if self.use_threading.get():
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                    results = list(executor.map(self.analyze_single_log, self.parsed_logs))
            else:
                results = [self.analyze_single_log(log) for log in self.parsed_logs]

            for res in results:
                if res:
                    threat_count += 1
                    self.alerts_data.append(res)
                    self.alert_tree.insert("", "end", values=(res['Threat Type'], res['Timestamp'], res['Attacker IP'], res['Snippet']))
                    self.auto_block_ip(res['Attacker IP'])
                    if "SQL" in res['Threat Type'] or "Ransomware" in res['Threat Type']:
                        self.attempt_email_alert(res['Threat Type'], res['Attacker IP'])

            self.btn_export.config(state="normal")
            messagebox.showinfo("Scan Complete", f"Analysis Finished.\nTotal Threats: {threat_count}")
            self.after(0, lambda: self.on_tab_change(None))
        except Exception as e: messagebox.showerror("Scan Error", str(e))
        finally: self.reset_buttons()

    def reset_buttons(self):
        self.btn_detect.config(state="normal", text="▶ 2. Run Detection")
        self.btn_upload.config(state="normal")

    def analyze_single_log(self, log):
        clean_req = normalize_payload(log.get('request', ''))
        threats = detect_threats(clean_req, log.get('ip'))
        if threats:
            return {"Timestamp": log.get('time', 'N/A'), "Attacker IP": log.get('ip', 'N/A'), "Threat Type": ", ".join(threats), "Snippet": log.get('request', '')[:100]}
        return None

    def add_rule(self):
        name = simpledialog.askstring("Add Rule", "Rule Name:"); 
        if name: 
            p = simpledialog.askstring("Add Rule", "Regex Pattern:")
            if p: self.active_rules[name] = p; messagebox.showinfo("Success", f"Rule '{name}' added.")
    
    def remove_rule(self):
        name = simpledialog.askstring("Remove Rule", "Name:")
        if name and name in self.active_rules: del self.active_rules[name]; messagebox.showinfo("Success", "Removed.")
        elif name: messagebox.showerror("Error", "Not found.")

    def show_rules(self):
        top = tb.Toplevel(self); top.title("Active Rules"); top.geometry("600x400")
        txt = ScrolledText(top, font=("Consolas", 10)); txt.pack(fill=tk.BOTH, expand=True)
        for n, p in self.active_rules.items(): txt.text.insert(tk.END, f"RULE: {n}\nREGEX: {p}\n{'-'*40}\n")

    def auto_block_ip(self, ip):
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.blocked_display.text.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] BLOCKED: {ip}\n", "danger")
            self.blocked_display.text.tag_config("danger", foreground="red")
            with open("blocked_ips_firewall.txt", "a") as f: f.write(f"DENY FROM {ip}\n")

    def attempt_email_alert(self, threat, ip):
        if not self.email_config["enabled"]: return
        now = datetime.datetime.now()
        if self.last_email_time is None or (now - self.last_email_time).total_seconds() > self.email_cooldown:
            self.last_email_time = now
            threading.Thread(target=self._send_mail, args=(threat, ip)).start()

    def _send_mail(self, threat, ip):
        try:
            msg = EmailMessage(); msg.set_content(f"ALERT: {threat} from {ip}")
            msg['Subject'] = f"SENTINYL ALERT: {threat}"; msg['From'] = self.email_config["sender"]; msg['To'] = self.email_config["receiver"]
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465); server.login(self.email_config["sender"], self.email_config["password"])
            server.send_message(msg); server.quit()
        except: pass

    def configure_email(self):
        s = simpledialog.askstring("SMTP", "Sender Email:")
        if s:
            p = simpledialog.askstring("SMTP", "App Password:", show='*')
            r = simpledialog.askstring("SMTP", "Receiver Email:")
            self.email_config = {"enabled": True, "sender": s, "receiver": r, "password": p}

    def export_report(self):
        if self.alerts_data:
            path = generate_pdf_report(self.alerts_data)
            messagebox.showinfo("PDF Export", f"Report saved:\n{path}")
            
    def on_tab_change(self, event):
        if self.notebook.index(self.notebook.select()) == 1: create_dashboard_chart(self.dashboard_frame, self.alerts_data)