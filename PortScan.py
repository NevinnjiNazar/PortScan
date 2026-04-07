import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox

PORTS = [80, 443, 3389, 21, 22, 23, 25, 53, 110, 143, 3306, 5900, 6379, 8080]
PORT_INFO = {
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
}

def explain_connect_ex(code: int) -> str:
    if code == 0:
        return "OPEN"

    winsock = {
        10061: "CLOSED",
        10060: "NO RESPONSE",
        10065: "HOST UNREACHABLE",
        10051: "NETWORK UNREACHABLE",
        11001: "HOST NOT FOUND",
    }
    if code in winsock:
        return winsock[code]

    return f"ERROR (CODE: {code})"


class PortScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Port Scanner")
        self.geometry("860x560")
        self.minsize(760, 520)

        self._init_style()

        self._worker_thread = None
        self._stop_flag = threading.Event()

        self._build_ui()

    def _init_style(self):
        self.style = ttk.Style(self)

        for theme in ("vista", "xpnative", "aqua", "clam", "alt", "default"):
            if theme in self.style.theme_names():
                self.style.theme_use(theme)
                break

        self.configure(bg=self._bg())

        self.style.configure("App.TFrame", background=self._bg())
        self.style.configure("Card.TFrame", background=self._card_bg(), relief="flat")

        self.style.configure(
            "Title.TLabel",
            background=self._bg(),
            foreground=self._fg(),
            font=("Segoe UI", 16, "bold"),
        )
        self.style.configure(
            "Sub.TLabel",
            background=self._bg(),
            foreground=self._muted(),
            font=("Segoe UI", 10),
        )

        self.style.configure(
            "CardTitle.TLabel",
            background=self._card_bg(),
            foreground=self._fg(),
            font=("Segoe UI", 11, "bold"),
        )
        self.style.configure(
            "CardText.TLabel",
            background=self._card_bg(),
            foreground=self._muted(),
            font=("Segoe UI", 10),
        )

        self.style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(12, 6))
        self.style.configure("Secondary.TButton", font=("Segoe UI", 10), padding=(12, 6))

        self.style.configure(
            "Status.TLabel",
            background=self._card_bg(),
            foreground=self._muted(),
            font=("Segoe UI", 10),
        )

        self.style.configure("Treeview", font=("Segoe UI", 10), rowheight=26)
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

        self.style.configure(
            "Ok.TLabel",
            background=self._card_bg(),
            foreground="#1b7f3a",
            font=("Segoe UI", 10, "bold"),
        )
        self.style.configure(
            "Warn.TLabel",
            background=self._card_bg(),
            foreground="#b45309",
            font=("Segoe UI", 10, "bold"),
        )
        self.style.configure(
            "Bad.TLabel",
            background=self._card_bg(),
            foreground="#b91c1c",
            font=("Segoe UI", 10, "bold"),
        )

    def _bg(self):      return "#FFFFFF"
    def _card_bg(self): return "#FFFFFF"
    def _fg(self):      return "#000000"
    def _muted(self):   return "#000000"

    def _build_ui(self):
        root = ttk.Frame(self, style="App.TFrame", padding=16)
        root.pack(fill="both", expand=True)

        header = ttk.Frame(root, style="App.TFrame")
        header.pack(fill="x")

        ttk.Label(header, text="Port Scanner", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Scanning a preset list of popular ports (TCP connect_ex).",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        content = ttk.Frame(root, style="App.TFrame")
        content.pack(fill="both", expand=True, pady=(14, 0))
        content.columnconfigure(0, weight=1)
        content.rowconfigure(1, weight=1)

        controls = ttk.Frame(content, style="Card.TFrame", padding=14)
        controls.grid(row=0, column=0, sticky="we")
        controls.columnconfigure(1, weight=1)

        ttk.Label(controls, text="Settings", style="CardTitle.TLabel").grid(
            row=0, column=0, columnspan=6, sticky="w", pady=(0, 10)
        )

        ttk.Label(controls, text="Target (hostname/IP)", style="CardText.TLabel").grid(
            row=1, column=0, sticky="w"
        )
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(controls, textvariable=self.target_var, width=40)
        self.target_entry.grid(row=1, column=1, sticky="we", padx=(10, 14))
        self.target_entry.focus_set()

        ttk.Label(controls, text="Timeout (ms)", style="CardText.TLabel").grid(
            row=1, column=2, sticky="w"
        )
        self.timeout_var = tk.StringVar(value="500")
        self.timeout_entry = ttk.Entry(controls, textvariable=self.timeout_var, width=10)
        self.timeout_entry.grid(row=1, column=3, sticky="w", padx=(10, 14))

        self.scan_btn = ttk.Button(controls, text="Scan", style="Primary.TButton", command=self.start_scan)
        self.scan_btn.grid(row=1, column=4, sticky="e")

        self.stop_btn = ttk.Button(
            controls,
            text="Stop",
            style="Secondary.TButton",
            command=self.stop_scan,
            state="disabled",
        )
        self.stop_btn.grid(row=1, column=5, sticky="e", padx=(10, 0))

        self.status_var = tk.StringVar(value="Ready.")
        self.status_label = ttk.Label(controls, textvariable=self.status_var, style="Status.TLabel")
        self.status_label.grid(row=2, column=0, columnspan=6, sticky="we", pady=(10, 0))

        self.progress = ttk.Progressbar(controls, mode="determinate", maximum=len(PORTS))
        self.progress.grid(row=3, column=0, columnspan=6, sticky="we", pady=(10, 0))

        results = ttk.Frame(content, style="Card.TFrame", padding=14)
        results.grid(row=1, column=0, sticky="nsew", pady=(14, 0))
        results.columnconfigure(0, weight=1)
        results.rowconfigure(1, weight=1)

        top_row = ttk.Frame(results, style="Card.TFrame")
        top_row.grid(row=0, column=0, sticky="we")
        top_row.columnconfigure(0, weight=1)

        ttk.Label(top_row, text="Results", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")

        self.open_ports_var = tk.StringVar(value="—")
        self.open_ports_label = ttk.Label(top_row, textvariable=self.open_ports_var, style="CardText.TLabel")
        self.open_ports_label.grid(row=0, column=1, sticky="e")

        columns = ("port", "service", "status")
        self.tree = ttk.Treeview(results, columns=columns, show="headings", height=12)

        self.tree.heading("port", text="Port")
        self.tree.heading("service", text="Service")
        self.tree.heading("status", text="Status")

        self.tree.column("port", width=90, anchor="center")
        self.tree.column("service", width=180, anchor="w")
        self.tree.column("status", width=280, anchor="w")

        vsb = ttk.Scrollbar(results, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        vsb.grid(row=1, column=1, sticky="ns", pady=(12, 0))

        self.tree.tag_configure("odd", background="#ffffff", foreground=self._fg())
        self.tree.tag_configure("even", background="#ffffff", foreground=self._fg())
        self.tree.tag_configure("open", foreground="#22c55e")
        self.tree.tag_configure("closed", foreground="#f59e0b")
        self.tree.tag_configure("error", foreground="#ef4444")

    def _set_controls_running(self, running: bool):
        self.scan_btn.config(state="disabled" if running else "normal")
        self.stop_btn.config(state="normal" if running else "disabled")
        self.target_entry.config(state="disabled" if running else "normal")
        self.timeout_entry.config(state="disabled" if running else "normal")

    def start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target hostname/IP.")
            return

        try:
            timeout_ms = int(self.timeout_var.get().strip())
            if timeout_ms <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Timeout must be a positive integer (ms).")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.open_ports_var.set("Open ports: —")
        self.progress["value"] = 0

        self._stop_flag.clear()
        self._set_controls_running(True)
        self.status_var.set("Resolving host...")

        self._worker_thread = threading.Thread(
            target=self._scan_worker,
            args=(target, timeout_ms),
            daemon=True,
        )
        self._worker_thread.start()

    def stop_scan(self):
        self._stop_flag.set()
        self.status_var.set("Stopping...")

    def _scan_worker(self, target: str, timeout_ms: int):
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            self._ui_error(f"DNS/target error: {e}")
            return

        self._ui_status(f"Resolved {target} -> {ip}. Scanning {len(PORTS)} ports...")
        open_ports = []

        for i, port in enumerate(PORTS, start=1):
            if self._stop_flag.is_set():
                self._ui_status("Stopped.")
                break

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_ms / 1000.0)

            try:
                code = s.connect_ex((ip, port))
            except OSError as e:
                code = -1
                status = f"ERROR ({e})"
            else:
                status = explain_connect_ex(code)
            finally:
                try:
                    s.close()
                except Exception:
                    pass

            port_name = PORT_INFO.get(port, "UNKNOWN")

            stripe = "even" if (i % 2 == 0) else "odd"
            if status == "OPEN":
                tag = ("open", stripe)
            elif status in ("CLOSED", "NO RESPONSE", "HOST UNREACHABLE", "NETWORK UNREACHABLE", "HOST NOT FOUND"):
                tag = ("closed", stripe)
            elif status.startswith("ERROR"):
                tag = ("error", stripe)
            else:
                tag = (stripe,)

            self._ui_add_row(port, port_name, status, tag)
            self._ui_progress(i)

            if code == 0:
                open_ports.append(port)

        if not self._stop_flag.is_set():
            self._ui_status("Done.")

        if open_ports:
            summary = ", ".join(f"{p} ({PORT_INFO.get(p, 'UNKNOWN')})" for p in open_ports)
        else:
            summary = "No open ports found (from the preset list)."

        self._ui_open_ports(f"Open ports: {summary}")
        self._ui_done()

    def _ui_add_row(self, port: int, service: str, status: str, tags=()):
        self.after(0, lambda: self.tree.insert("", "end", values=(port, service, status), tags=tags))

    def _ui_progress(self, value: int):
        self.after(0, lambda: self.progress.configure(value=value))

    def _ui_status(self, text: str):
        self.after(0, lambda: self.status_var.set(text))

    def _ui_open_ports(self, text: str):
        self.after(0, lambda: self.open_ports_var.set(text))

    def _ui_done(self):
        self.after(0, lambda: self._set_controls_running(False))

    def _ui_error(self, text: str):
        def _show():
            self._set_controls_running(False)
            self.status_var.set("Ready.")
            messagebox.showerror("Error", text)

        self.after(0, _show)


if __name__ == "__main__":
    app = PortScannerApp()
    app.mainloop()