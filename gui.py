import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

def rabin_karp(text, pattern, q=101):
    d = 256
    M = len(pattern)
    N = len(text)
    p = 0
    t = 0
    h = 1

    for i in range(M - 23):
        h = (h * d) % q

    for i in range(M):
        p = (d * p + ord(pattern[i])) % q
        t = (d * t + ord(text[i])) % q

    for i in range(N - M + 1):
        if p == t:
            if text[i:i + M] == pattern:
                return True
        if i < N - M:
            t = (d * (t - ord(text[i]) * h) + ord(text[i + M])) % q
            if t < 0:
                t += q
    return False

def load_signatures(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def scan_log_file(log_path, signatures):
    with open(log_path, 'r') as file:
        lines = file.readlines()
        alerts = []
        for line_number, line in enumerate(lines, start=1):
            for sig in signatures:
                if rabin_karp(line.lower(), sig.lower()):
                    alerts.append(f"[ALERT] Threat Detected: '{sig}' in Line {line_number}")
                    break
    return alerts

def browse_file(entry):
    file_path = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, file_path)

def run_scan():
    sig_path = sig_entry.get()
    log_path = log_entry.get()
    if not sig_path or not log_path:
        messagebox.showerror("Error", "Please select both files.")
        return
    try:
        signatures = load_signatures(sig_path)
        alerts = scan_log_file(log_path, signatures)
        output.delete(1.0, tk.END)
        if alerts:
            for alert in alerts:
                output.insert(tk.END, alert + "\n")
        else:
            output.insert(tk.END, "No threats detected.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

app = tk.Tk()
app.title("Rabin-Karp IDS")
app.geometry("600x400")

tk.Label(app, text="Signature File:").pack()
sig_entry = tk.Entry(app, width=60)
sig_entry.pack()
tk.Button(app, text="Browse", command=lambda: browse_file(sig_entry)).pack()

tk.Label(app, text="Log File:").pack()
log_entry = tk.Entry(app, width=60)
log_entry.pack()
tk.Button(app, text="Browse", command=lambda: browse_file(log_entry)).pack()

tk.Button(app, text="Run Scan", command=run_scan).pack(pady=10)

output = scrolledtext.ScrolledText(app, width=70, height=15)
output.pack()

app.mainloop()
