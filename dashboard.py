import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from io import StringIO

def rabin_karp(text, pattern, q=101):
    d = 256
    M = len(pattern)
    N = len(text)
    p = 0
    t = 0
    h = 1

    for i in range(M - 1):
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

def scan_log_file(log_lines, signatures):
    alerts = []
    for line_number, line in enumerate(log_lines, start=1):
        for sig in signatures:
            if rabin_karp(line.lower(), sig.lower()):
                alerts.append((line_number, sig, line.strip()))
                break
    return alerts

# Streamlit UI
st.set_page_config(page_title="Intrusion Detection Dashboard", layout="wide")
st.title("🔐 Intrusion Detection Dashboard")
st.markdown("Analyze log files using Rabin-Karp Pattern Matching")

sig_file = st.file_uploader("📥 Upload Signature File", type="txt")
log_file = st.file_uploader("📥 Upload Log File", type="txt")

if sig_file and log_file:
    sig_lines = [line.decode("utf-8").strip() for line in sig_file.readlines() if line.strip()]
    log_lines = [line.decode("utf-8") for line in log_file.readlines()]

    if st.button("🚨 Run Scan"):
        results = scan_log_file(log_lines, sig_lines)
        if results:
            st.success(f"✅ {len(results)} threats detected!")
            df = pd.DataFrame(results, columns=["Line Number", "Signature", "Log Line"])
            st.dataframe(df)

            # Graph: Frequency of threats over log lines (smaller size)
            line_counts = df["Line Number"].value_counts().sort_index()
            fig, ax = plt.subplots(figsize=(6, 3))  # Reduced size
            ax.plot(line_counts.index, line_counts.values, marker='o')
            ax.set_title("Threat Frequency Over Log Lines")
            ax.set_xlabel("Line Number")
            ax.set_ylabel("Number of Threats")
            st.pyplot(fig)

            # Download CSV
            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Download Report as CSV", data=csv, file_name="threat_report.csv", mime="text/csv")

        else:
            st.success("🎉 No threats detected!")
