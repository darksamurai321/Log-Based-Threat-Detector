# SENTINYL: Enterprise Threat Detection & Auto-Defense System

**SENTINYL** is a high-performance, Python-based cybersecurity tool designed to detect, analyze, and actively respond to network threats in real-time. It features an **Active Defense Engine** that blocks malicious IPs and sends instant alerts, designed to handle high-throughput logs.

The system combines **Signature-Based Detection** (Regex) with **Threat Intelligence** (IOCs) to identify sophisticated attacks like SQL Injection, Ransomware, and Cryptominers, even when payloads are obfuscated.

## 🚀 Enterprise Features (Client Requirements)

* **🛡️ Active Defense (Auto-Block):**
    * Automatically extracts attacker IPs and adds them to a persistent `blocked_ips_firewall.txt` list.
    * Proactively stops recurring attacks.
* **⚡ Scalable Load Balancing:**
    * Implements **Multi-Core Processing** (`concurrent.futures`) to analyze massive log files (1M+ lines) without freezing the GUI.
* **📧 Smart SMTP Alerts:**
    * Features a **Notification Rate Limiter** to prevent inbox flooding during massive attacks. Sends summarized alerts for high-risk threats.
* **🧠 Advanced Normalization:**
    * Decodes Double URL Encoding (`%255c`), HTML Entities, and Base64 before analysis.
* **📊 Visual Dashboard:**
    * Interactive `matplotlib` charts showing the "Top 10" threat distribution.
* **📄 Professional Reporting:**
    * Generates **PDF Audit Reports** with remediation recommendations (not just CSV).

## 🛠️ Installation

1.  **Prerequisites**
    * Python 3.10+

2.  **Install Dependencies**
    ```bash
    pip install matplotlib ttkbootstrap fpdf
    ```

## 🖥️ Usage Workflow

1.  **Launch SENTINYL**
    ```bash
    python src/main.py

    Exe Files will be located at /Log-Based-Detector/dist/
    ```

2.  **Step 1: Upload & Parse**
    * Click **"1. Upload & Parse Log"**.
    * Supports both Standard Apache/Nginx logs and Custom formats.
    * *Tip:* Check **"Enable Load Balancing"** for large files.

3.  **Step 2: Detect & Respond**
    * Click **"2. Run Detection"**.
    * The system scans for **35+ Attack Patterns** (SQLi, XSS, Ransomware, Log4j).
    * Malicious IPs are **Auto-Blocked** immediately.
    * Email alerts are sent for critical incidents.

4.  **Step 3: Analyze & Export**
    * View the **Visual Dashboard** for a threat breakdown.
    * Click **"📄 Export PDF"** to generate the final security report.

## 📂 Project Structure

```text
SENTINYL/
├── data/
│   ├── malicious_ips.csv   # Threat Intelligence (IOCs)
│   └── generated_traffic.log
├── src/
│   ├── main.py             # Entry Point
│   ├── gui.py              # Interface with Load Balancing & SMTP
│   ├── detection.py        # Enterprise Rule Pack (Ransomware/Miners)
│   ├── normalization.py    # Decoding Engine
│   ├── parsers.py          # Robust Log Parser
│   ├── reporter.py         # PDF Report Generator
│   └── dashboard.py        # Scalable Visualization
└── README.md