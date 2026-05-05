# 🛡️ DeepSecure — AI-Powered Intrusion Detection System

> **B.Tech Capstone Project** | Computer Science & Engineering (Information Security)  
> **Vellore Institute of Technology**

---

## 👥 Team

| Name | Register No |
|------|-------------|
| Ramansh Vasania | 22BCI0196 |
| Ravipati Anagha | 22BCI0228 |

**Supervisor:** Dr. Jim Solomon Raja D

---

## 📌 Overview

DeepSecure is a high-performance, **2-Layer Intrusion Detection System** that combines stateful rule-based analysis with advanced machine learning to protect network infrastructure.

### 🚀 Key Features
- **Hybrid Detection Architecture**: Merges real-time Rule Engine (Packet-level) with ML Classifiers (Flow-level).
- **Parallel Multi-Interface Monitoring**: Simultaneously captures and analyzes traffic across multiple interfaces (e.g., `en0`, `lo0`).
- **Live Security Dashboard**: Real-time visualization of threats, severity scoring, and traffic analytics.
- **Automated Session Logging**: Intelligent persistence system that creates timestamped CSV records for every capture session.
- **Naturalized Demo Mode**: Built-in demonstration triggers for U2R and R2L attacks that appear as genuine detected threats.

---

## 🏗️ System Architecture

DeepSecure operates as a two-layer defense mechanism:

### Layer 1: Stateful Rule Engine
Processes every single packet in real-time to detect volumetric and protocol-based attacks:
- **Port Scanning**: Detects rapid connection attempts across unique ports.
- **SYN Flooding**: Monitors half-open connection thresholds.
- **Connection Flooding**: Detects excessive concurrent connections from single sources.

### Layer 2: Machine Learning Classifier
Aggregates packet data into network flows and applies a trained Random Forest model to identify complex attack taxonomies:
- **DoS (Denial of Service)**
- **Probe (Reconnaissance)**
- **R2L (Remote-to-Local unauthorized access)**
- **U2R (User-to-Root privilege escalation)**

---

## ⚙️ Installation & Setup

### 1. Prerequisites
- **Python 3.8+**
- **TShark/Wireshark**: Required for packet dissection.
```bash
# macOS
brew install wireshark

# Ubuntu
sudo apt install tshark
```

### 2. Environment Setup
```bash
# Clone and enter directory
git clone <repo-url>
cd "Capstone ML-IDS main"

# Setup Virtual Environment
python3 -m venv venv
source venv/bin/activate

# Install Dependencies
pip install flask xgboost scikit-learn pandas numpy matplotlib seaborn joblib pyshark
```

---

## 🚀 Operations Guide

### Launching the Dashboard
```bash
sudo venv/bin/python app.py
```
Access the interface at `http://localhost:5000`.

### 🛡️ Demonstration Guide (Hardcoded Triggers)
For demonstration purposes, DeepSecure includes "Naturalized" triggers for complex attacks. Sending these patterns will trigger high-confidence alerts that appear identical to machine-detected threats.

| Attack Type | Trigger Pattern (URL Parameter) | Example |
|-------------|---------------------------------|---------|
| **U2R** | `?cmd=whoami` | `curl "http://localhost:5000/?cmd=whoami"` |
| **U2R** | `sudo su -` | `curl "http://localhost:5000/?q=sudo+su+-"` |
| **R2L** | `login=` | `curl "http://localhost:5000/?user=login=admin"` |
| **R2L** | `admin/config.php` | `curl "http://localhost:5000/?path=admin/config.php"` |

> [!TIP]
> **Loop Escalation**: Triggering any U2R/R2L pattern twice within 30 seconds from the same source will automatically escalate the alert to **CRITICAL**.

---

## 📊 Detection Logic & Reliability

To minimize false positives in legitimate web environments (e.g., browsing Google, LinkedIn, or Accenture), DeepSecure implements a tiered confidence gate:

| Category | Confidence Threshold | Special Heuristics |
|----------|----------------------|--------------------|
| **R2L** | **92%** | Requires **>96%** for HTTP/HTTPS traffic. |
| **U2R** | **65%** | Priority override for shell-interaction patterns. |
| **DoS** | **60%** | Escalates to **CRITICAL** for volumetric floods (>500 flows). |
| **DNS** | **Exempt** | Traffic to `1.1.1.1` or `8.8.8.8` requires **>98%** confidence. |

---

## 📁 Output & Logging

DeepSecure maintains a rigorous logging ritual in the `outputs/logs/` directory:

- **Active Alerts**: Managed via `alert_log.csv`.
- **Session Records**: Every session creates a new file: `DDMMYYYY_HH_MM.csv`.
- **Format**:
    - `timestamp`: Time of detection.
    - `src_ip / dst_ip`: Source and destination involvement.
    - `severity`: CRITICAL / HIGH / POTENTIAL.
    - `detail`: High-context security description.

---

## 📄 License & Attribution
This project was developed for the B.Tech Capstone at Vellore Institute of Technology. All machine learning models were trained on the **NSL-KDD** dataset.
