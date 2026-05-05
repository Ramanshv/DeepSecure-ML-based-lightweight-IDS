"""
config.py – Central configuration for DeepSecure IDS.

All hardcoded values have been moved here.
Values can be overridden by a .env file or environment variables.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env if it exists (no-op if it doesn't)
load_dotenv()

# ── Project Root ──────────────────────────────────────────────
ROOT = Path(__file__).parent

# ── Paths ─────────────────────────────────────────────────────
TRAIN_PATH      = os.getenv("TRAIN_PATH",      str(ROOT / "arch/nsl-kdd/KDDTrain+.txt"))
TEST_PATH       = os.getenv("TEST_PATH",        str(ROOT / "arch/nsl-kdd/KDDTest+.txt"))
VALIDATION_PATH = os.getenv("VALIDATION_PATH", str(ROOT / "arch/nsl-kdd/KDDTest-21.txt"))
MODEL_PATH      = os.getenv("MODEL_PATH",       str(ROOT / "models/deepsecure.pkl"))
FEATURES_PATH   = os.getenv("FEATURES_PATH",    str(ROOT / "models/selected_features.txt"))
ALERT_LOG_PATH  = os.getenv("ALERT_LOG_PATH",   str(ROOT / "outputs/alert_log.csv"))

# ── Extra datasets (optional — set env var to override path) ─────────────────
# CICIDS-2017: merged single CSV → arch/cicids2017.csv
CICIDS_PATH   = os.getenv("CICIDS_PATH", str(ROOT / "arch/cicids2017.csv"))

# UNSW-NB15: use the labelled training+testing sets (have attack_cat column)
#   arch/UNSW-NB15/Training and Testing Sets/
UNSW_PATH     = os.getenv("UNSW_PATH",   str(ROOT / "arch/UNSW-NB15/Training and Testing Sets"))

# Auto-create output folder so callers never have to worry about it
Path(ALERT_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
Path(MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)

# ── Training ──────────────────────────────────────────────────
FORCE_RETRAIN = os.getenv("FORCE_RETRAIN", "true").lower() == "true"

# ── Dataset columns (KDD Cup 99 / NSL-KDD) ────────────────────
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty",
]

# ── Live Capture ──────────────────────────────────────────────────────────
# Comma-separated interfaces. For local attack simulation include 'lo0'.
# Run `ifconfig` to see available interfaces on this machine.
CAPTURE_INTERFACES  = os.getenv("CAPTURE_INTERFACES", "en0,lo0")
CAPTURE_INTERFACE   = CAPTURE_INTERFACES.split(",")[0].strip()  # legacy compat
CAPTURE_BATCH_SIZE  = int(os.getenv("CAPTURE_BATCH_SIZE", "50"))  # evaluate ML every N packets
MAX_ALERT_LOG       = int(os.getenv("MAX_ALERT_LOG", "500"))
DETECTION_THRESHOLD = float(os.getenv("DETECTION_THRESHOLD", "0.80"))

# ── Rule-Based Detection Thresholds ───────────────────────────────────────
# Port scan: unique dst ports from same source within window
SCAN_WINDOW_S        = int(os.getenv("SCAN_WINDOW_S",        "30"))
SCAN_PORT_THRESHOLD  = int(os.getenv("SCAN_PORT_THRESHOLD",  "15"))   # → POTENTIAL
SCAN_HIGH_THRESHOLD  = int(os.getenv("SCAN_HIGH_THRESHOLD",  "50"))   # → HIGH
SCAN_CRIT_THRESHOLD  = int(os.getenv("SCAN_CRIT_THRESHOLD",  "200"))  # → CRITICAL

# SYN flood: SYN-only packets to same dst:port within window
SYN_FLOOD_WINDOW_S   = int(os.getenv("SYN_FLOOD_WINDOW_S",   "5"))
SYN_FLOOD_THRESHOLD  = int(os.getenv("SYN_FLOOD_THRESHOLD",  "20"))

# Connection flood: new connections to same dst:port within window
CONN_FLOOD_WINDOW_S  = int(os.getenv("CONN_FLOOD_WINDOW_S",  "10"))
CONN_FLOOD_THRESHOLD = int(os.getenv("CONN_FLOOD_THRESHOLD", "50"))

# ICMP flood: high-rate pings (ping -f)
ICMP_FLOOD_WINDOW_S  = int(os.getenv("ICMP_FLOOD_WINDOW_S",  "3"))
ICMP_FLOOD_THRESHOLD = int(os.getenv("ICMP_FLOOD_THRESHOLD", "50"))

# Cooldown: seconds before re-alerting same source for the same rule
ALERT_COOLDOWN_S     = int(os.getenv("ALERT_COOLDOWN_S", "15"))


# ── Web Dashboard ─────────────────────────────────────────────
FLASK_HOST  = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT  = int(os.getenv("FLASK_PORT", "5000"))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
SECRET_KEY  = os.getenv("SECRET_KEY", "dev-secret-change-me")
