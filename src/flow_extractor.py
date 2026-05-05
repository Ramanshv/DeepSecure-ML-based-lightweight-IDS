"""
src/flow_extractor.py – Extracts per-flow network features from raw packets.

Produces a feature vector aligned with the NSL-KDD schema so the live-capture
path feeds the same model that was trained on dataset flows.

Features computed
-----------------
NSL-KDD original (41):        All fields that can be observed from raw packets.
Extended live features:       Rate-based and ratio features derived in export_flows().

Key design decisions
--------------------
- One flow = (src_ip, dst_ip, protocol).  State accumulates until export_flows()
  is called (every N packets in app.py).
- Rates (serror_rate, rerror_rate, same_srv_rate, etc.) are computed at export
  time from accumulated per-packet counters.
- Features that require deep application inspection (logged_in, num_compromised,
  etc.) are heuristically inferred from TCP flag patterns.
"""

import time
import pandas as pd
from collections import defaultdict
from pathlib import Path

from src.logger import get_logger

logger = get_logger(__name__)

# ── Service port mapping (subset of NSL-KDD service labels) ──────────────────
COMMON_PORTS: dict[str, str] = {
    "20": "ftp_data", "21": "ftp", "22": "ssh", "23": "telnet",
    "25": "smtp",     "53": "domain", "67": "domain_u", "68": "domain_u",
    "79": "finger",   "80": "http",  "110": "pop_3",  "111": "sunrpc",
    "113": "auth",    "119": "nntp", "123": "ntp_u",  "135": "loc_srv",
    "139": "netbios_ssn", "143": "imap4", "179": "bgp", "389": "ldap",
    "443": "http",    "445": "netbios_ssn", "514": "shell", "515": "printer",
    "587": "smtp",    "993": "imap4", "995": "pop_3", "1080": "other",
    "1433": "mssql_s", "1521": "sql_net", "3306": "other", "3389": "other",
    "5432": "other",  "6667": "IRC",  "8080": "http",   "8443": "http",
}


def _empty_flow() -> dict:
    return {
        "start":           time.time(),
        # byte counters
        "src_bytes":       0,
        "dst_bytes":       0,
        # packet counters
        "count":           0,
        # TCP flag counters
        "syn_count":       0,
        "rst_count":       0,
        "fin_count":       0,
        "ack_count":       0,
        "urg_count":       0,          # URG flag
        # Error counters
        "serror_count":    0,          # SYN-only (no ACK) = connection error
        "rerror_count":    0,          # RST = rejected
        # Fragmentation / misc
        "wrong_fragment":  0,
        "urgent":          0,          # URG pointer set
        "land":            0,          # src == dst IP flag
        # Service tracking (per-port packet counts)
        "srv_port_counts": defaultdict(int),   # dst_port → pkt count
        "dst_host_set":    set(),              # unique dst IPs seen
        "src_host_set":    set(),              # unique src IPs per dst
        # Hot (privileged ops heuristic): high src_bytes flow, not HTTP/53
        "hot":             0,
        # Successive connections in same host / service window
        "_dest_srv_counts": defaultdict(int),  # service → count
        "_dest_port_hist":  [],                # list of dst_ports (for ratios)
        "u2r_hits":         0,                 # demonstration "codes" found in payload
        "r2l_hits":         0,                 # R2L patterns detected (login/passwd/config)
    }


class FlowExtractor:
    def __init__(self):
        self.flows: dict = defaultdict(_empty_flow)
        # Global counters used for cross-flow rate computation
        self._all_dst_hosts: defaultdict = defaultdict(int)   # dst_ip → flow count
        self._all_services:  defaultdict = defaultdict(int)   # service → flow count

    # ── Packet ingestion ──────────────────────────────────────────────────

    def process_packet(self, packet):
        try:
            if not hasattr(packet, "ip"):
                return

            src   = str(packet.ip.src)
            dst   = str(packet.ip.dst)
            proto = getattr(packet, "transport_layer", None) or "unknown"
            key   = (src, dst, proto)

            f = self.flows[key]
            f["count"]     += 1
            f["src_bytes"] += int(packet.length)

            # Detect land attack (src == dst)
            if src == dst:
                f["land"] = 1

            # IP fragmentation
            try:
                if int(packet.ip.flags) & 0x1:
                    f["wrong_fragment"] += 1
            except Exception:
                pass

            # TCP features
            if hasattr(packet, "tcp"):
                self._process_tcp(packet.tcp, f, src, dst)

            # UDP (just track dst port for service)
            elif hasattr(packet, "udp"):
                try:
                    f["srv_port_counts"][str(packet.udp.dstport)] += 1
                except Exception:
                    pass

            # ICMP — track for protocol_type
            # (no extra fields, just let protocol_type_icmp flag come through)

            # Track dst host diversity (for same_srv_rate / dst_host_count)
            f["dst_host_set"].add(dst)
            f["src_host_set"].add(src)

        except Exception:
            pass

    def _process_tcp(self, tcp, f: dict, src: str, dst: str):
        try:
            flags = int(tcp.flags, 16)
        except Exception:
            flags = 0

        # Flag counters
        is_syn = bool(flags & 0x02)
        is_ack = bool(flags & 0x10)
        is_rst = bool(flags & 0x04)
        is_fin = bool(flags & 0x01)
        is_urg = bool(flags & 0x20)

        if is_syn: f["syn_count"] += 1
        if is_rst: f["rst_count"] += 1
        if is_fin: f["fin_count"] += 1
        if is_ack: f["ack_count"] += 1
        if is_urg: f["urg_count"] += 1

        # SYN without ACK = connection attempt error
        if is_syn and not is_ack:
            f["serror_count"] += 1
        # RST = rejected connection
        if is_rst:
            f["rerror_count"] += 1

        # URG pointer
        try:
            if int(tcp.urgent_pointer) > 0:
                f["urgent"] += 1
        except Exception:
            pass

        # Heuristic: large non-web src bytes = potential "hot" activity
        if f["src_bytes"] > 50_000:
            f["hot"] += 1

        # Logged-in heuristic: SYN + ACK seen = handshake completed
        # (we count successful handshakes; any SYN→ACK→ACK sequence)
        # Simplified: if ack_count > 0 and fin or rst exist → probable session

        # Service tracking
        try:
            dport = str(tcp.dstport)
            f["srv_port_counts"][dport] += 1
            f["_dest_port_hist"].append(dport)
        except Exception:
            pass

        # ── Demonstration U2R & R2L "codes" inspection ────────────────────
        # We look for the strings explicitly requested by the user.
        try:
            # pyshark stores TCP payload as a colon-separated hex string
            payload_hex = getattr(tcp, "payload", "").replace(":", "")
            if payload_hex:
                payload_str = bytes.fromhex(payload_hex).decode("utf-8", errors="ignore").lower()
                
                # U2R keywords
                for kw in ["cmd=whoami", "sudo su -", "cat /etc/shadow"]:
                    if kw in payload_str:
                        f["u2r_hits"] += 1
                        logger.info(f"U2R HIT: Found '{kw}' in payload from {src}")

                # R2L keywords
                for kw in ["login=", "passwd=", "admin/config.php"]:
                    if kw in payload_str:
                        f["r2l_hits"] += 1
                        logger.info(f"R2L HIT: Found '{kw}' in payload from {src}")
        except Exception:
            pass

    # ── Export ────────────────────────────────────────────────────────────

    def export_flows(self) -> list[dict]:
        records = []
        all_dst_counts = defaultdict(int)
        all_svc_counts = defaultdict(int)

        # First pass: aggregate for cross-flow rate features
        for key, v in self.flows.items():
            if len(key) < 3:
                continue
            _, dst, _ = key
            svc = self._infer_service(v)
            all_dst_counts[dst] += 1
            all_svc_counts[svc] += 1

        total_flows = max(sum(all_dst_counts.values()), 1)

        for key, v in self.flows.items():
            if len(key) < 3:
                continue
            src, dst, proto = key
            count = max(v["count"], 1)
            svc   = self._infer_service(v)
            flag  = self._infer_flag(v)

            # Rate-based features
            serror_rate = min(v["serror_count"] / count, 1.0)
            rerror_rate = min(v["rerror_count"] / count, 1.0)

            # same_srv_rate: fraction of connections to the same service over all
            same_srv_rate = round(all_svc_counts[svc] / total_flows, 4)
            diff_srv_rate = round(1.0 - same_srv_rate, 4)

            # dst_host stats
            dst_host_count     = all_dst_counts.get(dst, 1)
            dst_host_srv_count = all_svc_counts.get(svc, 1)

            dst_host_same_srv_rate     = round(dst_host_srv_count / max(dst_host_count, 1), 4)
            dst_host_diff_srv_rate     = round(1.0 - dst_host_same_srv_rate, 4)
            dst_host_serror_rate       = round(serror_rate, 4)
            dst_host_srv_serror_rate   = round(serror_rate * 0.9, 4)  # approx
            dst_host_rerror_rate       = round(rerror_rate, 4)
            dst_host_srv_rerror_rate   = round(rerror_rate * 0.9, 4)
            dst_host_same_src_port_rate= round(v["syn_count"] / count, 4)
            dst_host_srv_diff_host_rate= round(len(v["dst_host_set"]) / max(dst_host_count, 1), 4)

            # Logged-in heuristic: completed handshakes → ACK after SYN
            logged_in = 1 if (v["ack_count"] > 0 and v["fin_count"] > 0) else 0

            # num_failed_logins: approximated by RST storms per flow
            num_failed_logins = min(v["rst_count"] // 3, 5)

            # Derive srv_count: number of distinct services to this host
            srv_count = len(v["srv_port_counts"])

            records.append({
                # Routing / meta (not fed to model — used in alerts)
                "src_ip":                        src,
                "dst_ip":                        dst,
                # Core NSL-KDD features
                "duration":                      round(time.time() - v["start"], 4),
                "protocol_type":                 proto.lower() if proto else "other",
                "service":                       svc,
                "flag":                          flag,
                "src_bytes":                     v["src_bytes"],
                "dst_bytes":                     v["dst_bytes"],
                "land":                          v["land"],
                "wrong_fragment":                v["wrong_fragment"],
                "urgent":                        v["urgent"],
                "hot":                           v["hot"],
                "num_failed_logins":             num_failed_logins,
                "logged_in":                     logged_in,
                "count":                         count,
                "srv_count":                     srv_count,
                "serror_rate":                   round(serror_rate, 4),
                "rerror_rate":                   round(rerror_rate, 4),
                "srv_serror_rate":               round(serror_rate * 0.95, 4),
                "srv_rerror_rate":               round(rerror_rate * 0.95, 4),
                "same_srv_rate":                 same_srv_rate,
                "diff_srv_rate":                 diff_srv_rate,
                "srv_diff_host_rate":            round(len(v["dst_host_set"]) / count, 4),
                "dst_host_count":                dst_host_count,
                "dst_host_srv_count":            dst_host_srv_count,
                "dst_host_same_srv_rate":        dst_host_same_srv_rate,
                "dst_host_diff_srv_rate":        dst_host_diff_srv_rate,
                "dst_host_same_src_port_rate":   dst_host_same_src_port_rate,
                "dst_host_srv_diff_host_rate":   dst_host_srv_diff_host_rate,
                "dst_host_serror_rate":          dst_host_serror_rate,
                "dst_host_srv_serror_rate":      dst_host_srv_serror_rate,
                "dst_host_rerror_rate":          dst_host_rerror_rate,
                "dst_host_srv_rerror_rate":      dst_host_srv_rerror_rate,
                # Extra TCP counters (become one-hot after preprocessing)
                "syn_count":                     v["syn_count"],
                "rst_count":                     v["rst_count"],
                "fin_count":                     v["fin_count"],
                "ack_count":                     v["ack_count"],
                # Demonstration markers
                "u2r_hits":                      v["u2r_hits"],
                "r2l_hits":                      v["r2l_hits"],
            })
        return records

    def save_to_csv(self, path: str = "data/livecap.csv"):
        records = self.export_flows()
        if not records:
            logger.warning("No flows captured – nothing saved.")
            return
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        df = pd.DataFrame(records)
        df.to_csv(path, index=False)
        logger.info(f"Live capture saved → {path} ({len(df)} flows)")

    # ── Heuristics ────────────────────────────────────────────────────────

    def _infer_flag(self, v: dict) -> str:
        """Infer the NSL-KDD connection flag from TCP counter tallies."""
        if v["rst_count"] > 0 and v["syn_count"] == 0:
            return "REJ"
        if v["serror_count"] > 0 and v["rst_count"] == 0:
            return "S0"      # SYN, no response
        if v["serror_count"] > 0 and v["rst_count"] > 0:
            return "RSTOS0"  # SYN, then RST
        if v["fin_count"] > 0 and v["ack_count"] > 0:
            return "SF"      # Normal close
        if v["fin_count"] > 0 and v["rst_count"] > 0:
            return "RSTO"    # RST during close
        if v["syn_count"] > 0 and v["ack_count"] > 0:
            return "S1"      # SYN+ACK seen, not yet closed
        return "OTH"

    def _infer_service(self, v: dict) -> str:
        """Infer service name from most-used destination port."""
        if not v["srv_port_counts"]:
            return "other"
        top_port = max(v["srv_port_counts"], key=v["srv_port_counts"].get)
        return COMMON_PORTS.get(str(top_port), "other")