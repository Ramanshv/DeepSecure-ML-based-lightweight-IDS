
"""
src/rule_detector.py – Stateful rule-based detection for volumetric/rate attacks.

Complements the ML model for attacks that are invisible at flow level:
  - Port Scan: one source probing many ports rapidly
  - SYN Flood: many SYN packets to the same target with no completions
  - Connection Flood: burst of connections to the same host:port

The ML model sees flow-level statistics (good for DoS that completes flows,
R2L, U2R). This module sees packet-level patterns (good for scans / floods
that are short-lived and never form proper TCP flows).

All state is time-windowed so counters decay automatically.
"""

import time
from collections import defaultdict
from threading import Lock
from typing import Optional

from src.logger import get_logger

logger = get_logger(__name__)

# ── Default thresholds (overridable via config) ───────────────────────────

# Port scan: unique dst ports from one source within the window
SCAN_WINDOW_S        = 30    # wider window: rapid scans still accumulate
SCAN_PORT_THRESHOLD  = 15    # unique ports → POTENTIAL
SCAN_HIGH_THRESHOLD  = 50    # unique ports → HIGH
SCAN_CRIT_THRESHOLD  = 200   # unique ports → CRITICAL (nmap default scan sees ~344 w/ pyshark loss)

# SYN flood: SYN-only packets to same dst:port within window
SYN_FLOOD_WINDOW_S   = 5
SYN_FLOOD_THRESHOLD  = 20    # SYN packets in window → HIGH

# Connection flood: new connections to same dst:port within window
CONN_FLOOD_WINDOW_S  = 10
CONN_FLOOD_THRESHOLD = 50    # new connections in window → HIGH

# ICMP flood: high-rate pings (ping -f)
ICMP_FLOOD_WINDOW_S  = 3
ICMP_FLOOD_THRESHOLD = 50    # ICMP echo requests in 3s → HIGH

# Cooldown: don't re-alert same source for same rule within N seconds
ALERT_COOLDOWN_S     = 15


class RuleDetector:
    """
    Packet-level stateful rule engine.

    Call process_packet(packet) for every captured packet.
    Returns a list of alert dicts (possibly empty) for any rules triggered.
    """

    def __init__(
        self,
        scan_window:        int = SCAN_WINDOW_S,
        scan_threshold:     int = SCAN_PORT_THRESHOLD,
        scan_high_threshold:int = SCAN_HIGH_THRESHOLD,
        scan_crit_threshold:int = SCAN_CRIT_THRESHOLD,
        syn_window:         int = SYN_FLOOD_WINDOW_S,
        syn_threshold:      int = SYN_FLOOD_THRESHOLD,
        conn_window:        int = CONN_FLOOD_WINDOW_S,
        conn_threshold:     int = CONN_FLOOD_THRESHOLD,
        icmp_window:        int = ICMP_FLOOD_WINDOW_S,
        icmp_threshold:     int = ICMP_FLOOD_THRESHOLD,
        cooldown:           int = ALERT_COOLDOWN_S,
        own_ports:          set = None,   # ports this process serves — exempt from flood rules
    ):
        self._scan_window   = scan_window
        self._scan_thresh   = scan_threshold
        self._scan_high_t   = scan_high_threshold
        self._scan_crit_t   = scan_crit_threshold
        self._syn_window    = syn_window
        self._syn_thresh    = syn_threshold
        self._conn_window   = conn_window
        self._conn_thresh   = conn_threshold
        self._icmp_window   = icmp_window
        self._icmp_thresh   = icmp_threshold
        self._cooldown      = cooldown

        # Ports this IDS process is serving on — exempt from flood rules
        # (browser polling the dashboard generates legitimate SYNs to these)
        self._own_ports: set = own_ports if own_ports is not None else {5000}

        # Track last time a non-loopback (external) port scan was detected.
        # Used to suppress loopback mirror alerts for the same attack.
        self._last_ext_scan_time: float = 0.0
        self._ext_scan_suppress_s: float = 30.0

        self._port_hits: dict[str, list] = defaultdict(list)
        self._syn_hits:  dict[tuple, list] = defaultdict(list)
        self._conn_hits: dict[tuple, list] = defaultdict(list)
        self._icmp_hits: dict[str, list]   = defaultdict(list)
        self._last_alert: dict[tuple, float] = {}
        self._lock = Lock()

    # ── Public API ────────────────────────────────────────────────────────

    def process_packet(self, packet) -> list[dict]:
        """
        Analyse a single raw pyshark packet.
        Returns a list of alert dicts (empty if nothing triggered).
        """
        alerts = []
        try:
            if not hasattr(packet, "ip"):
                return alerts

            src     = str(packet.ip.src)
            dst     = str(packet.ip.dst)
            now     = time.time()

            # ── ICMP Flood (ping -f) ───────────────────────────────────
            if hasattr(packet, "icmp"):
                with self._lock:
                    alert = self._check_icmp_flood(src, dst, now)
                    if alert:
                        alerts.append(alert)
                return alerts   # ICMP — no TCP rules needed

            if not hasattr(packet, "tcp"):
                return alerts

            tcp = packet.tcp
            try:
                flags     = int(tcp.flags, 16)
                is_syn    = bool(flags & 0x02)
                is_ack    = bool(flags & 0x10)
                is_rst    = bool(flags & 0x04)
                is_syn_only = is_syn and not is_ack  # pure SYN (no ACK)
            except Exception:
                return alerts

            try:
                dst_port = int(tcp.dstport)
            except Exception:
                dst_port = 0

            with self._lock:
                # ── Rule 1: Port Scan ─────────────────────────────────────
                scan_alert = self._check_port_scan(src, dst, dst_port, now)
                if scan_alert:
                    alerts.append(scan_alert)

                # ── Rule 2: SYN Flood ─────────────────────────────────────
                # For own ports (e.g. the Flask dashboard port 5000): normal
                # browser polling sends 1-5 SYNs per session.  We allow up
                # to 200 before alerting so the dashboard doesn't self-alarm.
                # A curl flood of 2000 easily breaks 200 → CRITICAL.
                if is_syn_only:
                    if dst_port in self._own_ports:
                        syn_alert = self._check_syn_flood(
                            src, dst, dst_port, now, high_override=200, crit_override=500
                        )
                    else:
                        syn_alert = self._check_syn_flood(src, dst, dst_port, now)
                    if syn_alert:
                        alerts.append(syn_alert)

                # ── Rule 3: Connection Flood ───────────────────────────────
                if is_syn_only:
                    if dst_port in self._own_ports:
                        conn_alert = self._check_conn_flood(
                            src, dst, dst_port, now, high_override=500, crit_override=1000
                        )
                    else:
                        conn_alert = self._check_conn_flood(src, dst, dst_port, now)
                    if conn_alert:
                        alerts.append(conn_alert)

        except Exception:
            pass

        return alerts

    # ── Rule implementations ──────────────────────────────────────────────

    def _check_port_scan(
        self, src: str, dst: str, dst_port: int, now: float
    ) -> Optional[dict]:
        # ── Ignore ephemeral destination ports ────────────────────────────
        # Real port scans target service ports (1-49151).
        # Response packets (Flask→curl, CDN→browser) arrive at the client's
        # randomly-assigned ephemeral port (49152-65535).  On loopback both
        # directions are captured, so the IDS would see src=127.0.0.1 scanning
        # hundreds of unique "ports" that are actually just client sockets.
        if dst_port >= 49152:
            return None

        hits = self._port_hits[src]
        hits.append((now, dst_port, dst))
        cutoff = now - self._scan_window
        self._port_hits[src] = [(t, p, d) for t, p, d in hits if t > cutoff]

        unique_ports = len({p for _, p, _ in self._port_hits[src]})
        is_loopback  = src.startswith("127.")

        # ── Loopback-specific thresholds ─────────────────────────────────
        # macOS transparent proxy / YouTube CDN browsing generates ~130-141
        # unique loopback port associations per 30s window.  Raising the bar
        # for loopback-source scans prevents false positives while still
        # catching nmap (which achieves 300+ ports even with pyshark loss).
        if is_loopback:
            crit_t = max(self._scan_crit_t, 250)   # YouTube tops ~141, nmap gets 300+
            high_t = max(self._scan_high_t, 200)   # well above YouTube ceiling
            pot_t  = 200                            # no loopback alert below 200 ports
        else:
            crit_t = self._scan_crit_t
            high_t = self._scan_high_t
            pot_t  = self._scan_thresh

        if unique_ports >= crit_t:
            severity = "CRITICAL"
        elif unique_ports >= high_t:
            severity = "HIGH"
        elif unique_ports >= pot_t:
            severity = "POTENTIAL"
        else:
            return None

        # ── Suppress loopback mirror of a concurrent external scan ────────
        # When nmap runs on this host, packets appear on BOTH the physical
        # interface (src=real-IP, correct) AND loopback (src=127.0.0.1,
        # duplicate).  If an external scan fired recently, drop the loopback.
        if is_loopback and (now - self._last_ext_scan_time) < self._ext_scan_suppress_s:
            return None

        # Record external scan time so future loopback alerts can be suppressed
        if not is_loopback:
            self._last_ext_scan_time = now

        if self._in_cooldown(src, "PORT_SCAN", now):
            return None

        detail = f"{unique_ports} unique ports in {self._scan_window}s"
        logger.warning(f"[RULE] PORT_SCAN ({severity}) from {src} – {detail}")
        return self._make_alert("PORT_SCAN", severity, src, now, detail)

    def _check_icmp_flood(
        self, src: str, dst: str, now: float
    ) -> Optional[dict]:
        hits = self._icmp_hits[src]
        hits.append(now)
        cutoff = now - self._icmp_window
        self._icmp_hits[src] = [t for t in hits if t > cutoff]

        count = len(self._icmp_hits[src])
        # ping -f floods at thousands/s — escalate to CRITICAL above 500
        if count >= 500:
            severity = "CRITICAL"
        elif count >= self._icmp_thresh:
            severity = "HIGH"
        else:
            return None

        if self._in_cooldown(src, "ICMP_FLOOD", now):
            return None
        detail = f"{count} ICMP packets from {src} to {dst} in {self._icmp_window}s"
        logger.warning(f"[RULE] ICMP_FLOOD ({severity}) from {src} – {detail}")
        # Don't clear hits — let the window expire them naturally so count
        # can keep escalating from HIGH → CRITICAL under sustained attack.
        return self._make_alert("ICMP_FLOOD", severity, src, now, detail)

    def _check_syn_flood(
        self, src: str, dst: str, dst_port: int, now: float,
        high_override: int = None, crit_override: int = None,
    ) -> Optional[dict]:
        key  = (src, dst, dst_port)
        hits = self._syn_hits[key]
        hits.append(now)
        cutoff = now - self._syn_window
        self._syn_hits[key] = [t for t in hits if t > cutoff]

        count    = len(self._syn_hits[key])
        high_t   = high_override if high_override is not None else self._syn_thresh
        crit_t   = crit_override if crit_override is not None else self._syn_thresh * 5

        if count >= crit_t:
            severity = "CRITICAL"
        elif count >= high_t:
            severity = "HIGH"
        else:
            return None

        if self._in_cooldown(src, "SYN_FLOOD", now):
            return None
        detail = f"{count} SYN packets to {dst}:{dst_port} in {self._syn_window}s"
        logger.warning(f"[RULE] SYN_FLOOD ({severity}) from {src} – {detail}")
        return self._make_alert("SYN_FLOOD", severity, src, now, detail)

    def _check_conn_flood(
        self, src: str, dst: str, dst_port: int, now: float,
        high_override: int = None, crit_override: int = None,
    ) -> Optional[dict]:
        key  = (src, dst, dst_port)
        hits = self._conn_hits[key]
        hits.append(now)
        cutoff = now - self._conn_window
        self._conn_hits[key] = [t for t in hits if t > cutoff]

        count  = len(self._conn_hits[key])
        high_t = high_override if high_override is not None else self._conn_thresh
        crit_t = crit_override if crit_override is not None else self._conn_thresh * 5

        if count >= crit_t:
            severity = "CRITICAL"
        elif count >= high_t:
            severity = "HIGH"
        else:
            return None

        if self._in_cooldown(src, "CONN_FLOOD", now):
            return None
        detail = f"{count} new connections to {dst}:{dst_port} in {self._conn_window}s"
        logger.warning(f"[RULE] CONN_FLOOD ({severity}) from {src} – {detail}")
        return self._make_alert("CONN_FLOOD", severity, src, now, detail)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _in_cooldown(self, src: str, rule: str, now: float) -> bool:
        key  = (src, rule)
        last = self._last_alert.get(key, 0)
        if now - last < self._cooldown:
            return True
        self._last_alert[key] = now
        return False

    @staticmethod
    def _make_alert(rule: str, severity: str, src_ip: str, ts: float, detail: str) -> dict:
        return {
            "rule":       rule,
            "severity":   severity,
            "src_ip":     src_ip,
            "timestamp":  time.strftime("%H:%M:%S", time.localtime(ts)),
            "confidence": "RULE",    # not ML confidence — rule-triggered
            "detail":     detail,
        }
