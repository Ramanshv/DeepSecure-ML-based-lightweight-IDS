"""
src/live_capture.py – Wraps pyshark LiveCapture with clean stop-flag support.

Key latency fix: pass '-l' (line-buffered) to tshark so packets are flushed
to Python immediately instead of sitting in tshark's internal write buffer.
Without this, pyshark may hold back 64-KB worth of packets before delivering
them, which is what causes the 3-5 second rule-alert delay on quiet interfaces.
"""

import pyshark
from src.logger import get_logger

logger = get_logger(__name__)


class LiveCapture:
    def __init__(self):
        self.packet_count = 0

    def start(self, callback, stop_flag: dict, iface: str = "en0"):
        logger.info(f"Starting live capture on interface: {iface}")

        try:
            capture = pyshark.LiveCapture(
                interface=iface,
                # '-l' = flush tshark output after every packet (line-buffered).
                # This is the critical flag that cuts latency from 3-5s to <1s.
                custom_parameters=["-l"],
                use_json=True,        # JSON decode is faster than XML for pyshark
                include_raw=False,    # skip raw hex — we don't need it
            )

            for packet in capture.sniff_continuously():
                if stop_flag.get("stop"):
                    logger.info("Stop flag received – halting capture.")
                    break

                self.packet_count += 1
                callback(packet)

                if self.packet_count % 50 == 0:
                    logger.debug(f"Packets captured so far: {self.packet_count}")

        except Exception as exc:
            logger.error(f"Capture error: {exc}", exc_info=True)

        finally:
            logger.info(f"Capture stopped. Total packets processed: {self.packet_count}")