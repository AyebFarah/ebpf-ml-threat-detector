import json
import sqlite3
from ..pipeline.event_keys import make_tcp_flow_dedup_key


class TcpFlowsRawRepository:
    def __init__(self, conn):
        self.conn = conn

    def insert_many(self, run_id: int, records: list[dict]) -> int:
        count = 0
        for r in records:
            if r.get("event_type") != "tcp_flow":
                continue
            dedup_key = make_tcp_flow_dedup_key(r)
            try:
                self.conn.execute(
                    """INSERT INTO tcp_flows_raw
                       (run_id, dedup_key, src_ip, src_port, dst_ip, dst_port, transport, direction,
                        start_ts, end_ts, duration_ms, handshake_completed, handshake_rtt_ms,
                        termination_reason, packets_out, packets_in, bytes_out, bytes_in,
                        retransmissions, raw_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        run_id, dedup_key,
                        r.get("src_ip"), r.get("src_port"),
                        r.get("dst_ip"), r.get("dst_port"),
                        r.get("transport"), r.get("direction"),
                        r.get("start_ts"), r.get("end_ts"),
                        r.get("duration_ms"),
                        int(r.get("handshake_completed", False)),
                        r.get("handshake_rtt_ms"),
                        r.get("termination_reason"),
                        r.get("packets_out"), r.get("packets_in"),
                        r.get("bytes_out"), r.get("bytes_in"),
                        r.get("retransmissions"),
                        json.dumps(r),
                    ),
                )
                count += 1
            except sqlite3.IntegrityError:
                continue
        return count