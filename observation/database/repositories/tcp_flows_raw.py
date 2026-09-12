import json
from sqlalchemy.dialects.sqlite import insert

from sqlalchemy.orm import Session
from observation.database.models import TcpFlowRaw
from ...pipeline.event_keys import make_tcp_flow_dedup_key


class TcpFlowsRawRepository:
    def __init__(self, conn):
        self.conn = conn

    def insert_many(self, run_id: int, records: list[dict]) -> int:
        count = 0
        for r in records:
            if r.get("event_type") != "tcp_flow":
                continue
            dedup_key = make_tcp_flow_dedup_key(r)
            result = self.conn.execute(insert(TcpFlowRaw).values(
                run_id=run_id, dedup_key=dedup_key, src_ip=r.get("src_ip"),
                src_port=r.get("src_port"), dst_ip=r.get("dst_ip"), dst_port=r.get("dst_port"),
                transport=r.get("transport"), direction=r.get("direction"),
                start_ts=r.get("start_ts"), end_ts=r.get("end_ts"),
                duration_ms=r.get("duration_ms"),
                handshake_completed=int(r.get("handshake_completed", False)),
                handshake_rtt_ms=r.get("handshake_rtt_ms"),
                termination_reason=r.get("termination_reason"),
                packets_out=r.get("packets_out"), packets_in=r.get("packets_in"),
                bytes_out=r.get("bytes_out"), bytes_in=r.get("bytes_in"),
                retransmissions=r.get("retransmissions"), raw_json=json.dumps(r),
            ).on_conflict_do_nothing(index_elements=["run_id", "dedup_key"]))
            if result.rowcount:
                count += 1
        return count
