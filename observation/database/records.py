from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CorrelatedEvent:
    run_id: int
    timestamp: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    transport: Optional[str]
    direction: Optional[str]
    process_pid: Optional[int]
    process_name: Optional[str]

    dns_matched: bool
    dns_method: Optional[str]
    dns_time_delta_ms: Optional[int]
    dns_response_latency_ms: Optional[float]

    tls_matched: bool
    tls_method: Optional[str]
    tls_time_delta_ms: Optional[int]
    ssh_matched: bool
    ssh_method: Optional[str]
    ssh_time_delta_ms: Optional[int]
    tcp_flow_matched: bool
    tcp_flow_method: Optional[str]
    tcp_flow_time_delta_ms: Optional[int]
    http_matched: bool
    http_method: Optional[str]
    http_time_delta_ms: Optional[int]

    process_context_matched: bool
    process_context_method: Optional[str]

    file_activity_count: int
    file_activity_method: Optional[str]
    privilege_activity_count: int
    privilege_activity_method: Optional[str]

    raw_json: str

    # not columns -- carried through so the repository can populate
    # child tables after the parent row's id is known
    process_context_block: Optional[dict] = None
    dns_block: Optional[dict] = None
    tls_block: Optional[dict] = None
    tcp_block: Optional[dict] = None
    http_block: Optional[dict] = None
    file_activity: list = field(default_factory=list)
    privilege_activity: list = field(default_factory=list)

    @classmethod
    def from_record(cls, run_id: int, record: dict) -> "CorrelatedEvent":
        network = record.get("network") or {}
        process = record.get("process") or {}
        correlation = record.get("correlation") or {}
        dns_block = record.get("dns")

        return cls(
            run_id=run_id,
            timestamp=record.get("timestamp"),
            src_ip=network.get("src_ip"),
            dst_ip=network.get("dst_ip"),
            src_port=network.get("src_port"),
            dst_port=network.get("dst_port"),
            transport=network.get("transport"),
            direction=network.get("direction"),
            process_pid=process.get("pid"),
            process_name=process.get("name"),

            dns_matched=bool(correlation.get("dns_matched")),
            dns_method=correlation.get("dns_method"),
            dns_time_delta_ms=correlation.get("dns_time_delta_ms"),
            dns_response_latency_ms=(dns_block or {}).get("response_latency_ms"),

            tls_matched=bool(correlation.get("tls_matched")),
            tls_method=correlation.get("tls_method"),
            tls_time_delta_ms=correlation.get("tls_time_delta_ms"),
            ssh_matched=bool(correlation.get("ssh_matched")),
            ssh_method=correlation.get("ssh_method"),
            ssh_time_delta_ms=correlation.get("ssh_time_delta_ms"),
            tcp_flow_matched=bool(correlation.get("tcp_flow_matched")),
            tcp_flow_method=correlation.get("tcp_flow_method"),
            tcp_flow_time_delta_ms=correlation.get("tcp_flow_time_delta_ms"),
            http_matched=bool(correlation.get("http_matched")),
            http_method=correlation.get("http_method"),
            http_time_delta_ms=correlation.get("http_time_delta_ms"),

            process_context_matched=bool(correlation.get("process_context_matched")),
            process_context_method=correlation.get("process_context_method"),

            file_activity_count=correlation.get("file_activity_count", 0),
            file_activity_method=correlation.get("file_activity_method"),
            privilege_activity_count=correlation.get("privilege_activity_count", 0),
            privilege_activity_method=correlation.get("privilege_activity_method"),

            raw_json=json.dumps(record),

            process_context_block=record.get("process_context"),
            dns_block=dns_block,
            tls_block=record.get("tls"),
            tcp_block=record.get("tcp"),
            http_block=record.get("http"),
            file_activity=record.get("file_activity") or [],
            privilege_activity=record.get("privilege_activity") or [],
        )


@dataclass
class SshSessionRecord:
    run_id: int
    session_key: Optional[str]
    username: Optional[str]
    src_ip: Optional[str]
    src_port: Optional[int]
    pid: Optional[int]
    earliest_event_ts: Optional[str]
    auth_success_ts: Optional[str]
    auth_method: Optional[str]
    session_opened_ts: Optional[str]
    session_closed_ts: Optional[str]
    session_duration_seconds: Optional[float]
    disconnected_ts: Optional[str]
    tcp_connect_matched: bool
    tcp_connect_dst_ip: Optional[str]
    tcp_connect_time_delta_ms: Optional[int]
    tcp_close_matched: bool
    tcp_close_timestamp: Optional[str]
    connection_duration_seconds: Optional[float]
    execve_matched: bool
    execve_binary: Optional[str]
    execve_timestamp: Optional[str]
    raw_json: str

    @classmethod
    def from_record(cls, run_id: int, record: dict) -> "SshSessionRecord":
        return cls(
            run_id=run_id,
            session_key=record.get("session_key"),
            username=record.get("username"),
            src_ip=record.get("src_ip"),
            src_port=record.get("src_port"),
            pid=record.get("pid"),
            earliest_event_ts=record.get("earliest_event_ts"),
            auth_success_ts=record.get("auth_success_ts"),
            auth_method=record.get("auth_method"),
            session_opened_ts=record.get("session_opened_ts"),
            session_closed_ts=record.get("session_closed_ts"),
            session_duration_seconds=record.get("session_duration_seconds"),
            disconnected_ts=record.get("disconnected_ts"),
            tcp_connect_matched=bool(record.get("tcp_connect_matched")),
            tcp_connect_dst_ip=record.get("tcp_connect_dst_ip"),
            tcp_connect_time_delta_ms=record.get("tcp_connect_time_delta_ms"),
            tcp_close_matched=bool(record.get("tcp_close_matched")),
            tcp_close_timestamp=record.get("tcp_close_timestamp"),
            connection_duration_seconds=record.get("connection_duration_seconds"),
            execve_matched=bool(record.get("execve_matched")),
            execve_binary=record.get("execve_binary"),
            execve_timestamp=record.get("execve_timestamp"),
            raw_json=json.dumps(record),
        )