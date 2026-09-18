"""Ship each audit row to a SIEM as it is written, so decisions land in Splunk,
Elastic, Datadog or syslog next to the rest of your security telemetry.

The local hash-chained `audit.jsonl` stays the system of record; this is a copy
on the wire. Forwarding is best-effort and off the hot path: rows go onto a queue
and a daemon thread sends them, so a slow or down collector never blocks or
breaks a tool call. Dependency-free (stdlib urllib / socket).

    audit_forward:
      http: {url: "https://http-inputs.example.splunkcloud.com/services/collector/raw",
             headers: {Authorization: "Splunk ${HEC_TOKEN}"}}
    # or
    audit_forward:
      syslog: {host: siem.internal, port: 514, proto: udp}
    # or any OpenTelemetry collector (OTLP/HTTP JSON logs)
    audit_forward:
      otlp: {endpoint: "http://otel-collector:4318/v1/logs"}
    # add `format: ocsf` to `http:` to send OCSF v1.9 API Activity events instead of raw rows
"""

from __future__ import annotations

import json
import os
import queue
import socket
import sys
import threading
import urllib.request


class Forwarder:
    """A background sender. `sink(row)` does the actual transport; failures are
    swallowed (logged once) so audit forwarding can never take the proxy down."""

    def __init__(self, sink, name: str = "sink", maxsize: int = 2000):
        self.sink = sink
        self.name = name
        self.q: queue.Queue = queue.Queue(maxsize=maxsize)
        self._errored = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def send(self, row: dict) -> None:
        try:
            self.q.put_nowait(row)
        except queue.Full:
            pass  # drop under backpressure rather than block a tool call

    def flush(self, timeout: float | None = None) -> None:
        """Wait for the queue to drain (used by tests and clean shutdown)."""
        self.q.join()

    def _run(self) -> None:
        while True:
            row = self.q.get()
            try:
                if row is not None:
                    self.sink(row)
            except Exception as e:  # a down collector must not matter
                if not self._errored:
                    print(f"aggrete: audit forward ({self.name}) failed, will keep trying quietly: {e}",
                          file=sys.stderr)
                    self._errored = True
            finally:
                self.q.task_done()
            if row is None:
                return


def _http_sink(url: str, headers: dict):
    def sink(row: dict) -> None:
        data = json.dumps(row, default=str).encode()
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json", **headers})
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    return sink


def _syslog_sink(host: str, port: int, proto: str):
    proto = proto.lower()

    def sink(row: dict) -> None:
        # RFC 3164-ish: <priority>tag: message. 134 = local0.informational.
        msg = b"<134>aggrete: " + json.dumps(row, default=str).encode()
        if proto == "tcp":
            with socket.create_connection((host, port), timeout=5) as s:
                s.sendall(msg + b"\n")
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.sendto(msg, (host, port))
            finally:
                s.close()
    return sink


def _otlp_attr(k: str, v):
    if isinstance(v, bool):
        return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int):
        return {"key": k, "value": {"intValue": str(v)}}
    if isinstance(v, float):
        return {"key": k, "value": {"doubleValue": v}}
    return {"key": k, "value": {"stringValue": v if isinstance(v, str) else json.dumps(v, default=str)}}


def otlp_log_record(row: dict) -> dict:
    """One audit row as an OTLP/HTTP JSON LogRecord: the row is the body, and
    every top-level field is also an attribute (`aggrete.<field>`) so collectors
    can filter without parsing the body."""
    decision = str(row.get("decision") or "")
    sev = "WARN" if decision in ("deny", "hold") else "INFO"
    attrs = [_otlp_attr(f"aggrete.{k}", v) for k, v in row.items() if k not in ("ts", "prev")]
    attrs.append(_otlp_attr("event.name", "aggrete.decision"))
    return {
        "timeUnixNano": str(int(float(row.get("ts") or 0) * 1e9)),
        "severityText": sev,
        "severityNumber": 13 if sev == "WARN" else 9,
        "body": {"stringValue": json.dumps(row, default=str)},
        "attributes": attrs,
    }


def _otlp_sink(endpoint: str, headers: dict, service_name: str = "aggrete"):
    """OTLP/HTTP JSON logs (`/v1/logs`) to any OpenTelemetry collector. No SDK."""
    def sink(row: dict) -> None:
        payload = {"resourceLogs": [{
            "resource": {"attributes": [_otlp_attr("service.name", service_name)]},
            "scopeLogs": [{"scope": {"name": "aggrete"}, "logRecords": [otlp_log_record(row)]}],
        }]}
        req = urllib.request.Request(
            endpoint, data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json", **headers})
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    return sink


# ---------- OCSF (Open Cybersecurity Schema Framework) ----------

_OCSF_DECISION = {
    #  decision      action_id, action,     disposition_id, disposition, status_id, status
    "allow":          (1, "Allowed",  1, "Allowed",   1, "Success"),
    "deny":           (2, "Denied",   2, "Blocked",   2, "Failure"),
    "hold":           (3, "Observed", 14, "Delayed",  0, "Unknown"),
    "input_required": (3, "Observed", 1, "Allowed",   0, "Unknown"),
    "approved":       (1, "Allowed",  1, "Allowed",   1, "Success"),
    "denied":         (2, "Denied",   2, "Blocked",   2, "Failure"),
}
_OCSF_SEVERITY = {"deny": 3, "hold": 2, "allow": 1}


def ocsf_event(row: dict, product_version: str = "0") -> dict:
    """One audit row as an OCSF v1.9 API Activity (class 6003) event with the
    security_control profile. Rule id and text go in `policy`, the human reason
    in `status_detail`, the tool in `resources`, the person in `actor.user`."""
    decision = str(row.get("decision") or "allow")
    action_id, action, disp_id, disp, status_id, status = _OCSF_DECISION.get(decision, _OCSF_DECISION["allow"])
    if decision == "allow" and row.get("redacted"):
        action_id, action, disp_id, disp = 4, "Modified", 11, "Corrected"
    activity_id = 3 if row.get("write") else 2
    tool = str(row.get("tool") or "")
    upstream, _, short = tool.partition("__")
    ev = {
        "class_uid": 6003, "class_name": "API Activity", "category_uid": 6, "category_name": "Application Activity",
        "activity_id": activity_id, "activity_name": "Update" if activity_id == 3 else "Read",
        "type_uid": 600300 + activity_id,
        "time": int(float(row.get("ts") or 0) * 1000),
        "severity_id": _OCSF_SEVERITY.get(decision, 1),
        "status_id": status_id, "status": status,
        "status_code": str(row.get("rule") or decision),
        "message": f"{decision} tools/call {tool} for {row.get('user')}",
        "action_id": action_id, "action": action, "disposition_id": disp_id, "disposition": disp,
        "is_alert": decision in ("deny", "hold") or bool(row.get("alerts")),
        "metadata": {"product": {"name": "Aggrete", "vendor_name": "Aggrete", "version": product_version},
                     "version": "1.9.0", "profiles": ["security_control"],
                     "uid": str(row.get("hash") or ""), "log_name": "aggrete.audit"},
        "actor": {"user": {"email_addr": row.get("user"), "type_id": 1}},
        "api": {"operation": "tools/call" if row.get("stage") != "check" else "aggrete/check",
                "service": {"name": upstream or "aggrete"}},
        "resources": [{"type": "mcp_tool", "name": short or tool, "uid": tool, "role_id": 1, "role": "Target",
                       "data": {"domain": row.get("domain"), "stage": row.get("stage")}}],
        "src_endpoint": {"svc_name": "mcp-client"},
        "unmapped": {k: v for k, v in row.items() if k in ("evidence", "alerts", "redacted", "entities", "purpose", "upstream_ms", "prev")},
    }
    if row.get("rule"):
        ev["policy"] = {"uid": str(row["rule"]), "name": str(row["rule"]), "is_applied": True}
        ev["actor"]["authorizations"] = [{"decision": disp.lower(), "policy": {"uid": str(row["rule"])}}]
    if isinstance(row.get("evidence"), dict) and row["evidence"].get("approval"):
        ev["status_detail"] = f"held for approval {row['evidence']['approval']}"
    return ev


def build_forwarder(cfg: dict | None) -> Forwarder | None:
    """Build a forwarder from an `audit_forward:` block, or None when unset.
    URL and header values may reference ${ENV} so tokens stay out of the config."""
    if not cfg:
        return None
    if cfg.get("http"):
        h = cfg["http"]
        url = os.path.expandvars(h["url"])
        headers = {k: os.path.expandvars(str(v)) for k, v in (h.get("headers") or {}).items()}
        sink = _http_sink(url, headers)
        if h.get("format") == "ocsf":
            try:
                from importlib.metadata import version as _pv
                ver = _pv("aggrete")
            except Exception:
                ver = "0"
            raw = sink
            def sink(row: dict, _raw=raw, _ver=ver) -> None:  # noqa: E306
                _raw(ocsf_event(row, _ver))
            return Forwarder(sink, "http-ocsf")
        return Forwarder(sink, "http")
    if cfg.get("otlp"):
        o = cfg["otlp"]
        endpoint = os.path.expandvars(o.get("endpoint") or o.get("url") or "http://localhost:4318/v1/logs")
        headers = {k: os.path.expandvars(str(v)) for k, v in (o.get("headers") or {}).items()}
        return Forwarder(_otlp_sink(endpoint, headers, o.get("service_name", "aggrete")), "otlp")
    if cfg.get("syslog"):
        s = cfg["syslog"]
        return Forwarder(_syslog_sink(os.path.expandvars(str(s["host"])),
                                      int(s.get("port", 514)), s.get("proto", "udp")), "syslog")
    return None
