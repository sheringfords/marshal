# marshall Python SDK — thin client over marshalld (Phase 3)
# pip: marshall-sdk (scaffold)
#   from marshall_sdk import ExecutionClient
#   c = ExecutionClient("http://localhost:3000", token="...")
#   print(c.execute("shell", {"program": "/bin/echo", "args": ["hi"]}))
#   for event, data in c.stream("shell", {"program": "/bin/echo", "args": ["hi"]}):
#       print(event, data)
#
# The token is sent as `Authorization: Bearer <token>` on every request and
# is never copied into errors, logs, or execution summaries.
import json
import requests

class ExecutionClient:
    def __init__(self, base_url, timeout=30, token=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        if token:
            self.session.headers.update({"authorization": f"Bearer {token}"})

    def health(self):
        r = self.session.get(f"{self.base_url}/health", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def tools(self):
        r = self.session.get(f"{self.base_url}/v1/tools", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def create_session(self, label=None):
        r = self.session.post(f"{self.base_url}/v1/sessions", json={"label": label}, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def delete_session(self, session_id):
        r = self.session.delete(f"{self.base_url}/v1/sessions/{session_id}", timeout=self.timeout)
        # 204 carries no body: success is the status itself.
        if r.status_code == 204:
            return True
        try:
            err = r.json()
        except Exception:
            err = {"error": r.text}
        raise RuntimeError(f"{err.get('code')}: {err.get('error')}")

    def get_policy(self):
        # The policy endpoint returns the active `marshall.yaml` as YAML
        # text, not JSON — callers get the raw string.
        r = self.session.get(f"{self.base_url}/v1/policy", timeout=self.timeout)
        r.raise_for_status()
        return r.text

    def execute(self, tool, args, session_id=None, idempotency_key=None):
        body = {"tool": tool, "args": args}
        if session_id: body["session_id"] = session_id
        if idempotency_key: body["idempotency_key"] = idempotency_key
        r = self.session.post(f"{self.base_url}/v1/execute", json=body, timeout=self.timeout)
        if r.status_code >= 400:
            try:
                err = r.json()
            except: err = {"error": r.text}
            raise RuntimeError(f"{err.get('code')}: {err.get('error')}")
        return r.json()  # {outcome: ToolOutcome}

    def _to_request(self, entry):
        # Accepts (tool, args), (tool, args, extra), or dict {tool, args, ...}.
        if isinstance(entry, dict):
            body = {"tool": entry["tool"], "args": entry["args"]}
            sid = entry.get("session_id", entry.get("sessionId"))
            key = entry.get("idempotency_key", entry.get("idempotencyKey"))
            if sid: body["session_id"] = sid
            if key: body["idempotency_key"] = key
            return body
        if len(entry) == 3:
            t, a, extra = entry
            body = {"tool": t, "args": a}
            sid = (extra or {}).get("session_id", (extra or {}).get("sessionId"))
            key = (extra or {}).get("idempotency_key", (extra or {}).get("idempotencyKey"))
            if sid: body["session_id"] = sid
            if key: body["idempotency_key"] = key
            return body
        t, a = entry
        return {"tool": t, "args": a}

    def batch(self, requests, max_concurrency=8, session_id=None):
        body = {"requests": [self._to_request(e) for e in requests], "max_concurrency": max_concurrency}
        if session_id: body["session_id"] = session_id
        r = self.session.post(f"{self.base_url}/v1/execute/batch", json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def sequence(self, steps, continue_on_error=False, session_id=None):
        body = {"steps": [self._to_request(e) for e in steps], "continue_on_error": continue_on_error}
        if session_id: body["session_id"] = session_id
        r = self.session.post(f"{self.base_url}/v1/execute/sequence", json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def stream(self, tool, args, session_id=None, idempotency_key=None):
        """Yield (event, data) SSE tuples. Requires `requests` stream."""
        body = {"tool": tool, "args": args}
        if session_id: body["session_id"] = session_id
        if idempotency_key: body["idempotency_key"] = idempotency_key
        with self.session.post(f"{self.base_url}/v1/execute/stream", json=body, stream=True, timeout=self.timeout, headers={"accept": "text/event-stream"}) as r:
            r.raise_for_status()
            buf = ""
            for chunk in r.iter_content(decode_unicode=True):
                if not chunk: continue
                buf += chunk
                while "\n\n" in buf:
                    raw, buf = buf.split("\n\n", 1)
                    event = "message"
                    data_raw = ""
                    for line in raw.splitlines():
                        if line.startswith("event: "): event = line[7:]
                        elif line.startswith("data: "): data_raw = line[6:]
                    try: data = json.loads(data_raw)
                    except: data = data_raw
                    yield event, data
