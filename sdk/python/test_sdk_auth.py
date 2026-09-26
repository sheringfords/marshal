"""Auth regression tests for the Python SDK (MAR-P1-004).

Run: `python3 sdk/python/test_sdk_auth.py` — stdlib only, stubbed transport.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from marshall_sdk import ExecutionClient  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = str(self._payload)

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_content(self, decode_unicode=False):
        yield 'event: done\ndata: {"success": true}\n\n'


class FakeSession:
    """Stands in for requests.Session: merges default headers like it does."""

    def __init__(self, routes):
        self.headers = {}
        self.routes = routes
        self.calls = []

    def _call(self, method, url, **kwargs):
        merged = dict(self.headers)
        merged.update(kwargs.get("headers") or {})
        self.calls.append({"method": method, "url": url, "headers": merged,
                           "json": kwargs.get("json")})
        handler = self.routes.get(url.split("http://x")[1], self.routes["default"])
        return handler(method, url, kwargs)

    def get(self, url, **kwargs):
        return self._call("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._call("POST", url, **kwargs)

    def delete(self, url, **kwargs):
        return self._call("DELETE", url, **kwargs)


def make_client(token, routes):
    client = ExecutionClient("http://x", token=token)
    fake = FakeSession(routes)
    if token:
        fake.headers.update(client.session.headers)
    client.session = fake
    return client, fake


def test_bearer_on_every_endpoint():
    routes = {"default": lambda m, u, k: FakeResponse(200, {"ok": True})}
    client, fake = make_client("s3cret", routes)
    client.health()
    client.tools()
    client.get_policy()
    client.create_session("x")
    client.execute("system", {"operation": "now"})
    client.batch([("system", {"operation": "now"})])
    client.sequence([("system", {"operation": "now"})])
    list(client.stream("system", {"operation": "now"}))
    assert len(fake.calls) >= 8, fake.calls
    for call in fake.calls:
        assert call["headers"].get("authorization") == "Bearer s3cret", call


def test_delete_session_and_get_policy():
    def delete_ok(method, url, kwargs):
        assert method == "DELETE", method
        assert url.endswith("/v1/sessions/abc"), url
        return FakeResponse(204, {})

    def policy_ok(method, url, kwargs):
        assert url.endswith("/v1/policy"), url
        return FakeResponse(200, {})

    routes = {"/v1/sessions/abc": delete_ok, "/v1/policy": policy_ok,
              "default": lambda m, u, k: FakeResponse(200, {})}
    client, _ = make_client("t", routes)
    assert client.delete_session("abc") is True
    assert isinstance(client.get_policy(), str)

    routes["/v1/sessions/missing"] = lambda m, u, k: FakeResponse(
        404, {"error": "session not found: missing", "code": "session_not_found"})
    try:
        client.delete_session("missing")
    except RuntimeError as err:
        assert "session_not_found" in str(err), err
    else:
        raise AssertionError("missing session did not raise")


def test_token_never_leaks_into_errors():
    routes = {"default": lambda m, u, k: FakeResponse(
        401, {"error": "unauthorized", "code": "unauthorized"})}
    client, _ = make_client("s3cret", routes)
    try:
        client.execute("system", {"operation": "now"})
    except RuntimeError as err:
        assert "s3cret" not in str(err), err
        assert "unauthorized" in str(err), err
    else:
        raise AssertionError("401 did not raise")


def test_tokenless_client_sends_no_credentials():
    routes = {"default": lambda m, u, k: FakeResponse(200, {})}
    client = ExecutionClient("http://x")
    fake = FakeSession(routes)
    client.session = fake
    client.execute("system", {"operation": "now"})
    assert "authorization" not in fake.calls[0]["headers"], fake.calls[0]


if __name__ == "__main__":
    test_bearer_on_every_endpoint()
    test_delete_session_and_get_policy()
    test_token_never_leaks_into_errors()
    test_tokenless_client_sends_no_credentials()
    print("sdk python auth tests: 4 passed")
