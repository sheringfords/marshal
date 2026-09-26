# Deploying marshalld

`marshalld` executes tools on request. Everything below follows from that: the
defaults are closed, and the ways to open them are deliberate.

## The three things that must be true

1. **A token is set.** Without `MARSHALLD_API_TOKEN`, `/v1/*` is open to anyone
   who can reach the port. The daemon refuses to bind a non-loopback address
   without one, so the only unauthenticated deployment is a loopback one.
2. **The policy is the one you wrote.** `--config` is fatal if the file does not
   load, and every allowlist is deny-by-default: an empty list means the tool is
   not registered. Check with `--validate-config` before shipping.
3. **`code` is off, or you meant it.** On the local backend, code execution has
   no OS isolation and bypasses `filesystem` and `http` policy — see
   [Isolation](#isolation). It will not start without `allow_unsandboxed: true`.

## Container

```sh
docker build -t marshalld .
docker run --rm -p 3000:3000 \
  -e MARSHALLD_API_TOKEN="$(openssl rand -hex 32)" \
  -v "$PWD/marshall.yaml:/etc/marshalld/marshall.yaml:ro" \
  marshalld --config /etc/marshalld/marshall.yaml
```

The image sets `MARSHALLD_BIND=0.0.0.0` because a container that binds loopback
is unreachable. That makes the token mandatory: without it the process exits
rather than serving. It runs as uid 10001 and the `HEALTHCHECK` probes
`/health` through `marshalld --healthcheck`, so a wedged server is detected
rather than a dead binary.

Give it a read-only root filesystem and a writable workspace:

```sh
docker run --rm -p 3000:3000 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid \
  --cap-drop ALL --security-opt no-new-privileges \
  -e MARSHALLD_API_TOKEN="$TOKEN" \
  marshalld --config /etc/marshalld/marshall.yaml
```

`noexec` on the workspace tmpfs is worth the trouble: it stops a written file
from being executed even if some path lets one be written.

## systemd

```ini
[Unit]
Description=marshalld
After=network.target

[Service]
Type=exec
ExecStart=/usr/local/bin/marshalld --config /etc/marshalld/marshall.yaml
Environment=MARSHALLD_BIND=127.0.0.1
EnvironmentFile=/etc/marshalld/token.env
User=marshalld
Group=marshalld

# The tools enforce policy in-process, so the unit sandbox is the OS-level
# containment the crate does not provide itself.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
StateDirectory=marshalld
ReadWritePaths=/var/lib/marshalld
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`token.env` holds `MARSHALLD_API_TOKEN=...` and should be mode 0600, owned by
root.

## Reverse proxy

Terminate TLS in front and keep `marshalld` on loopback. It speaks plain HTTP
and has no certificate handling of its own.

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_read_timeout 120s;   # tool calls are slower than web requests
    proxy_buffering off;        # /v1/execute/stream is SSE
}
```

`proxy_buffering off` matters: with it on, the streaming endpoint delivers
nothing until the response completes, which defeats the point of streaming.

## Configuration reference

| Variable | Default | Notes |
|---|---|---|
| `MARSHALLD_API_TOKEN` | unset | Bearer token for `/v1/*`. Required for non-loopback binds. |
| `MARSHALLD_BIND` | `127.0.0.1` | Listen address. `--bind` overrides. |
| `PORT` / `MARSHALLD_PORT` | `3000` | Listen port. `--port` overrides. |
| `MARSHALLD_CORS_ORIGIN` | unset | Exact allowed origin. Unset sends no CORS headers. An unparseable value is fatal. |
| `MARSHALLD_SESSION_TTL_SECS` | `3600` | Session lifetime; workspaces are removed on expiry. |
| `MARSHALLD_ALLOWED_HOSTS` | unset | Comma-separated egress allowlist, when not using a policy file. |
| `MARSHALLD_JSON_LOGS` | unset | Structured logs. |
| `RUST_LOG` | `info` | Log filter. |

## Observability

`GET /metrics` is Prometheus exposition and needs no token — neither does
`/health`, so a probe without credentials can still report liveness. Both are
outside the rate limiter for the same reason.

Useful alerts:

- `rate(marshalld_failure_total[5m])` climbing without a matching request rate
  usually means a policy change broke a caller.
- Any `marshalld_requests_total` increase on an instance you thought was idle.
- 429s concentrated on one client: either a runaway loop or a quota set too low.

The JSONL audit log (`audit_log:`) holds one record per execution with a
`content_sha256` and no payload. It rotates at 10 MiB to `.jsonl.1`, which is
one generation — ship it somewhere durable if you need history.

## Isolation

The crate enforces policy in-process. There is no seccomp filter, namespace, or
chroot of its own, and a tool that gets past its policy has the daemon's
privileges. The deployment provides the containment:

| Approach | What it gets you |
|---|---|
| Policy only (default) | Path, host, and command allowlists. Fine for trusted callers. |
| Container/VM around the daemon | The unit above, or a locked-down container. What most deployments should do. |
| `--features wasm` | wasmtime fuel and memory caps, WASI preopen. For `code`. |
| `ContainerBackend` | Fail-closed placeholder: refuses every request with `isolation_unavailable`. Not containment. |

If callers are untrusted, do not enable `code` on the local backend. The gate
in `marshall.yaml` exists because the tool otherwise reads any file the daemon
can read and reaches any host the daemon can reach, regardless of what
`filesystem` and `http` say.
