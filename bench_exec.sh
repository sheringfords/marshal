#!/bin/bash
# Execution baseline benchmarks (ENGINEERING_RECOVERY Phase 4).
# Drives a release marshalld over loopback with curl, measuring latency
# distributions with python3. Daemon binary must already be built:
#   cargo build --release --bin marshalld
# Usage: ./bench_exec.sh [port]
set -u
PORT=${1:-3471}
B="http://127.0.0.1:$PORT"
T="Authorization: Bearer bench-token"
BIN="${MARSHALLD_BIN:-./target/release/marshalld}"
WORK="$(mktemp -d /tmp/marshall-bench-XXXXXX)"
trap 'kill $DAEMON_PID 2>/dev/null; rm -rf "$WORK"' EXIT

cat > "$WORK/policy.yaml" <<YAML
workspace: $WORK/ws
concurrency: 32
audit_log: $WORK/audit.jsonl
filesystem:
  writable: true
shell:
  timeout_ms: 10000
  commands:
    - program: /bin/echo
      args: NoFlags
http:
  allowed_hosts: []
code:
  allowed_languages: []
YAML
mkdir -p "$WORK/ws"
MARSHALLD_API_TOKEN=bench-token "$BIN" --config "$WORK/policy.yaml" --port "$PORT" --bind 127.0.0.1 > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 30); do curl -sf "$B/health" >/dev/null && break; sleep 0.2; done

bench() { # name, count, payload-file
  python3 - "$1" "$2" "$3" <<'EOF'
import json, subprocess, sys, time
name, n, payload = sys.argv[1], int(sys.argv[2]), sys.argv[3]
body = open(payload, 'rb').read()
times = []
import os
port = os.environ.get("BENCH_PORT", "3471")
for _ in range(int(os.environ.get("BENCH_WARMUP", "10"))):
    subprocess.run(["curl", "-s", "-o", "/dev/null", "-H", "Authorization: Bearer bench-token",
                    "-H", "Content-Type: application/json", "--data-binary", "@" + payload,
                    f"http://127.0.0.1:{port}{sys.argv[4] if len(sys.argv) > 4 else '/v1/execute'}"],
                   check=True, capture_output=True)
for _ in range(n):
    t = time.perf_counter()
    subprocess.run(["curl", "-s", "-o", "/dev/null", "-H", "Authorization: Bearer bench-token",
                    "-H", "Content-Type: application/json", "--data-binary", "@" + payload,
                    f"http://127.0.0.1:{port}{sys.argv[4] if len(sys.argv) > 4 else '/v1/execute'}"],
                   check=True, capture_output=True)
    times.append((time.perf_counter() - t) * 1000)
times.sort()
import statistics
print(f"{name}: n={n} p50={times[n//2]:.2f}ms p95={times[int(n*0.95)]:.2f}ms p99={times[int(n*0.99)]:.2f}ms "
      f"mean={statistics.mean(times):.2f}ms stdev={statistics.stdev(times):.2f}ms")
EOF
}

echo '{"tool":"shell","args":{"program":"/bin/echo","args":["hi"]}}' > "$WORK/single.json"
echo "hello world" > "$WORK/ws/file.txt"
echo "{\"tool\":\"filesystem\",\"args\":{\"operation\":\"read\",\"path\":\"$WORK/ws/file.txt\"}}" > "$WORK/read.json"
echo "{\"tool\":\"filesystem\",\"args\":{\"operation\":\"write\",\"path\":\"$WORK/ws/out.txt\",\"content\":\"bench\"}}" > "$WORK/write.json"
python3 -c "
import json
reqs=[{'tool':'shell','args':{'program':'/bin/echo','args':['x%d'%i]}} for i in range(8)]
print(json.dumps({'requests':reqs,'max_concurrency':8}))" > "$WORK/batch8.json"

export BENCH_PORT="$PORT"
bench single-echo 100 "$WORK/single.json"
bench fs-read 100 "$WORK/read.json"
bench fs-write 50 "$WORK/write.json"
BENCH_WARMUP=5 bench batch-8 30 "$WORK/batch8.json" /v1/execute/batch
