# 07 — Market Research: agent execution runtimes

> Convention: **[V]** = validated from official docs or repo reads this session. **[H]** = hypothesis/inference. Pricing from public pages, Sep 2026 — re-verify before any purchase.

## Capability comparison (current official documentation)

| Dimension | E2B [V] | Daytona [V] | Modal [V] | Plain Docker [V-conceptual] |
|---|---|---|---|---|
| Isolation | Firecracker microVM, own kernel per sandbox (`e2b.dev/security`) | Containers by default + full VM classes (Linux/Windows) + GPU isolation (`daytona.io/docs/en/isolation`) | gVisor user-space kernel default; VM Sandboxes beta (`modal.com/docs/guide/sandboxes`) | Shared-kernel containers; escape = kernel exploit suffices |
| Workloads | Arbitrary Linux + code-interpreter SDKs (Python/JS first-class), FS/memory snapshots, computer-use | Broadest: any OCI image, `code_run` + exec/PTY, LSP/git/preview/SSH, Windows/macOS, GPUs; SDKs Py/TS/Ruby/Go/Java | Any OCI/`modal.Image`, `sb.exec`, volumes/secrets/tunnels/cron; GPU-first; Py/JS/Go SDKs | Anything on Linux; no agent SDK, snapshots, or preview URLs built in |
| Lifecycle | Default 10 min, max 1h Hobby / 24h Pro; pause (FS+memory) + auto-resume | Auto-stop 15 min default, TTL, auto-archive; pause/resume VM-only | Default max 5 min, up to 24h; idle-timeout kill; memory snapshots alpha | You build TTL/reaping/CRIU yourself |
| Cold start (vendor claims — treat as H) | ~150 ms; resume ~1 s | Containers <90 ms claimed; VM/GPU slower | Sub-second cached images; snapshots 3–10× init cut claimed | Image-pull dominated |
| Deployment | Managed cloud (GCP, US/EU/APAC); BYOC Enterprise (AWS/GCP); OSS self-host `e2b-dev/infra` | Managed cloud; BYOC/custom regions via Helm (control plane stays Daytona's) | Managed serverless only; **no BYOC/self-host** | Anywhere incl. air-gap |
| Pricing | Hobby $0+$100 credit; Pro $150/mo + usage (~$0.0504/vCPU-hr, $0.0162/GiB-hr); no GPU | No platform fee + $200 credit; vCPU $0.0504/hr, mem $0.0162/GiB-hr; H100 ~$3.95/hr | Starter $0+$30/mo compute; sandboxes ≈3× function rate (~$0.14/core-hr); region multipliers | Infra + engineering time only |

## Where Marshall fits [V-repo + H-positioning]

Marshall answers **"should this tool call happen, and what is provable afterwards"** — deny-by-default policy, DNS-pinning HTTP, arg policies, output caps, content-free audit. Runtimes answer **"blast radius when code is hostile."** They compose: Marshall in front, microVM/gVisor behind `code` for untrusted callers. OPA/Cedar decide allow/deny but don't execute tools, pin DNS, or emit hashed audit records; reproducing Marshall by combining libraries (~80%) means owning the bypass seams (`tests/escapes.rs` is the asset).

## Three candidate use cases [H — hypotheses, not validated demand]

1. **Enterprise coding-agent gateway** — buyer: platform eng + security/compliance (SOC 2 review). Job: workspace-scoped read, `git status|log`-only shell, 2-host HTTP allowlist, JSONL audit per decision. Incumbents: Bedrock AgentCore Policy (Cedar, GA Mar 2026), TrueFoundry OPA guardrails, DIY docker+proxy+scripts. Incentive: one reviewable `marshall.yaml` + `--validate-config` + hot-reload instead of policy scattered across proxy/wrappers/logs.
2. **Regulated / air-gapped deployment** (finance/health/gov) — buyer: infra/security lead with data-residency constraints. Job: loopback daemon, `allowed_hosts: []`, `code` off, systemd containment, JSONL to SIEM. Incumbents: E2B BYOC / Daytona custom regions (vendor control plane stays outside), Modal (no BYOC), self-hosted `e2b-dev/infra` ops burden. Incentive: single-binary policy daemon vs a Firecracker fleet when the threat is over-permissioned tool use, not hostile code.
3. **Per-tenant MCP/agent gateway (prototype)** — buyer: AI-platform team fronting shared APIs. Job: per-workspace daemon, batch/sequence determinism, quotas, SSE. Honesty note [V]: Marshall is single-token with in-memory sessions — sell "one daemon per tenant," never SaaS multi-tenancy.

## Differentiation that survives combining libraries [H]

The SSRF table + sandbox-escape attack suite + redaction-by-default + stable error codes + `redaction_policy_version` audit trail is a compliance story that takes sustained adversarial maintenance to replicate — harder to copy in an afternoon than any single policy check.

## Sources

E2B pricing/security/enterprise + docs (persistence, auto-resume, BYOC); Daytona docs (sandboxes, isolation, BYOC) + pricing; Modal docs (sandboxes, networking, cold-start) + pricing; northflank/beam/morph roundups (secondary); AgentCore/Cedar + TrueFoundry + OPA-vs-Cedar + MCP access-control coverage; Marshall `README.md`, `docs/DEPLOYMENT.md`, `Cargo.toml`, `marshall.yaml`, `src/sandbox.rs`, `src/http.rs`, `tests/escapes.rs`. Open questions: Daytona OSS status post-Jun-2026 (conflicting secondary claims); E2B storage/egress rates; Modal per-region multipliers.
