// marshall JS SDK — thin client over marshalld (Phase 3)
// npm: marshall-sdk (scaffold)
// Usage:
//   import { ExecutionClient } from './index.js'
//   const c = new ExecutionClient('http://localhost:3000', { token: process.env.MARSHALLD_API_TOKEN })
//   await c.execute('shell', {program:'/bin/echo', args:['hi']})
//   for await (const chunk of c.stream('shell', {program:'/bin/echo', args:['hi']})) console.log(chunk)
//
// The token is sent as `Authorization: Bearer <token>` on every request and
// is never copied into errors, logs, or execution summaries.

export class ExecutionClient {
  constructor(baseUrl, opts = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetch = opts.fetch || globalThis.fetch;
    this.token = opts.token || null;
  }

  // Authorization header for every API request. Absent when no token was
  // configured, so the client also works against open local deployments.
  authHeaders() {
    return this.token ? { authorization: `Bearer ${this.token}` } : {};
  }

  async health() {
    const r = await this.fetch(`${this.baseUrl}/health`, { headers: { ...this.authHeaders() } });
    if (!r.ok) throw new Error(`health ${r.status}`);
    return r.json();
  }

  async tools() {
    const r = await this.fetch(`${this.baseUrl}/v1/tools`, { headers: { ...this.authHeaders() } });
    if (!r.ok) throw new Error(`tools ${r.status}`);
    return r.json();
  }

  // The policy endpoint returns the active `marshall.yaml` as YAML text,
  // not JSON — callers get the raw string.
  async policy() {
    const r = await this.fetch(`${this.baseUrl}/v1/policy`, { headers: { ...this.authHeaders() } });
    if (!r.ok) throw new Error(`policy ${r.status}`);
    return r.text();
  }

  async createSession(label) {
    const r = await this.fetch(`${this.baseUrl}/v1/sessions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...this.authHeaders() },
      body: JSON.stringify({ label }),
    });
    if (!r.ok) throw new Error(`createSession ${r.status}: ${await r.text()}`);
    return r.json();
  }

  async deleteSession(sessionId) {
    const r = await this.fetch(`${this.baseUrl}/v1/sessions/${encodeURIComponent(sessionId)}`, {
      method: 'DELETE',
      headers: { ...this.authHeaders() },
    });
    // 204 carries no body: success is the status itself.
    if (r.status === 204) return true;
    if (!r.ok) throw new Error(`deleteSession ${r.status}: ${await r.text()}`);
    return true;
  }

  async execute(tool, args, opts = {}) {
    const body = { tool, args, session_id: opts.sessionId, idempotency_key: opts.idempotencyKey };
    const r = await this.fetch(`${this.baseUrl}/v1/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...this.authHeaders() },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({ error: r.statusText }));
      throw Object.assign(new Error(err.error || err.code), { code: err.code, status: r.status });
    }
    return r.json(); // { outcome: ToolOutcome }
  }

  // SSE streaming — yields {event, data} per chunk
  // Accepts tuples [tool, args] or objects {tool, args, session_id, idempotency_key}.
  // Top-level opts.sessionId scopes memory/todo/plan via inject_session_id server-side.
  static #toRequest(entry) {
    if (Array.isArray(entry)) {
      const [tool, args, extra = {}] = entry;
      return { tool, args, session_id: extra.sessionId, idempotency_key: extra.idempotencyKey };
    }
    return {
      tool: entry.tool,
      args: entry.args,
      session_id: entry.session_id ?? entry.sessionId,
      idempotency_key: entry.idempotency_key ?? entry.idempotencyKey,
    };
  }

  async batch(requests, opts = {}) {
    const body = { requests: requests.map((e) => ExecutionClient.#toRequest(e)), max_concurrency: opts.maxConcurrency, session_id: opts.sessionId };
    const r = await this.fetch(`${this.baseUrl}/v1/execute/batch`, { method: 'POST', headers: { 'content-type': 'application/json', ...this.authHeaders() }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(`batch ${r.status}: ${await r.text()}`);
    return r.json();
  }

  async sequence(steps, opts = {}) {
    const body = { steps: steps.map((e) => ExecutionClient.#toRequest(e)), continue_on_error: opts.continueOnError, session_id: opts.sessionId };
    const r = await this.fetch(`${this.baseUrl}/v1/execute/sequence`, { method: 'POST', headers: { 'content-type': 'application/json', ...this.authHeaders() }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(`sequence ${r.status}: ${await r.text()}`);
    return r.json();
  }

  async *stream(tool, args, opts = {}) {
    const body = { tool, args, session_id: opts.sessionId, idempotency_key: opts.idempotencyKey };
    const r = await this.fetch(`${this.baseUrl}/v1/execute/stream`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'text/event-stream', ...this.authHeaders() },
      body: JSON.stringify(body),
    });
    if (!r.ok || !r.body) throw new Error(`stream ${r.status}`);
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n\n')) !== -1) {
        const raw = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const event = (raw.match(/^event: (.*)/m) || [])[1] || 'message';
        const dataRaw = (raw.match(/^data: (.*)/m) || [])[1] || '';
        let data;
        try { data = JSON.parse(dataRaw); } catch { data = dataRaw; }
        yield { event, data };
      }
    }
  }
}
