// Auth regression tests for the JS SDK (MAR-P1-004).
// Run: `node --test sdk/js/` — no dependencies, stub fetch only.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ExecutionClient } from './index.js';

// A canned fetch: records every call, answers per URL.
function stubFetch(routes) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({ url, init });
    const path = new URL(url, 'http://x').pathname;
    const route = routes[path] || routes.default;
    return route(url, init);
  };
  return { calls, fetch };
}

const jsonOk = (data) => ({
  ok: true,
  status: 200,
  json: async () => data,
  text: async () => JSON.stringify(data),
});

const jsonErr = (status, data) => ({
  ok: false,
  status,
  json: async () => data,
  text: async () => JSON.stringify(data),
});

function sseBody(frames) {
  const bytes = frames.map((f) => new TextEncoder().encode(f));
  let i = 0;
  return {
    getReader() {
      return {
        async read() {
          if (i >= bytes.length) return { done: true, value: undefined };
          return { done: false, value: bytes[i++] };
        },
      };
    },
  };
}

describe('authenticated client', () => {
  it('sends Bearer on every endpoint', async () => {
    const { calls, fetch } = stubFetch({
      '/v1/execute/stream': () => ({
        ok: true,
        status: 200,
        body: sseBody(['event: done\ndata: {"success":true}\n\n']),
      }),
      '/v1/sessions/abc': () => ({ ok: true, status: 204, text: async () => '' }),
      default: (url) => jsonOk({ url }),
    });
    const c = new ExecutionClient('http://localhost:3000', { token: 's3cret', fetch });

    await c.health();
    await c.tools();
    assert.equal(typeof await c.policy(), 'string');
    await c.createSession('x');
    await c.deleteSession('abc');
    await c.execute('system', { operation: 'now' });
    await c.batch([['system', { operation: 'now' }]]);
    await c.sequence([['system', { operation: 'now' }]]);
    for await (const _ of c.stream('system', { operation: 'now' })) { /* drain */ }

    assert.ok(calls.length >= 8, `expected calls, got ${calls.length}`);
    for (const call of calls) {
      assert.equal(
        call.init.headers?.authorization,
        'Bearer s3cret',
        `${call.url} missed the token`,
      );
    }
  });

  it('parses SSE events from an authenticated stream', async () => {
    const { fetch } = stubFetch({
      '/v1/execute/stream': () => ({
        ok: true,
        status: 200,
        body: sseBody([
          'event: summary\ndata: {"ok":true}\n\n',
          'event: done\ndata: {"success":true}\n\n',
        ]),
      }),
    });
    const c = new ExecutionClient('http://localhost:3000', { token: 't', fetch });
    const events = [];
    for await (const evt of c.stream('system', { operation: 'now' })) events.push(evt);
    assert.deepEqual(events.map((e) => e.event), ['summary', 'done']);
    assert.deepEqual(events[1].data, { success: true });
  });

  it('never copies the token into thrown errors', async () => {
    const { fetch } = stubFetch({
      default: () => jsonErr(401, { error: 'unauthorized', code: 'unauthorized' }),
    });
    const c = new ExecutionClient('http://localhost:3000', { token: 's3cret', fetch });
    await assert.rejects(() => c.execute('system', { operation: 'now' }), (err) => {
      assert.ok(!String(err.message).includes('s3cret'), `leak: ${err.message}`);
      assert.equal(err.code, 'unauthorized');
      return true;
    });
  });
});

describe('tokenless client', () => {
  it('sends no authorization header (open local deployments keep working)', async () => {
    const { calls, fetch } = stubFetch({ default: (url) => jsonOk({ url }) });
    const c = new ExecutionClient('http://localhost:3000', { fetch });
    await c.execute('system', { operation: 'now' });
    await c.tools();
    assert.ok(!('authorization' in (calls[0].init.headers || {})));
    assert.deepEqual(c.authHeaders(), {});
  });
});
