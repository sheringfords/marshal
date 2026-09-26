# SDKs for marshalld

Thin clients over `marshalld` HTTP API (`/v1/execute`, SSE `/v1/execute/stream`).

Both clients accept a token for authenticated deployments; it is sent as
`Authorization: Bearer <token>` on every request and never copied into
errors. Tests: `node --test sdk/js/`, `python3 sdk/python/test_sdk_auth.py`.

## JS

```js
import { ExecutionClient } from './js/index.js'
const c = new ExecutionClient('http://localhost:3000', { token: process.env.MARSHALLD_API_TOKEN })
console.log(await c.health())
console.log(await c.tools())
console.log(await c.policy())
const {session_id} = await c.createSession('demo')
console.log(await c.execute('filesystem', {operation:'mkdir', path:`/tmp/marshalld/${session_id}/hi`}))
for await (const {event, data} of c.stream('shell', {program:'/bin/echo', args:['hi']})) console.log(event, data)
await c.deleteSession(session_id)
```

## Python

```python
from marshall_sdk import ExecutionClient
c = ExecutionClient("http://localhost:3000", token="...")
c.health()
c.get_policy()
c.create_session("demo")
c.execute("shell", {"program": "/bin/echo", "args": ["hi"]})
for event, data in c.stream("shell", {"program": "/bin/echo", "args": ["hi"]}): print(event, data)
c.delete_session(session_id)
```
