import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const document = readFileSync(new URL('../docs/parallel-jwt-validation.md', import.meta.url), 'utf8')
const example = document.match(/<!-- safe-approov-tail-example -->\s*```javascript\n([\s\S]*?)\n```/)
assert.ok(example, 'The safe Tail example must remain executable from its Markdown fence')
const { default: tailWorker } = await import(`data:text/javascript;base64,${Buffer.from(example[1]).toString('base64')}`)

const summary = {
  event: 'approov.request',
  version: 3,
  mode: 'annotate',
  action: 'forward',
  token: { presence: 'PRESENT', verification: 'VERIFIED' },
  attestation: 'PASS',
  binding: 'VALID',
  messageSignature: { mode: 'either', status: 'VALID' },
  validation: 'PASS',
  responseStatus: 200,
  upstreamStatus: 200,
  durationMs: 12.5
}

test('the Tail example exports only approved fields from structured or JSON summaries', async t => {
  const calls = []
  t.mock.method(globalThis, 'fetch', async (...args) => { calls.push(args); return new Response(null) })
  const sensitive = {
    url: 'https://api.example.com/private?email=fixture@example.com&pin=1234',
    headers: { 'X-Session-ID': 'fixture-session-secret', Authorization: 'fixture-auth-secret' },
    approovToken: 'fixture-approov-secret',
    exception: 'fixture-private-exception'
  }
  const inputSummary = {
    ...summary,
    token: { ...summary.token, raw: sensitive.approovToken },
    messageSignature: { ...summary.messageSignature, signature: 'fixture-signature-secret' },
    plugins: { arbitrary: sensitive },
    request: sensitive,
    ...sensitive
  }
  await tailWorker.tail([{
    event: { request: sensitive },
    exceptions: [{ message: sensitive.exception }],
    logs: [
      { level: 'log', message: [inputSummary] },
      { level: 'log', message: [JSON.stringify(inputSummary)] },
      { level: 'log', message: [sensitive, sensitive.exception, '{broken-json'] },
      { level: 'error', message: [inputSummary] }
    ]
  }])

  assert.equal(calls.length, 1)
  assert.equal(calls[0][0], 'https://log-ingester.example.com/v1/logs')
  assert.equal(calls[0][1].method, 'POST')
  assert.deepEqual(JSON.parse(calls[0][1].body), [summary, summary])
  for (const secret of [sensitive.url, ...Object.values(sensitive.headers), sensitive.approovToken, sensitive.exception, 'fixture-signature-secret']) {
    assert.ok(!calls[0][1].body.includes(secret), `The Tail body must omit ${secret}`)
  }
})

test('the Tail example validates values instead of forwarding unknown strings or objects', async t => {
  const calls = []
  t.mock.method(globalThis, 'fetch', async (...args) => { calls.push(args); return new Response(null) })
  const secret = 'fixture-value-must-not-leave'
  await tailWorker.tail([{
    logs: [{
      level: 'log',
      message: [{
        ...summary,
        mode: secret,
        action: { secret },
        token: { presence: secret, verification: { secret } },
        attestation: secret,
        binding: secret,
        messageSignature: { mode: secret, status: { secret } },
        validation: secret,
        responseStatus: '200',
        upstreamStatus: 600,
        durationMs: Infinity
      }]
    }]
  }])

  assert.equal(calls.length, 1)
  assert.deepEqual(JSON.parse(calls[0][1].body), [{
    event: 'approov.request',
    version: 3,
    mode: null,
    action: null,
    token: { presence: null, verification: null },
    attestation: null,
    binding: null,
    messageSignature: { mode: null, status: null },
    validation: null,
    responseStatus: null,
    upstreamStatus: null,
    durationMs: null
  }])
  assert.ok(!calls[0][1].body.includes(secret))
})

test('the Tail example skips unknown versions, malformed messages, and unrelated events', async t => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(null))
  await tailWorker.tail([
    null,
    { logs: 'fixture-private-metadata' },
    { logs: [null, { level: 'log', message: [null, [], 3, 'not JSON', ' '.repeat(65537), { ...summary, version: 4 }, { ...summary, event: 'debug.dump' }] }] },
    { logs: [{ level: 'log', message: 'fixture-raw-console-message' }] }
  ])
  assert.equal(fetch.mock.callCount(), 0)
})
