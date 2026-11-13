// Imported by preflight.test.mjs so CI runs these in Node, outside Vitest.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createConnection } from 'node:net'
import { createInterface } from 'node:readline'
import { runChild } from '../scripts/wrangler.mjs'
import { acquireRegistryLock } from './e2e/registry-lock.mjs'

test('independent preview runs isolate aliases, API policies, and readiness without Cloudflare', () => {
  const probe = spawnSync(process.execPath, [fileURLToPath(new URL('./tooling-preview-probe.mjs', import.meta.url))], { encoding: 'utf8', timeout: 10000 })
  assert.equal(probe.status, 0, probe.stderr || probe.stdout)
  assert.equal(JSON.parse(probe.stdout).urls.length, 3)
})

test('local E2E runs cannot overwrite the same checkout registry concurrently', t => {
  const folder = mkdtempSync(join(tmpdir(), 'approov-e2e-lock-'))
  t.after(() => rmSync(folder, { recursive: true, force: true }))
  const release = acquireRegistryLock(folder)
  t.after(release)
  const lock = join(folder, '.wrangler', 'e2e-registry.lock')
  assert.equal(JSON.parse(readFileSync(lock, 'utf8')).pid, process.pid)
  assert.throws(() => acquireRegistryLock(folder), /Another E2E run owns the plugin registry/)
  release()
  assert.equal(existsSync(lock), false)
  const next = acquireRegistryLock(folder)
  release() // Repeated cleanup must not delete a later owner's lock.
  assert.equal(existsSync(lock), true)
  next()
  assert.equal(existsSync(lock), false)
})

test('PID-only termination releases the local E2E registry lock', { timeout: 10000, skip: process.platform === 'win32' }, async t => {
  const folder = mkdtempSync(join(tmpdir(), 'approov-e2e-lock-signal-'))
  const helper = new URL('./e2e/registry-lock.mjs', import.meta.url).href
  const script = `import { acquireRegistryLock } from ${JSON.stringify(helper)}; acquireRegistryLock(process.argv[1]); console.log('ready'); setInterval(() => {}, 1000)`
  const owner = spawn(process.execPath, ['--input-type=module', '-e', script, folder], { stdio: ['ignore', 'pipe', 'pipe'] })
  const closed = once(owner, 'close')
  t.after(async () => {
    if (owner.exitCode === null && owner.signalCode === null) owner.kill('SIGKILL')
    await closed
    rmSync(folder, { recursive: true, force: true })
  })
  await once(owner.stdout, 'data')
  assert.throws(() => acquireRegistryLock(folder), /Another E2E run owns the plugin registry/)
  owner.kill('SIGTERM')
  const [, signal] = await closed
  assert.equal(signal, 'SIGTERM')
  assert.equal(existsSync(join(folder, '.wrangler', 'e2e-registry.lock')), false)
  acquireRegistryLock(folder)()
})

test('the child runner preserves signal exit status and removes its signal handlers', async () => {
  const counts = ['SIGINT', 'SIGTERM'].map(signal => process.listenerCount(signal))
  assert.equal(await runChild(process.execPath, ['-e', 'process.kill(process.pid, "SIGTERM")']), 143)
  assert.deepEqual(['SIGINT', 'SIGTERM'].map(signal => process.listenerCount(signal)), counts)
  await assert.rejects(runChild('/approov-test-missing-executable', []), { code: 'ENOENT' })
  assert.deepEqual(['SIGINT', 'SIGTERM'].map(signal => process.listenerCount(signal)), counts)
})

const isAlive = pid => {
  try { process.kill(pid, 0); return true } catch (err) {
    if (err.code === 'ESRCH') return false
    throw err
  }
}

for (const signal of ['SIGTERM', 'SIGINT']) {
  test(`PID-only ${signal} waits for the child's server and descendants to stop`, { timeout: 15000, skip: process.platform === 'win32' }, async t => {
    const folder = mkdtempSync(join(tmpdir(), 'approov-wrapper-signal-'))
    const marker = join(folder, 'stopped')
    const leaf = join(folder, 'leaf.mjs')
    const cli = join(folder, 'cli.mjs')
    writeFileSync(leaf, `
      import { createServer } from 'node:net'
      import { writeFileSync } from 'node:fs'
      const server = createServer(socket => socket.end())
      let stopping = false
      for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => {
        if (stopping) return
        stopping = true
        setTimeout(() => server.close(() => {
          writeFileSync(process.argv[2], signal)
          process.exit(0)
        }), 100)
      })
      server.listen(0, '127.0.0.1', () => console.log(JSON.stringify({ leafPid: process.pid, port: server.address().port })))
    `)
    writeFileSync(cli, `
      import { spawn } from 'node:child_process'
      const child = spawn(process.execPath, [process.argv[2], process.argv[3]], { stdio: 'inherit' })
      console.log(JSON.stringify({ cliPid: process.pid }))
      for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => child.kill(signal))
      child.on('close', code => process.exit(code ?? 1))
    `)
    const runner = new URL('../scripts/wrangler.mjs', import.meta.url).href
    const harness = `import { runChild } from ${JSON.stringify(runner)}; process.exitCode = await runChild(process.execPath, process.argv.slice(1))`
    const wrapper = spawn(process.execPath, ['--input-type=module', '-e', harness, cli, leaf, marker], { stdio: ['ignore', 'pipe', 'pipe'] })
    const closed = once(wrapper, 'close')
    const lines = createInterface({ input: wrapper.stdout })
    let stderr = ''
    wrapper.stderr.on('data', data => { stderr += data })
    const pids = [wrapper.pid]
    t.after(async () => {
      lines.close()
      for (const pid of pids.reverse()) {
        try { process.kill(pid, 'SIGKILL') } catch (err) { if (err.code !== 'ESRCH') throw err }
      }
      await closed
      rmSync(folder, { recursive: true, force: true })
    })
    const ready = await new Promise((resolve, reject) => {
      lines.on('line', line => {
        const value = JSON.parse(line)
        if (value.cliPid) pids.push(value.cliPid)
        if (value.leafPid) { pids.push(value.leafPid); resolve(value) }
      })
      wrapper.once('close', () => reject(new Error(`wrapper stopped before readiness: ${stderr}`)))
    })
    assert.equal(isAlive(ready.leafPid), true)
    wrapper.kill(signal)
    const [code, exitSignal] = await closed
    assert.equal(exitSignal, null)
    assert.equal(code, 0, stderr)
    assert.equal(readFileSync(marker, 'utf8'), signal)
    for (const pid of pids) assert.equal(isAlive(pid), false, `PID ${pid} must stop before the wrapper exits`)
    await new Promise((resolve, reject) => {
      const socket = createConnection({ host: '127.0.0.1', port: ready.port })
      socket.once('error', err => err.code === 'ECONNREFUSED' ? resolve() : reject(err))
      socket.once('connect', () => { socket.destroy(); reject(new Error('the descendant server still accepts connections')) })
    })
  })
}
