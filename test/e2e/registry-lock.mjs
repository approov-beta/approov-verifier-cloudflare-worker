import { closeSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

// Different aliases isolate remote requests, but local runs still share the
// generated plugin registry. Fail before either run changes another's bundle.
export const acquireRegistryLock = (repoRoot) => {
  const directory = join(repoRoot, '.wrangler')
  const file = join(directory, 'e2e-registry.lock')
  mkdirSync(directory, { recursive: true })
  let fd
  try {
    fd = openSync(file, 'wx')
  } catch (err) {
    if (err.code !== 'EEXIST') throw err
    throw new Error(`Another E2E run owns the plugin registry. Lock: ${file}. Remove a stale lock only after its owner process stops.`)
  }
  const owner = JSON.stringify({ pid: process.pid, started: Date.now() })
  try {
    writeFileSync(fd, owner)
  } catch (err) {
    closeSync(fd)
    unlinkSync(file)
    throw err
  }
  let released = false
  const signals = ['SIGINT', 'SIGTERM']
  const stop = signal => {
    release()
    // The runner uses synchronous child commands. Signal callbacks run only
    // after an in-flight command ends, so releasing cannot interrupt its build.
    process.kill(process.pid, signal)
  }
  const handlers = new Map(signals.map(signal => [signal, () => stop(signal)]))
  const release = () => {
    if (released) return
    released = true
    process.off('exit', release)
    for (const [signal, handler] of handlers) process.off(signal, handler)
    closeSync(fd)
    try {
      // A manually replaced lock belongs to another run.
      if (readFileSync(file, 'utf8') === owner) unlinkSync(file)
    } catch (err) {
      if (err.code !== 'ENOENT') throw err
    }
  }
  process.once('exit', release)
  for (const [signal, handler] of handlers) process.once(signal, handler)
  return release
}
