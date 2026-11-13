import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import { constants } from 'node:os'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { validateConfig } from './preflight.mjs'

// Keep the wrapper alive until Wrangler finishes its own descendant cleanup.
// Supervisors often signal only this PID, unlike a terminal's process group.
export const runChild = (command, args) => new Promise((resolve, reject) => {
  const child = spawn(command, args, { stdio: 'inherit' })
  const handlers = new Map(['SIGINT', 'SIGTERM'].map(signal => [signal, () => child.kill(signal)]))
  const cleanup = () => {
    for (const [signal, handler] of handlers) process.off(signal, handler)
  }
  for (const [signal, handler] of handlers) process.on(signal, handler)
  child.once('error', err => {
    cleanup()
    reject(err)
  })
  child.once('close', (code, signal) => {
    cleanup()
    resolve(code ?? (signal ? 128 + constants.signals[signal] : 1))
  })
})

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2)
  try {
    validateConfig(args, { development: args[0] === 'dev' })
    const require = createRequire(import.meta.url)
    const cli = resolve(dirname(require.resolve('wrangler/package.json')), 'bin/wrangler.js')
    process.exitCode = await runChild(process.execPath, [cli, ...args])
  } catch (err) {
    console.error(err.message)
    process.exitCode = 1
  }
}
