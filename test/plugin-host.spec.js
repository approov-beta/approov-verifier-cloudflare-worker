/**
 * Plugin-host unit tests.
 *
 * The host is plugin-agnostic, so we replace the build-time-generated registry
 * with a set of synthetic plugins that deliberately exercise every lifecycle
 * branch: a plugin with no `configure`, one whose `configure` throws, one with
 * no `evaluate`, one whose `evaluate` throws, and one whose `evaluate` returns
 * `undefined` (no annotation written).
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('../src/plugins.generated.js', () => ({
  plugins: [
    // No configure + no evaluate: must be skipped by both hooks.
    { id: 'bare' },
    // configure throws: error is captured, config slot becomes null.
    { id: 'cfg-throws', configure: () => { throw new Error('cfg boom') } },
    // configure returns a fragment, evaluate returns a value (happy path).
    {
      id: 'cfg-ok',
      configure: (env) => ({ seen: env.MARKER }),
      evaluate: ({ config }) => ({ ok: true, marker: config && config.seen })
    },
    // configure returns undefined → coalesced to null.
    { id: 'cfg-undefined', configure: () => undefined },
    // evaluate throws → isolated, recorded as ERROR, others still run.
    { id: 'eval-throws', evaluate: () => { throw new Error('eval boom') } },
    // evaluate returns undefined → no annotation written; custom resultKey.
    { id: 'eval-undefined', resultKey: 'customSlot', evaluate: () => undefined },
    // Reserved result key: must never overwrite core enforcement state.
    { id: 'reserved-result', resultKey: 'tokenResult', evaluate: () => 'PASS' },
    { id: 'reserved-status', resultKey: 'clientStatus', evaluate: () => 'success' },
    // Duplicate ids and result keys must invalidate plugin configuration.
    { id: 'duplicate-id', resultKey: 'duplicate-one' },
    { id: 'duplicate-id', resultKey: 'duplicate-two' },
    { id: 'duplicate-result-a', resultKey: 'shared-result' },
    { id: 'duplicate-result-b', resultKey: 'shared-result' },
    // Unsafe/malformed property names must not enter config or result objects.
    { id: '' },
    { id: 42 },
    null,
    { id: '__proto__' },
    { id: 'unsafe-result', resultKey: 'constructor', evaluate: () => 'polluted' }
  ]
}))

const { configurePlugins, runPlugins, plugins, PLUGIN_EVALUATION_TIMEOUT_MS } = await import('../src/plugin-host.js')

const originalPlugins = [...plugins]

afterEach(() => {
  plugins.splice(0, plugins.length, ...originalPlugins)
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('configurePlugins', () => {
  it('runs each plugin configure hook and isolates failures', () => {
    const errors = []
    const config = configurePlugins({ MARKER: 'hi' }, errors)

    // Plugin with no configure hook gets a null slot.
    expect(config.bare).toBeNull()
    // Throwing configure records an error and a null slot.
    expect(config['cfg-throws']).toBeNull()
    expect(errors.join(' ')).toContain('plugin "cfg-throws" configure failed')
    // Happy-path config fragment is preserved and receives env + shared.
    expect(config['cfg-ok']).toEqual({ seen: 'hi' })
    // configure returning undefined is coalesced to null.
    expect(config['cfg-undefined']).toBeNull()
    expect(errors.join(' ')).toContain('reserved result key "tokenResult"')
    expect(errors.join(' ')).toContain('duplicate plugin id "duplicate-id"')
    expect(errors.join(' ')).toContain('duplicate plugin result key "shared-result"')
    expect(errors.join(' ')).toContain('invalid plugin id')
    expect(errors.join(' ')).toContain('unsafe plugin id "__proto__"')
    expect(errors.join(' ')).toContain('unsafe plugin result key "constructor"')
    expect(Object.getPrototypeOf(config)).toBeNull()
    expect(config).not.toHaveProperty('__proto__')
  })
})

describe('runPlugins', () => {
  it('writes results, skips no-op plugins, and isolates throwing plugins', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const ctx = { pluginConfig: configurePlugins({ MARKER: 'hi' }, []) }
    const out = { tokenResult: 'INVALID_SIG' }

    await runPlugins(ctx, { request: {}, approovToken: 't', tokenVerification: {} }, out)

    // Value-returning evaluate is stored under the plugin id, with config wired in.
    expect(out['cfg-ok']).toEqual({ ok: true, marker: 'hi' })
    // Throwing evaluate is captured as an ERROR annotation, never propagated.
    expect(out['eval-throws']).toEqual({ status: 'ERROR', error: 'eval boom' })
    // A plugin without evaluate writes nothing.
    expect(out).not.toHaveProperty('bare')
    // evaluate returning undefined writes nothing, even under a custom resultKey.
    expect(out).not.toHaveProperty('customSlot')
    expect(out.tokenResult).toBe('INVALID_SIG')
    expect(out).not.toHaveProperty('constructor', 'polluted')

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('plugin "eval-throws" evaluate failed'),
      expect.objectContaining({ status: 'ERROR' })
    )
  })

  it('passes a null config when ctx carries no pluginConfig', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const out = {}

    // ctx without pluginConfig exercises the `: null` branch of config lookup.
    await runPlugins({}, { request: {}, approovToken: 't', tokenVerification: {} }, out)

    expect(out['cfg-ok']).toEqual({ ok: true, marker: null })
  })
})

describe('plugin evaluation deadline', () => {
  it.each(['resolve', 'reject'])('continues after timeout and ignores a late %s', async (settlement) => {
    vi.useFakeTimers()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    let settle
    let signal
    plugins.splice(0, plugins.length,
      {
        id: 'slow',
        evaluate: (args) => {
          signal = args.signal
          return new Promise((resolve, reject) => { settle = settlement === 'resolve' ? resolve : reject })
        }
      },
      { id: 'next', evaluate: () => 'continued' })
    const out = { tokenResult: 'PASS' }
    const pending = runPlugins({}, {}, out)
    await vi.advanceTimersByTimeAsync(PLUGIN_EVALUATION_TIMEOUT_MS - 1)
    expect(out.next).toBeUndefined()
    expect(signal.aborted).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    await pending
    expect(out).toEqual({
      tokenResult: 'PASS',
      slow: { status: 'TIMEOUT', error: 'Plugin evaluation exceeded 1000 ms' },
      next: 'continued'
    })
    expect(signal.aborted).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
    settle(settlement === 'resolve' ? 'late value' : new Error('late rejection'))
    await vi.advanceTimersByTimeAsync(0)
    expect(out.slow.status).toBe('TIMEOUT')
  })

  it('keeps the TIMEOUT result when a cooperative plugin rejects on abort', async () => {
    vi.useFakeTimers()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const aborted = vi.fn()
    plugins.splice(0, plugins.length, {
      id: 'cooperative',
      evaluate: ({ signal }) => new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          aborted()
          reject(new Error('plugin cancelled'))
        }, { once: true })
      })
    })
    const out = {}
    const pending = runPlugins({}, {}, out)
    await vi.advanceTimersByTimeAsync(PLUGIN_EVALUATION_TIMEOUT_MS)
    await pending
    expect(aborted).toHaveBeenCalledOnce()
    expect(out.cooperative.status).toBe('TIMEOUT')
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each(['success', 'failure'])('cleans up the timer after an asynchronous %s', async (outcome) => {
    vi.useFakeTimers()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    let signal
    plugins.splice(0, plugins.length, {
      id: 'quick',
      evaluate: async (args) => {
        signal = args.signal
        if (outcome === 'failure') throw new Error('quick failure')
        return 'done'
      }
    })
    const out = {}
    await runPlugins({}, {}, out)
    expect(out.quick).toEqual(outcome === 'success' ? 'done' : { status: 'ERROR', error: 'quick failure' })
    expect(vi.getTimerCount()).toBe(0)
    await vi.advanceTimersByTimeAsync(PLUGIN_EVALUATION_TIMEOUT_MS)
    expect(signal.aborted).toBe(false)
  })
})

describe('plugin deadline in the Workers runtime', () => {
  it('releases a never-settling plugin using the real runtime timer', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    plugins.splice(0, plugins.length,
      { id: 'never', evaluate: () => new Promise(() => {}) },
      { id: 'after', evaluate: () => 'ran' })
    const out = {}
    await runPlugins({}, {}, out)
    expect(out.never.status).toBe('TIMEOUT')
    expect(out.after).toBe('ran')
  })
})
