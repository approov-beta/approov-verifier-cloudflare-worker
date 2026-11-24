import { describe, expect, it, vi, afterEach } from 'vitest'
import { assertValidConfig, LEGACY_CONFIG, validateWorkerConfig } from '../src/config/schema.mjs'
import { establishContext } from '../src/config/context.js'
import { handleRequest } from '../src/worker/handle-request.js'
import { makeEnv } from './fixtures.js'

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })
const block = { APPROOV_MODE: 'block', APPROOV_TOKEN_ACTION: 'block', APPROOV_MESSAGE_SIGNING_ACTION: 'continue' }

describe('explicit Worker configuration', () => {
  it.each([
    { APPROOV_MODE: 'annotate' }, block,
    { ...block, APPROOV_TOKEN_BINDING_ENABLED: true, APPROOV_TOKEN_BINDING_ACTION: 'continue' },
    { ...block, APPROOV_TOKEN_BINDING_ENABLED: 'true', APPROOV_TOKEN_BINDING_ACTION: 'block' }
  ])('accepts an explicit valid policy (%j)', env => expect(validateWorkerConfig(env)).toEqual([]))

  it.each([
    [{}, 'APPROOV_MODE'],
    [{ APPROOV_MODE: 'BLOCK' }, 'APPROOV_MODE'],
    [{ APPROOV_MODE: null }, 'APPROOV_MODE'],
    [{ APPROOV_MODE: 'block' }, 'APPROOV_TOKEN_ACTION'],
    [{ APPROOV_MODE: 'block', APPROOV_TOKEN_ACTION: 'block' }, 'APPROOV_MESSAGE_SIGNING_ACTION'],
    [{ ...block, APPROOV_TOKEN_BINDING_ENABLED: true }, 'APPROOV_TOKEN_BINDING_ACTION'],
    [{ ...block, APPROOV_TOKEN_BINDING_ACTION: 'continue' }, 'APPROOV_TOKEN_BINDING_ACTION'],
    [{ ...block, APPROOV_TOKEN_ACTION: 'log' }, 'APPROOV_TOKEN_ACTION'],
    [{ ...block, APPROOV_MESSAGE_SIGNING_ACTION: 'ignore' }, 'APPROOV_MESSAGE_SIGNING_ACTION'],
    [{ ...block, APPROOV_MESSAGE_SIGNING_ACTION: ' continue ' }, 'APPROOV_MESSAGE_SIGNING_ACTION'],
    [{ APPROOV_MODE: 'annotate', APPROOV_TOKNE_ACTION: 'block' }, 'APPROOV_TOKNE_ACTION']
  ])('rejects incomplete or conflicting policy (%j)', (env, name) => {
    expect(validateWorkerConfig(env).join('\n')).toContain(name)
  })

  it.each(['APPROOV_TOKEN_ACTION', 'APPROOV_TOKEN_BINDING_ACTION', 'APPROOV_MESSAGE_SIGNING_ACTION', 'APPROOV_BLOCK_RESPONSE_STATUS', 'APPROOV_BLOCK_RESPONSE_BODY'])('rejects any presence of %s in annotate mode', name => {
    for (const value of ['block', 'continue', '', null]) {
      expect(validateWorkerConfig({ APPROOV_MODE: 'annotate', [name]: value }).join('\n')).toContain('must not be set in annotate mode')
    }
  })

  it.each(Object.keys(LEGACY_CONFIG))('reports the replacement for %s', name => {
    const errors = validateWorkerConfig({ APPROOV_MODE: 'annotate', [name]: 'PRIVATE-VALUE' })
    expect(errors.join('\n')).toContain(LEGACY_CONFIG[name])
    expect(errors.join('\n')).not.toContain('PRIVATE-VALUE')
  })

  it.each([
    ['APPROOV_LOGGING_ENABLED', 'yes'], ['APPROOV_DEBUG', null],
    ['APPROOV_TOKEN_HEADER_NAME', ''], ['APPROOV_TOKEN_BINDING_HEADER_NAME', 3],
    ['APPROOV_STATUS_HEADER_NAME', 'bad header'],
    ['APPROOV_TOKEN_BINDING_CLAIM_NAME', {}], ['APPROOV_BACKEND_CONFIG', ''],
    ['APPROOV_BLOCK_RESPONSE_BODY', {}], ['API_DOMAIN', {}],
    ['APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS', '-1'], ['APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES', '1.5'],
    ['APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES', '9007199254740992'],
    ['APPROOV_BLOCK_RESPONSE_STATUS', 199], ['APPROOV_BLOCK_RESPONSE_STATUS', 600],
    ['APPROOV_ANALYTICS', {}]
  ])('rejects an invalid value for %s', (name, value) => {
    expect(validateWorkerConfig({ ...block, [name]: value }).join('\n')).toContain(name)
  })

  it('accepts supported scalar values and an Analytics Engine binding', () => {
    expect(validateWorkerConfig({
      ...block,
      APPROOV_LOGGING_ENABLED: true,
      APPROOV_ANALYTICS_ENABLED: 'false',
      APPROOV_TOKEN_HEADER_NAME: 'X-Token',
      APPROOV_TOKEN_AUDIENCE: 'api',
      APPROOV_BLOCK_RESPONSE_BODY: '',
      APPROOV_BLOCK_RESPONSE_STATUS: '403',
      APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS: 0,
      APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES: '0',
      APPROOV_ANALYTICS: { writeDataPoint () {} }
    })).toEqual([])
  })

  it('validates plugin fields and rejects schema conflicts', () => {
    const env = { APPROOV_MODE: 'annotate', APPROOV_CUSTOM_ENABLED: 'false' }
    const plugin = { APPROOV_CUSTOM_ENABLED: { type: 'boolean' } }
    expect(validateWorkerConfig(env, [plugin])).toEqual([])
    expect(validateWorkerConfig(env).join('\n')).toContain('unknown')
    for (const name of ['OTHER_FIELD', 'APPROOV_MODE', 'APPROOV_REJECT_ON_FAIL']) {
      expect(validateWorkerConfig(env, [{ [name]: { type: 'boolean' } }]).join('\n')).toContain('conflicts')
    }
    expect(validateWorkerConfig(env, [{ APPROOV_CUSTOM_ENABLED: { type: 'unsupported' } }]).join('\n')).toContain('unsupported configuration schema')
  })

  it('uses accepted native numeric settings without replacing them with defaults', () => {
    const ctx = establishContext(makeEnv({
      APPROOV_MODE: 'block',
      APPROOV_BLOCK_RESPONSE_STATUS: 418,
      APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS: 0,
      APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES: 4,
      APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: 'test secret'
    }))
    expect(ctx.isValid).toBe(true)
    expect(ctx.approovBlockResponseStatus).toBe(418)
    expect(ctx.approovMessageSigningTolerance).toBe(0)
    expect(ctx.approovMessageSigningMaxBodyBytes).toBe(4)
  })

  it('reports all startup errors without values', () => {
    const ctx = establishContext(makeEnv({ APPROOV_MODE: 'PRIVATE-MODE', APPROOV_TOKEN_HEADER_NAME: {}, APPROOV_BACKEND_CONFIG: 'PRIVATE-SECRET' }))
    expect(ctx.isValid).toBe(false)
    expect(() => assertValidConfig(ctx)).toThrow('APPROOV_MODE')
    expect(() => assertValidConfig(ctx)).toThrow('APPROOV_TOKEN_HEADER_NAME')
    expect(ctx.errors.join('\n')).not.toContain('PRIVATE')
    expect(() => assertValidConfig(establishContext(makeEnv()))).not.toThrow()
  })

  it('checks policy in preflight without a local backend export', () => {
    const env = { APPROOV_MODE: 'annotate', API_DOMAIN: 'api.example.com' }
    expect(establishContext(env, { preflight: true }).isValid).toBe(true)
    expect(establishContext({ ...env, APPROOV_TOKEN_ACTION: 'block' }, { preflight: true }).isValid).toBe(false)
    expect(establishContext(makeEnv(), { preflight: true }).isValid).toBe(true)
  })

  it('revalidates mutated bindings instead of using a stale context', async () => {
    const env = makeEnv()
    const first = establishContext(env)
    env.APPROOV_MODE = 'block'
    expect(establishContext(env)).not.toBe(first)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const origin = vi.fn()
    vi.stubGlobal('fetch', origin)
    expect((await handleRequest(new Request('https://worker.local/api'), env)).status).toBe(500)
    expect(origin).not.toHaveBeenCalled()
    env.APPROOV_TOKEN_ACTION = 'continue'
    env.APPROOV_MESSAGE_SIGNING_ACTION = 'continue'
    expect(establishContext(env).isValid).toBe(true)
  })
})

describe('block mode without a blocking action', () => {
  const warned = (overrides) => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const ctx = establishContext(makeEnv({ APPROOV_MODE: 'block', ...overrides }))
    expect(ctx.isValid).toBe(true)
    return warn.mock.calls.some(([message]) => message.includes('no action is "block"'))
  }

  it('warns when every action is "continue"', () => {
    expect(warned({ APPROOV_TOKEN_ACTION: 'continue', APPROOV_MESSAGE_SIGNING_ACTION: 'continue' })).toBe(true)
  })

  it('stays quiet when one action blocks', () => {
    expect(warned({ APPROOV_TOKEN_ACTION: 'continue', APPROOV_MESSAGE_SIGNING_ACTION: 'block' })).toBe(false)
  })
})
