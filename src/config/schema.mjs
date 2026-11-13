// Shared by Wrangler preflight and the Worker. Errors never include values.
export const LEGACY_CONFIG = Object.freeze({
  APPROOV_REJECT_ON_FAIL: 'APPROOV_MODE, APPROOV_TOKEN_ACTION, APPROOV_TOKEN_BINDING_ACTION and APPROOV_MESSAGE_SIGNING_ACTION',
  APPROOV_ANNOTATE_RESULT: 'APPROOV_MODE',
  APPROOV_ANNOTATE_ON_FAIL: 'APPROOV_MODE',
  APPROOV_MESSAGE_SIGNING_MODE: 'APPROOV_MESSAGE_SIGNING_REQUIRED (install, account, either, or both)',
  APPROOV_TOKEN_BINDING: 'APPROOV_TOKEN_BINDING_ENABLED',
  APPROOV_BINDING_HEADER_NAME: 'APPROOV_TOKEN_BINDING_HEADER_NAME',
  APPROOV_BINDING_CLAIM_NAME: 'APPROOV_TOKEN_BINDING_CLAIM_NAME',
  APPROOV_FAIL_RESPONSE_STATUS: 'APPROOV_BLOCK_RESPONSE_STATUS',
  APPROOV_FAIL_RESPONSE_MESSAGE: 'APPROOV_BLOCK_RESPONSE_BODY',
  APPROOV_ANALYTICS_LOG: 'APPROOV_LOGGING_ENABLED'
})

const CORE_SCHEMA = Object.freeze({
  APPROOV_MODE: { type: 'enum', values: ['annotate', 'block'] },
  APPROOV_TOKEN_ACTION: { type: 'enum', values: ['block', 'continue'] },
  APPROOV_TOKEN_BINDING_ACTION: { type: 'enum', values: ['block', 'continue'] },
  APPROOV_MESSAGE_SIGNING_ACTION: { type: 'enum', values: ['block', 'continue'] },
  APPROOV_MESSAGE_SIGNING_REQUIRED: { type: 'enum', values: ['install', 'account', 'either', 'both'] },
  APPROOV_TOKEN_BINDING_ENABLED: { type: 'boolean' },
  APPROOV_LOGGING_ENABLED: { type: 'boolean' },
  APPROOV_ANALYTICS_ENABLED: { type: 'boolean' },
  APPROOV_DEBUG: { type: 'boolean' },
  APPROOV_ECHO_MODE: { type: 'boolean' },
  APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET: { type: 'boolean' },
  APPROOV_TOKEN_AUDIENCE_FROM_HOST: { type: 'boolean' },
  APPROOV_TOKEN_HEADER_NAME: { type: 'header' },
  APPROOV_STATUS_HEADER_NAME: { type: 'header' },
  APPROOV_TOKEN_BINDING_HEADER_NAME: { type: 'header' },
  APPROOV_TOKEN_BINDING_CLAIM_NAME: { type: 'text' },
  APPROOV_TOKEN_AUDIENCE: { type: 'text' },
  APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: { type: 'text' },
  APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID: { type: 'text' },
  APPROOV_BACKEND_CONFIG: { type: 'text' },
  APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS: { type: 'integer', min: 0, max: Number.MAX_SAFE_INTEGER },
  APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES: { type: 'integer', min: 0, max: Number.MAX_SAFE_INTEGER },
  APPROOV_BLOCK_RESPONSE_STATUS: { type: 'integer', min: 200, max: 599 },
  APPROOV_BLOCK_RESPONSE_BODY: { type: 'string' },
  APPROOV_PROTECTED_PATHS: { type: 'string' },
  APPROOV_ANALYTICS: { type: 'binding' },
  API_PASSTHROUGH: { type: 'boolean' },
  API_PORT: { type: 'integer', min: 1, max: 65535 },
  API_DOMAIN: { type: 'string' }
})

export const parseBoolean = (value, fallback = false, errors = null, name = null) => {
  if (value === undefined) return fallback
  if (value === true || value === 'true') return true
  if (value === false || value === 'false') return false
  if (errors && name) errors.push(`env.${name} must be true or false`)
  return fallback
}

const scalarError = (value, rule) => {
  switch (rule.type) {
    case 'boolean':
      return [true, false, 'true', 'false'].includes(value) ? null : 'must be true or false'
    case 'enum':
      return rule.values.includes(value) ? null : `must be one of: ${rule.values.join(', ')}`
    case 'integer': {
      const validType = typeof value === 'number' || (typeof value === 'string' && /^\d+$/.test(value))
      const number = Number(value)
      return validType && Number.isSafeInteger(number) && number >= rule.min && number <= rule.max
        ? null
        : `must be an integer between ${rule.min} and ${rule.max}`
    }
    case 'header':
      return typeof value === 'string' && /^[!#$%&'*+.^_`|~\w-]+$/.test(value) ? null : 'must be a valid HTTP header name'
    case 'text':
      return typeof value === 'string' && value.trim() !== '' ? null : 'must be a non-empty string'
    case 'string':
      return typeof value === 'string' ? null : 'must be a string'
    case 'binding':
      return value && typeof value.writeDataPoint === 'function' ? null : 'must be an Analytics Engine binding'
    default:
      return 'has an unsupported configuration schema'
  }
}

export const validateWorkerConfig = (env, pluginSchemas = []) => {
  const errors = []
  const schema = { ...CORE_SCHEMA }
  for (const fields of pluginSchemas) {
    for (const [name, rule] of Object.entries(fields)) {
      if (!name.startsWith('APPROOV_') || Object.hasOwn(schema, name) || Object.hasOwn(LEGACY_CONFIG, name)) {
        errors.push(`plugin configuration field ${name} conflicts with the Worker schema`)
      } else {
        schema[name] = rule
      }
    }
  }
  for (const name of Object.keys(env)) {
    if (Object.hasOwn(LEGACY_CONFIG, name)) {
      errors.push(`env.${name} is no longer supported; use ${LEGACY_CONFIG[name]}`)
    } else if (name.startsWith('APPROOV_') && !Object.hasOwn(schema, name)) {
      errors.push(`unknown configuration field env.${name}`)
    }
  }
  for (const [name, rule] of Object.entries(schema)) {
    if (!Object.hasOwn(env, name)) continue
    if (name === 'API_PORT' && env[name] === '' && parseBoolean(env.API_PASSTHROUGH)) continue
    const error = scalarError(env[name], rule)
    if (error) errors.push(`env.${name} ${error}`)
  }
  if (!Object.hasOwn(env, 'APPROOV_MODE')) errors.push('env.APPROOV_MODE is required (annotate or block)')

  const mode = env.APPROOV_MODE
  const bindingEnabled = parseBoolean(env.APPROOV_TOKEN_BINDING_ENABLED)
  const actionNames = ['APPROOV_TOKEN_ACTION', 'APPROOV_TOKEN_BINDING_ACTION', 'APPROOV_MESSAGE_SIGNING_ACTION']
  if (mode === 'annotate') {
    for (const name of [...actionNames, 'APPROOV_BLOCK_RESPONSE_STATUS', 'APPROOV_BLOCK_RESPONSE_BODY']) {
      if (Object.hasOwn(env, name)) errors.push(`env.${name} must not be set in annotate mode`)
    }
  } else if (mode === 'block') {
    for (const name of ['APPROOV_TOKEN_ACTION', 'APPROOV_MESSAGE_SIGNING_ACTION']) {
      if (!Object.hasOwn(env, name)) errors.push(`env.${name} is required in block mode`)
    }
    if (bindingEnabled && !Object.hasOwn(env, 'APPROOV_TOKEN_BINDING_ACTION')) {
      errors.push('env.APPROOV_TOKEN_BINDING_ACTION is required when token binding is enabled in block mode')
    }
  }
  if (!bindingEnabled && Object.hasOwn(env, 'APPROOV_TOKEN_BINDING_ACTION')) {
    errors.push('env.APPROOV_TOKEN_BINDING_ACTION must not be set when token binding is disabled')
  }
  return errors
}

export const assertValidConfig = (context) => {
  if (!context.isValid) throw new Error(`Invalid Approov configuration:\n${context.errors.join('\n')}`)
}
