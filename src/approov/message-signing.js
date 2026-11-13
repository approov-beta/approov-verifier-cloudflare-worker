import crypto from 'node:crypto'
import {
  APPROOV_MESSAGE_SIGNING_ALGORITHMS,
  APPROOV_MESSAGE_SIGNING_MODES,
  APPROOV_MESSAGE_SIGNING_OUTCOMES,
  APPROOV_MESSAGE_SIGNING_REQUIRED_FIELDS,
  APPROOV_MESSAGE_SIGNING_REQUIRED_PARAMS,
  APPROOV_MESSAGE_SIGNING_URL_FIELDS
} from '../constants.js'
import { hasText } from '../utils/text.js'
import { decodeBase64OrBase64Url } from '../utils/crypto.js'
import { deriveAccountDeviceKey } from './account-key.js'
import {
  StructuredHeaderDictionary,
  createVerifier,
  httpbis
} from '../vendor/http-message-signatures.js'

/**
 * Normalize an installation public key claim into PEM SPKI format.
 *
 * `ipk` may arrive either as PEM text or base64/base64url-encoded DER SPKI.
 * The signature verifier expects a PEM-like key representation.
 *
 * @param {String} value Raw public key value from token claim.
 * @param {String} label Human-readable key label for error messages.
 * @returns {String} PEM-formatted public key.
 * @throws {Error} When the provided key value cannot be parsed.
 */
const createPublicKeyFromValue = (value, label) => {
  const trimmed = value.trim()
  try {
    let keyObject = null
    if (trimmed.includes('-----BEGIN')) {
      keyObject = crypto.createPublicKey(trimmed)
    } else {
      const der = decodeBase64OrBase64Url(trimmed)
      keyObject = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' })
    }

    if (keyObject.asymmetricKeyType !== 'ec' || keyObject.asymmetricKeyDetails.namedCurve !== 'prime256v1') {
      throw new Error('Install key must use ECDSA P-256')
    }
    return keyObject
      .export({ format: 'pem', type: 'spki' })
      .toString()
  } catch (err) {
    throw new Error(`${label} is invalid: ${err.message}`)
  }
}

/**
 * Build the canonical request object expected by the vendored verifier.
 *
 * Signature verification operates on normalized lowercase `signature` and
 * `signature-input` headers plus the original method/url/header set.
 *
 * @param {*} request Incoming request.
 * @param {String} signatureHeader Serialized `Signature` entry.
 * @param {String} signatureInputHeader Serialized `Signature-Input` entry.
 * @returns {{method: String, url: String, headers: Object}} Canonical request object.
 */
const buildSignatureRequest = (request, signatureHeader, signatureInputHeader) => {
  const headers = Object.fromEntries(request.headers.entries())
  headers.signature = signatureHeader
  headers['signature-input'] = signatureInputHeader

  return {
    method: request.method,
    url: request.url,
    headers
  }
}

/**
 * Decode a parsed `Content-Digest` Byte Sequence into digest bytes.
 *
 * The bundled parser stores the original base64 spelling. RFC 8941 permits
 * omitted padding and nonzero pad bits, so compare decoded bytes instead.
 * Other Structured Field types and malformed base64 are not digest values.
 *
 * @param {*} item Parsed dictionary value.
 * @returns {Buffer|null} Digest bytes, or null when unsupported.
 */
const extractExpectedDigest = (item) => {
  if (!item || typeof item.toBase64 !== 'function') return null
  const encoded = item.toBase64()
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}(?:==)?|[A-Za-z0-9+/]{3}=?)?$/.test(encoded)) return null
  return Buffer.from(encoded, 'base64')
}

class ContentDigestValidationError extends Error {}

/**
 * Validate RFC 9530 `Content-Digest` when that header is present.
 *
 * Supports `sha-256` and `sha-512`. Any mismatch or unsupported algorithm/value
 * causes a hard verification failure.
 *
 * @param {*} ctx Worker context.
 * @param {*} request Incoming request.
 * @returns {Promise<void>} Resolves when digest is valid or not present.
 * @throws {Error} On malformed header, unsupported algorithms, or mismatch.
 */
const verifyContentDigest = async (ctx, request) => {
  const header = request.headers.get('content-digest')
  if (!hasText(header)) return

  let digestEntries
  try {
    digestEntries = new StructuredHeaderDictionary(header).parsed
  } catch {
    throw new ContentDigestValidationError('Content-Digest header is malformed')
  }
  /* istanbul ignore next -- defensive: a non-blank header either parses to a
     dictionary with at least one entry or throws during parsing above. */
  if (!digestEntries || digestEntries.size === 0) {
    throw new ContentDigestValidationError('Content-Digest header is empty')
  }

  const hashers = []

  for (const [algo, [item]] of digestEntries.entries()) {
    const normalizedAlgo = algo.toLowerCase()
    const hashAlgo = normalizedAlgo === 'sha-256'
      ? 'sha256'
      : normalizedAlgo === 'sha-512'
        ? 'sha512'
        : null

    if (!hashAlgo) {
      throw new ContentDigestValidationError(`Unsupported content digest algorithm: ${algo}`)
    }

    const expectedDigest = extractExpectedDigest(item)

    if (expectedDigest === null) {
      throw new ContentDigestValidationError(`Unsupported Content-Digest value for ${algo}`)
    }

    hashers.push({
      algo,
      expectedDigest,
      hash: crypto.createHash(hashAlgo)
    })
  }

  const body = request.clone().body
  if (body) {
    const reader = body.getReader()
    let bytesRead = 0

    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        bytesRead += value.byteLength
        if (bytesRead > ctx.approovMessageSigningMaxBodyBytes) {
          throw new ContentDigestValidationError(
            `Content-Digest body exceeds ${ctx.approovMessageSigningMaxBodyBytes} byte limit`
          )
        }

        for (const { hash } of hashers) {
          hash.update(value)
        }
      }
    } finally {
      // Release the cloned branch. An abandoned, unread branch would otherwise
      // buffer the rest of the body in memory while the request is forwarded.
      try { await reader.cancel() } catch { /* the stream is already closed or errored */ }
    }
  }

  for (const { algo, expectedDigest, hash } of hashers) {
    const computedDigest = hash.digest()

    if (
      expectedDigest.length !== computedDigest.length ||
      !crypto.timingSafeEqual(expectedDigest, computedDigest)
    ) {
      throw new ContentDigestValidationError(`Content digest verification failed for ${algo}`)
    }
  }
}

/**
 * Verify a single named signature entry (`install` or `account`).
 *
 * The worker isolates one entry from potentially multi-entry signature headers,
 * then verifies that entry with the configured algorithm/key pair.
 *
 * @param {*} args Verification arguments.
 * @param {*} args.request Incoming request.
 * @param {*} args.signatures Parsed `Signature` dictionary.
 * @param {*} args.signatureInputs Parsed `Signature-Input` dictionary.
 * @param {String} args.signatureName Entry key to verify.
 * @param {*} args.verificationKey Key material used by verifier.
 * @param {String} args.algorithm Expected signing algorithm identifier.
 * @param {Number} args.tolerance Allowed time skew in seconds.
 * @param {String[]} args.requiredFields Components the signature must cover.
 * @returns {Promise<{ok: Boolean, status: String, error: String|null}>} Entry verification outcome.
 */
const verifySignatureEntry = async ({
  request,
  signatures,
  signatureInputs,
  signatureName,
  verificationKey,
  algorithm,
  tolerance,
  requiredFields
}) => {
  const signatureEntry = signatures.get(signatureName)
  const signatureInputEntry = signatureInputs.get(signatureName)
  if (!hasText(signatureEntry) || !hasText(signatureInputEntry)) {
    return {
      ok: false,
      status: APPROOV_MESSAGE_SIGNING_OUTCOMES.MISSING_SIGNATURE_ENTRY,
      error: `Missing ${signatureName} signature entry`
    }
  }

  const signatureHeader = `${signatureName}=${signatureEntry}`
  const signatureInputHeader = `${signatureName}=${signatureInputEntry}`

  const signatureRequest = buildSignatureRequest(
    request,
    signatureHeader,
    signatureInputHeader
  )

  let internalError = false
  try {
    // Inspect only the entry being verified. Another signature's coverage must
    // never satisfy this entry's policy. The vendor validates malformed inputs.
    const components = signatureInputs.parsed.get(signatureName)[0]
    const coversTargetUri = Array.isArray(components) &&
      components.some(([name, params]) => name === '@target-uri' && params.size === 0)
    const urlFields = coversTargetUri ? ['@target-uri'] : APPROOV_MESSAGE_SIGNING_URL_FIELDS
    const verified = await httpbis.verifyMessage(
      {
        keyLookup: async () => ({
          id: signatureName,
          algs: [algorithm],
          verify: async (...args) => {
            try {
              return await createVerifier(verificationKey, algorithm)(...args)
            } catch {
              internalError = true
              return false
            }
          }
        }),
        requiredParams: APPROOV_MESSAGE_SIGNING_REQUIRED_PARAMS,
        requiredFields: [...requiredFields, ...urlFields],
        tolerance
      },
      signatureRequest
    )

    if (internalError) {
      return { ok: false, status: APPROOV_MESSAGE_SIGNING_OUTCOMES.ERROR, error: null }
    }
    return verified === true
      ? { ok: true, status: APPROOV_MESSAGE_SIGNING_OUTCOMES.VALID, error: null }
      : {
          ok: false,
          status: APPROOV_MESSAGE_SIGNING_OUTCOMES.INVALID,
          error: `Invalid ${signatureName} message signature`
        }
  } catch (err) {
    return {
      ok: false,
      status: APPROOV_MESSAGE_SIGNING_OUTCOMES.INVALID,
      error: err.message
    }
  }
}

/** Explicit requirements override compatibility with token-only deployments. */
export const getMessageSigningMode = (payload, ctx) => {
  if (ctx?.approovMessageSigningRequired) return ctx.approovMessageSigningRequired
  const install = Object.hasOwn(payload, 'ipk')
  const account = Object.hasOwn(payload, 'mskid')
  if (install && account) return APPROOV_MESSAGE_SIGNING_MODES.EITHER
  if (install) return APPROOV_MESSAGE_SIGNING_MODES.INSTALL
  if (account) return APPROOV_MESSAGE_SIGNING_MODES.ACCOUNT
  return APPROOV_MESSAGE_SIGNING_MODES.NONE
}

const failure = (status, error = null) => ({ ok: false, status, error })

const requiredNames = mode => mode === 'both' ? ['install', 'account'] : ['install', 'account'].includes(mode) ? [mode] : []

/** Verify required and present signatures. A valid member cannot hide a failure. */
const checkRequiredSignatures = async (ctx, request, payload) => {
  const mode = getMessageSigningMode(payload, ctx)
  const required = requiredNames(mode)
  const result = {
    ok: true,
    status: APPROOV_MESSAGE_SIGNING_OUTCOMES.NOT_REQUIRED,
    mode,
    signatureName: required.length === 1 ? required[0] : null,
    error: null,
    signatures: { install: null, account: null }
  }

  let signatures
  let signatureInputs
  let commonFailure = null
  const signatureHeader = request.headers.get('signature')
  const signatureInputHeader = request.headers.get('signature-input')
  const headersPresent = signatureHeader !== null || signatureInputHeader !== null
  if (!hasText(signatureHeader) || !hasText(signatureInputHeader)) {
    commonFailure = failure(APPROOV_MESSAGE_SIGNING_OUTCOMES.MISSING_HEADERS)
  }
  try {
    if (hasText(signatureHeader)) signatures = new StructuredHeaderDictionary(signatureHeader)
    if (hasText(signatureInputHeader)) signatureInputs = new StructuredHeaderDictionary(signatureInputHeader)
  } catch {
    commonFailure = failure(APPROOV_MESSAGE_SIGNING_OUTCOMES.MALFORMED_HEADERS)
  }
  // A member in either dictionary is present, including an unmatched entry.
  // Claims supply keys; they must not suppress verification of a present member.
  const selected = ['install', 'account'].filter(name => required.includes(name) ||
    signatures?.parsed.has(name) || signatureInputs?.parsed.has(name))
  if (mode === 'either' && !selected.length) selected.push('install', 'account')
  if (!selected.length) {
    if (headersPresent && commonFailure) return { ...result, ...commonFailure }
    return result
  }
  result.signatureName = selected.length === 1 ? selected[0] : null

  const keys = {}
  if (selected.includes('install')) {
    if (typeof payload.ipk !== 'string' || !payload.ipk.trim()) {
      result.signatures.install = failure(APPROOV_MESSAGE_SIGNING_OUTCOMES.INVALID_INSTALL_KEY_CLAIM)
    } else {
      try {
        keys.install = createPublicKeyFromValue(payload.ipk, 'Approov install public key')
      } catch {
        result.signatures.install = failure(APPROOV_MESSAGE_SIGNING_OUTCOMES.INVALID_INSTALL_KEY_CLAIM)
      }
    }
  }
  if (selected.includes('account')) {
    if (typeof payload.mskid !== 'string' || !payload.mskid.trim()) {
      result.signatures.account = failure(APPROOV_MESSAGE_SIGNING_OUTCOMES.INVALID_ACCOUNT_KEY_ID_CLAIM)
    } else if (!ctx.approovAccountMessageSigningSecret) {
      result.signatures.account = failure(APPROOV_MESSAGE_SIGNING_OUTCOMES.ACCOUNT_SECRET_NOT_CONFIGURED)
    } else if (ctx.approovAccountMessageSigningKeyId && ctx.approovAccountMessageSigningKeyId !== payload.mskid.trim()) {
      result.signatures.account = failure(APPROOV_MESSAGE_SIGNING_OUTCOMES.ACCOUNT_KEY_ID_MISMATCH)
    } else {
      try {
        // evaluateApproovToken supplies only a cryptographically verified payload.
        keys.account = deriveAccountDeviceKey(ctx.approovAccountMessageSigningSecret, payload.did)
        if (!keys.account) {
          result.signatures.account = failure(APPROOV_MESSAGE_SIGNING_OUTCOMES.INVALID_DEVICE_ID_CLAIM)
        }
      } catch {
        result.signatures.account = failure(APPROOV_MESSAGE_SIGNING_OUTCOMES.ERROR)
      }
    }
  }

  const contentDigestPresent = hasText(request.headers.get('content-digest'))
  if (!commonFailure && request.body !== null && !contentDigestPresent) {
    commonFailure = failure(APPROOV_MESSAGE_SIGNING_OUTCOMES.MISSING_CONTENT_DIGEST)
  }
  if (!commonFailure) {
    try {
      await verifyContentDigest(ctx, request)
    } catch (err) {
      const invalidDigest = err instanceof ContentDigestValidationError
      commonFailure = failure(
        invalidDigest ? APPROOV_MESSAGE_SIGNING_OUTCOMES.INVALID_CONTENT_DIGEST : APPROOV_MESSAGE_SIGNING_OUTCOMES.ERROR,
        invalidDigest ? err.message : null
      )
    }
  }
  const requiredFields = [
    ...APPROOV_MESSAGE_SIGNING_REQUIRED_FIELDS,
    (ctx.approovTokenHeaderName || 'Approov-Token').toLowerCase()
  ]
  if (contentDigestPresent) requiredFields.push('content-digest')

  for (const name of selected) {
    if (result.signatures[name]) continue
    result.signatures[name] = commonFailure || await verifySignatureEntry({
      request,
      signatures,
      signatureInputs,
      signatureName: name,
      verificationKey: keys[name],
      algorithm: name === 'install' ? APPROOV_MESSAGE_SIGNING_ALGORITHMS.INSTALL : APPROOV_MESSAGE_SIGNING_ALGORITHMS.ACCOUNT,
      tolerance: ctx.approovMessageSigningTolerance,
      requiredFields
    })
  }
  const entries = selected.map(name => result.signatures[name])
  result.ok = entries.every(entry => entry.ok)
  result.status = selected.length === 1
    ? entries[0].status
    : entries.some(entry => entry.status === APPROOV_MESSAGE_SIGNING_OUTCOMES.ERROR)
      ? APPROOV_MESSAGE_SIGNING_OUTCOMES.ERROR
      : result.ok ? APPROOV_MESSAGE_SIGNING_OUTCOMES.VALID : APPROOV_MESSAGE_SIGNING_OUTCOMES.INVALID
  result.error = entries.find(entry => !entry.ok)?.error ?? null
  return result
}

export const validateMessageSignatures = async (ctx, request, payload) => {
  const mode = getMessageSigningMode(payload, ctx)
  try {
    return await checkRequiredSignatures(ctx, request, payload)
  } catch {
    const required = mode === 'either' ? ['install', 'account'] : requiredNames(mode)
    const signatures = { install: null, account: null }
    for (const name of required) signatures[name] = failure(APPROOV_MESSAGE_SIGNING_OUTCOMES.ERROR)
    return { ok: false, status: APPROOV_MESSAGE_SIGNING_OUTCOMES.ERROR, mode, signatureName: required.length === 1 ? required[0] : null, error: null, signatures }
  }
}
