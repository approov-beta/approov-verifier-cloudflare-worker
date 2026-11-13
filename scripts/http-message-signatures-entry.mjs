// Stable build entry for the vendored CommonJS library. Keep this adapter in
// sync with the public ESM exports in src/vendor/http-message-signatures.js.
import * as messageSignaturesModule from '../vendor/http-message-signatures/lib/index.js'
import * as structuredHeaderModule from '../vendor/http-message-signatures/lib/structured-header.js'

// CommonJS default wrapping differs between the source build and ESM runtimes.
const resolveInteropExport = (moduleValue, predicate) => {
  const candidates = [
    moduleValue,
    moduleValue && moduleValue.default,
    moduleValue && moduleValue.default && moduleValue.default.default,
    moduleValue && moduleValue.default && moduleValue.default.__esModule && moduleValue.default.default,
    moduleValue && moduleValue.__esModule && moduleValue.default
  ]
  return candidates.find(candidate => predicate(candidate)) || null
}
const messageSigningLib = resolveInteropExport(
  messageSignaturesModule,
  candidate => candidate && candidate.httpbis && typeof candidate.createVerifier === 'function'
)
if (!messageSigningLib) throw new Error('unable to resolve vendored http-message-signatures exports')
const structuredHeaderLib = resolveInteropExport(
  structuredHeaderModule,
  candidate => candidate && typeof candidate.Dictionary === 'function'
)
if (!structuredHeaderLib) throw new Error('unable to resolve vendored structured-header exports')

export const { httpbis, createSigner, createVerifier } = messageSigningLib
export const { Dictionary: StructuredHeaderDictionary } = structuredHeaderLib
