import { trimOrNull } from '../utils/text.js'

const utf8 = new TextDecoder()

// Decode every %XX escape. Unlike decodeURIComponent, one invalid sequence
// (such as "%ff") never leaves the rest of the path undecoded.
const percentDecode = (path) => path.replace(/(?:%[0-9a-f]{2})+/gi, (run) =>
  utf8.decode(Uint8Array.from(run.slice(1).split('%'), (hex) => Number.parseInt(hex, 16))))

/**
 * Normalize a path for matching only; the forwarded URL is never changed.
 *
 * Many origins percent-decode (some more than once), collapse duplicate
 * slashes, treat a backslash as a slash, drop ";" path parameters or route
 * case-insensitively, so a raw comparison would let an alternate spelling of a
 * protected path reach the origin unchecked. A false positive only adds
 * checks; a false negative skips them.
 *
 * @param {String} pathname URL path.
 * @returns {String} Decoded, parameter-free, slash-collapsed, lowercase path.
 */
export const normalizePathForMatching = (pathname) => {
  let path = String(pathname)
  // Three passes cover double and triple encoding. Decoding is idempotent
  // once no escape is left.
  for (let pass = 0; pass < 3; pass++) path = percentDecode(path)
  return path
    .replace(/\\/g, '/')
    .replace(/;[^/]*/g, '')
    .replace(/\/{2,}/g, '/')
    .toLowerCase()
}

// Resolve "." and ".." segments that only appear after decoding, such as
// "/public%2f..%2fapi" or "/public/..;/api". The URL parser has already
// resolved the literal ones.
const resolveDotSegments = (path) => {
  const resolved = []
  for (const segment of path.split('/')) {
    if (segment === '..') resolved.pop()
    else if (segment !== '' && segment !== '.') resolved.push(segment)
  }
  return `/${resolved.join('/')}`
}

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

// Compile one protected-path pattern (a JSDoc block cannot hold the examples).
//
// A pattern is a path prefix in which "*" stands for one path segment, so
// "/shop/*/*/checkout" covers "/shop/de/v6/checkout" and "/shop/it/v6/checkout"
// in one entry instead of one per market. A "*" next to other characters
// matches the rest of that segment only ("/customer/v*/carts"). "*" never
// crosses a "/" and a whole-segment "*" never matches an empty segment. Every
// other character is literal. Like a prefix, a pattern matches the path itself
// and anything below it: "/api" covers "/api" and "/api/users", while "/api/*"
// covers only what is below "/api". A match also ends at ".", whitespace or a
// NUL, because origins commonly route "/checkout.json" or "/checkout%20" to
// "/checkout". Returns an anchored matcher for normalized paths.
const compilePathPattern = (pattern) => {
  const segments = normalizePathForMatching(pattern)
    .split('/')
    .map((segment) => (segment === '*' ? '[^/]+' : segment.split('*').map(escapeRegExp).join('[^/]*')))
  return new RegExp(`^${segments.join('/')}(?:[/?.\\s\\0]|$)`)
}

/**
 * Parse `APPROOV_PROTECTED_PATHS`, a comma-separated list of path patterns.
 *
 * Unset or blank keeps the default: every request reaching the Worker is
 * checked. An entry without a leading `/` would never match, and an entry with
 * a trailing `/` would match only that exact path and nothing below it, so
 * both are configuration errors rather than silently unprotected paths.
 *
 * @param {*} env Worker environment bindings.
 * @param {String[]} errors Mutable configuration error list.
 * @returns {RegExp[]|null} Matchers, or null when every path is protected.
 */
export const parseProtectedPaths = (env, errors) => {
  const raw = trimOrNull(env.APPROOV_PROTECTED_PATHS)
  if (!raw) return null

  const patterns = raw.split(',').map((entry) => entry.trim()).filter(Boolean)
  const invalid = patterns.filter((pattern) => !pattern.startsWith('/'))
  if (invalid.length > 0) {
    errors.push('env.APPROOV_PROTECTED_PATHS entries must start with "/"')
    return null
  }
  if (patterns.some((pattern) => pattern.endsWith('/'))) {
    errors.push('env.APPROOV_PROTECTED_PATHS entries must not end with "/": use "/api" for a path and everything below it, or "/api/*" for only what is below it')
    return null
  }
  return Object.freeze(patterns.map(compilePathPattern))
}

/**
 * Return whether the request path is checked by the Worker.
 *
 * @param {*} ctx Worker context.
 * @param {String} pathname URL path.
 * @returns {Boolean} True when every path is protected or a pattern matches.
 */
export const isProtectedPath = (ctx, pathname) => {
  if (!ctx.approovProtectedPaths) return true
  // Origins differ on whether they resolve decoded dot segments, so a match
  // on either spelling is protected.
  const path = normalizePathForMatching(pathname)
  const resolved = resolveDotSegments(path)
  return ctx.approovProtectedPaths.some((matcher) => matcher.test(path) || matcher.test(resolved))
}
