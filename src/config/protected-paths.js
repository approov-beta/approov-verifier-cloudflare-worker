import { trimOrNull } from '../utils/text.js'

/**
 * Normalize a path for matching only; the forwarded URL is never changed.
 *
 * Many origins percent-decode, collapse duplicate slashes or route
 * case-insensitively, so a raw comparison would let an encoded spelling of a
 * protected path reach the origin unchecked. A false positive only adds
 * checks; a false negative skips them.
 *
 * @param {String} pathname URL path.
 * @returns {String} Decoded, slash-collapsed, lowercase path.
 */
export const normalizePathForMatching = (pathname) => {
  let path = String(pathname)
  try {
    path = decodeURIComponent(path)
  } catch {
    // Not decodable: keep the raw spelling.
  }
  return path.replace(/\/{2,}/g, '/').toLowerCase()
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
// and anything below it. Returns an anchored matcher for normalized paths.
const compilePathPattern = (pattern) => {
  const segments = normalizePathForMatching(pattern)
    .split('/')
    .map((segment) => (segment === '*' ? '[^/]+' : segment.split('*').map(escapeRegExp).join('[^/]*')))
  return new RegExp(`^${segments.join('/')}(?:[/?]|$)`)
}

/**
 * Parse `APPROOV_PROTECTED_PATHS`, a comma-separated list of path patterns.
 *
 * Unset or blank keeps the default: every request reaching the Worker is
 * checked. An entry without a leading `/` would never match, so it is a
 * configuration error rather than a silently unprotected path.
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
  const path = normalizePathForMatching(pathname)
  return ctx.approovProtectedPaths.some((matcher) => matcher.test(path))
}
