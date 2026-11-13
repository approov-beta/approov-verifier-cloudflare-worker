// This header is client-supplied diagnostic data, never attestation evidence.
// Only SDK status names may reach logs or annotations; never echo unknown data.
const STATUSES = new Set([
  'success', 'no_network', 'poor_network', 'mitm_detected', 'untrusted_network',
  'no_approov_service', 'bad_url', 'unknown_url', 'unprotected_url',
  'not_initialized', 'rejected', 'disabled', 'unknown_key', 'bad_key',
  'bad_payload', 'internal_error'
])

export const parseClientStatus = (value) => {
  if (value === null) return null
  if (value.length > 32) return 'invalid'
  const status = value.trim()
  return STATUSES.has(status) ? status : 'invalid'
}
