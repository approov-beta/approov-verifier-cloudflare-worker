/**
 * Project: Approov Cloudflare Worker
 * Copyright(c) 2026 by Approov Ltd.
 *
 * @fileoverview Cloudflare Worker entrypoint.
 */

import { handleRequest } from './worker/handle-request.js'
import { env } from 'cloudflare:workers'
import { establishContext } from './config/context.js'
import { assertValidConfig } from './config/schema.mjs'

// Cloudflare evaluates this scope before accepting a Worker version. No I/O.
const startupContext = establishContext(env)
assertValidConfig(startupContext)

export default {
  /**
   * Cloudflare Worker fetch entrypoint.
   *
   * Delegates request processing to the composed handler module so `index.js`
   * remains a minimal binder.
   *
   * @param {*} request Incoming request.
   * @param {*} env Worker environment bindings.
   * @returns {Promise<Response>} Worker response.
   */
  async fetch (request, env) {
    return await handleRequest(request, env)
  }
}
