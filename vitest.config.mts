import { cloudflareTest } from '@cloudflare/vitest-pool-workers'
import { configDefaults, defineConfig } from 'vitest/config'

// Satisfy Wrangler's required-secret preflight. The real test value is supplied
// by the explicit Miniflare binding below, which takes precedence at runtime.
process.env.APPROOV_BACKEND_CONFIG ??= 'provided-by-miniflare-test-bindings'

export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: {
        bindings: {
          API_DOMAIN: 'upstream.example.com',
          APPROOV_MODE: 'annotate',
          APPROOV_BACKEND_CONFIG: '{"currentArcEncodingSecret":"test-arc-secret","pendingArcEncodingSecret":null,"previousArcEncodingSecrets":[],"defaultPassJWKS":{"keys":[{"kty":"oct","use":"sig","alg":"HS256","kid":"_HS256","k":"dW5pdC10ZXN0LWRlZmF1bHQtdG9rZW4tc2VjcmV0"}]},"passJWKS":{"keys":[{"kty":"EC","x":"EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84","y":"kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY","crv":"P-256","kid":"__default__","alg":"ES256","use":"sig"}]},"failJWKS":{"keys":[{"kty":"EC","x":"OoakUoe5GAVxpZq4M_xcXcyLBJVmKsPLLC8Q-CHaweA","y":"8VMqZ8nqz9KpLO-4u2FAT7Rmu5ZZuU30LYFysi7E5AM","crv":"P-256","kid":"__default__","alg":"ES256","use":"sig"}]},"apis":{"worker.local":{"kid":"__default__","isPassKeyPresent":true,"isFailKeyPresent":true}}}'
        }
      },
      wrangler: {
        configPath: './wrangler.toml'
      }
    })
  ],
  test: {
    exclude: [...configDefaults.exclude, 'test/preflight.test.mjs', 'test/docs-examples.test.mjs', 'test/audit.test.mjs'],
    coverage: {
      provider: 'istanbul',
      // Cover everything we own: the core worker and every drop-in plugin.
      include: ['src/**/*.js', 'src/**/*.mjs', 'plugins/**/*.js'],
      // Exclude code we do not author or that is mechanically generated:
      // - src/vendor/**            third-party HTTP Message Signatures library
      // - src/plugins.generated.js build-time plugin registry (just imports)
      // - **/*.spec.js             the tests themselves
      exclude: [
        'src/vendor/**',
        'src/plugins.generated.js',
        '**/*.spec.js'
      ],
      reporter: ['text', 'html', 'json-summary'],
      // The worker's own code must stay fully exercised. CI fails on any drop.
      thresholds: {
        statements: 100,
        branches: 100,
        functions: 100,
        lines: 100
      }
    }
  }
})
